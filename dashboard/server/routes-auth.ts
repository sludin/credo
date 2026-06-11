import express, { Request, Response } from 'express';
import type { AxiosInstance } from 'axios';
import type { DashboardConfig } from './config';
import type { SessionUser } from './auth/session';
import {
  loadUsers,
  saveUsers,
  findUserById,
  findUserByInviteToken,
  findUserByCredentialId,
  findUserByShepherdAccount,
  createUser,
  regenerateInvite,
  type DashboardUser,
} from './auth/users';
import {
  beginRegistration,
  finishRegistration,
  beginAuthentication,
  finishAuthentication,
} from './auth/webauthn';
import { verifyPopToken, resolveShepherdAccount, type PopToken } from './auth/pop';
import { requireAuth, requireRole } from './auth/middleware';

type Role = 'admin' | 'operator' | 'readonly';

function asyncHandler(fn: (req: Request, res: Response) => Promise<void>) {
  return (req: Request, res: Response): void => {
    fn(req, res).catch((err: unknown) => {
      console.error('Auth route error:', err);
      res.status(500).json({ error: 'Internal server error.' });
    });
  };
}

async function fetchShepherdRole(
  shepherdAccount: string,
  shepherdApi: AxiosInstance,
  serviceCert: { certPath: string; certFingerprint: string }
): Promise<{ role: Role } | { error: string }> {
  let accounts: Array<{ name: string; role: Role; active: boolean }>;
  try {
    const resp = await shepherdApi.get<{
      accounts: Array<{ name: string; role: Role; active: boolean }>;
    }>('/accounts');
    accounts = resp.data.accounts;
  } catch (err) {
    const status = (err as { response?: { status?: number } }).response?.status;
    const msg = err instanceof Error ? err.message : String(err);
    if (status === 401 || status === 403) {
      return {
        error:
          `[Layer 1 — dashboard service cert] Shepherd rejected the dashboard mTLS cert (HTTP ${status}). ` +
          `Add a Shepherd account for this cert in shepherd.accounts.json. ` +
          `Cert: ${serviceCert.certPath} | fingerprint256: ${serviceCert.certFingerprint}`,
      };
    }
    return { error: `[Layer 1 — dashboard service cert] Shepherd /accounts request failed: ${msg}` };
  }
  const account = accounts.find((a) => a.name === shepherdAccount);
  if (!account) {
    return {
      error:
        `[Layer 2 — proxied user identity] Shepherd account '${shepherdAccount}' not found. ` +
        `Add an account named '${shepherdAccount}' to shepherd.accounts.json. ` +
        `(The dashboard service cert was accepted OK — this is a user account lookup failure.)`,
    };
  }
  if (!account.active) {
    return {
      error:
        `[Layer 2 — proxied user identity] Shepherd account '${shepherdAccount}' is inactive. ` +
        `Set active=true in shepherd.accounts.json.`,
    };
  }
  return { role: account.role };
}

// In-memory challenge store. Challenges are short-lived (WebAuthn ceremony must
// complete within a few minutes), so memory storage is sufficient.
const pendingChallenges = new Map<string, { challenge: string; expiresAt: number }>();

function storePendingChallenge(key: string, challenge: string): void {
  pendingChallenges.set(key, { challenge, expiresAt: Date.now() + 5 * 60 * 1000 });
}

function consumePendingChallenge(key: string): string | null {
  const entry = pendingChallenges.get(key);
  pendingChallenges.delete(key);
  if (!entry || Date.now() > entry.expiresAt) return null;
  return entry.challenge;
}

export function createAuthRouter(
  config: DashboardConfig,
  shepherdApi: AxiosInstance,
  serviceCert: { certPath: string; certFingerprint: string }
) {
  const router = express.Router();
  const auth = config.auth;

  // ------------------------------------------------------------------
  // GET /auth/me
  // ------------------------------------------------------------------
  router.get('/me', requireAuth, (req: Request, res: Response) => {
    res.json({ user: req.session.user });
  });

  // ------------------------------------------------------------------
  // POST /auth/logout
  // ------------------------------------------------------------------
  router.post('/logout', (req: Request, res: Response) => {
    req.session.destroy(() => {
      res.json({ ok: true });
    });
  });

  // ------------------------------------------------------------------
  // POST /auth/enroll/verify — verify CLI PoP token, begin WebAuthn registration
  // ------------------------------------------------------------------
  router.post('/enroll/verify', asyncHandler(async (req: Request, res: Response) => {
    const { token: rawToken, pop } = req.body as { token?: string; pop?: PopToken };

    if (!rawToken || typeof rawToken !== 'string') {
      res.status(400).json({ error: 'Missing invite token.' });
      return;
    }
    if (!pop || typeof pop !== 'object') {
      res.status(400).json({ error: 'Missing PoP token.' });
      return;
    }

    const { users } = loadUsers();
    const user = findUserByInviteToken(users, rawToken);
    if (!user) {
      res.status(400).json({ error: 'Invite token not found or expired.' });
      return;
    }

    const popResult = verifyPopToken(pop, rawToken, config);
    if (!popResult.ok) {
      res.status(400).json({ error: popResult.error });
      return;
    }

    // Confirm the PoP identity is authorized for this user.
    if (user.identityUri) {
      // Fast path: identity was pre-registered at create-user time — just compare directly.
      if (popResult.identityUri !== user.identityUri) {
        res.status(400).json({
          error: 'PoP identity does not match the registered identity for this user.',
          expected: user.identityUri,
          got: popResult.identityUri,
        });
        return;
      }
    } else {
      // Fallback: resolve via Shepherd accounts (for users created without --identity).
      const shepherdAccountName = await resolveShepherdAccount(popResult.identityUri, shepherdApi);
      if (!shepherdAccountName || shepherdAccountName !== user.shepherdAccount) {
        res.status(400).json({
          error: 'PoP identity does not match the invited shepherd account.',
          expected: user.shepherdAccount,
          got: shepherdAccountName ?? '(no matching shepherd account found for identity URI)',
          identityUri: popResult.identityUri,
        });
        return;
      }
    }

    // Exchange the PoP for a Shepherd JWT + refresh token.
    let shepherdAccessToken: string | undefined;
    let shepherdRefreshToken: string | undefined;
    let shepherdTokenExpiresAt: string | undefined;
    try {
      const tokenResp = await shepherdApi.post<{
        accessToken: string;
        refreshToken: string;
        expiresAt: string;
      }>('/auth/token', { pop });
      shepherdAccessToken = tokenResp.data.accessToken;
      shepherdRefreshToken = tokenResp.data.refreshToken;
      shepherdTokenExpiresAt = tokenResp.data.expiresAt;
    } catch (err) {
      res.status(400).json({
        error: `Could not obtain Shepherd token: ${err instanceof Error ? err.message : String(err)}`,
      });
      return;
    }

    // Persist the resolved identity URI and Shepherd tokens on the user record.
    const { users: usersForUpdate } = loadUsers();
    const updateIdx = usersForUpdate.findIndex((u) => u.id === user.id);
    if (updateIdx !== -1) {
      usersForUpdate[updateIdx] = {
        ...usersForUpdate[updateIdx],
        identityUri: popResult.identityUri,
        shepherdAccessToken,
        shepherdRefreshToken,
        shepherdTokenExpiresAt,
      };
      saveUsers({ users: usersForUpdate });
    }

    const { options, challenge } = await beginRegistration(auth, user);
    storePendingChallenge(`enroll:${user.id}`, challenge);

    res.json({ registrationOptions: options, userId: user.id });
  }));

  // ------------------------------------------------------------------
  // POST /auth/enroll/finish — complete registration, create session
  // ------------------------------------------------------------------
  router.post('/enroll/finish', asyncHandler(async (req: Request, res: Response) => {
    const { userId, response, label } = req.body as {
      userId?: string;
      response?: unknown;
      label?: string;
    };

    if (!userId || !response) {
      res.status(400).json({ error: 'Missing userId or response.' });
      return;
    }

    const expectedChallenge = consumePendingChallenge(`enroll:${userId}`);
    if (!expectedChallenge) {
      res.status(400).json({ error: 'Registration challenge expired or not found.' });
      return;
    }

    const { users } = loadUsers();
    const userIdx = users.findIndex((u) => u.id === userId);
    if (userIdx === -1) {
      res.status(400).json({ error: 'User not found.' });
      return;
    }
    const user = users[userIdx];

    let passkey;
    try {
      passkey = await finishRegistration(auth, response as Parameters<typeof finishRegistration>[1], expectedChallenge, label ?? 'Passkey');
    } catch (err) {
      res.status(400).json({ error: String(err) });
      return;
    }

    const updatedUser = { ...user, passkeys: [...user.passkeys, passkey], pendingInvite: null };
    users[userIdx] = updatedUser;
    saveUsers({ users });

    const roleResult = await fetchShepherdRole(user.shepherdAccount, shepherdApi, serviceCert);
    if ('error' in roleResult) {
      res.status(400).json({ error: `Could not resolve shepherd account role: ${roleResult.error}` });
      return;
    }

    const sessionUser: SessionUser = {
      userId: updatedUser.id,
      shepherdAccount: updatedUser.shepherdAccount,
      identityUri: updatedUser.identityUri ?? updatedUser.shepherdAccount,
      displayName: updatedUser.displayName,
      role: roleResult.role,
      roleVerifiedAt: Date.now(),
    };
    req.session.user = sessionUser;
    res.json({ ok: true, user: sessionUser });
  }));

  // ------------------------------------------------------------------
  // POST /auth/login/begin
  // ------------------------------------------------------------------
  router.post('/login/begin', asyncHandler(async (req: Request, res: Response) => {
    const { options, challenge } = await beginAuthentication(auth);
    // Keyed by remote IP + a nonce to avoid collisions; the challenge itself is
    // the authoritative check, this is just a lookup key.
    const key = `login:${req.ip}:${Date.now()}`;
    storePendingChallenge(key, challenge);
    res.json({ options, challengeKey: key });
  }));

  // ------------------------------------------------------------------
  // POST /auth/login/finish
  // ------------------------------------------------------------------
  router.post('/login/finish', asyncHandler(async (req: Request, res: Response) => {
    const { challengeKey, response } = req.body as {
      challengeKey?: string;
      response?: unknown;
    };

    if (!challengeKey || !response) {
      res.status(400).json({ error: 'Missing challengeKey or response.' });
      return;
    }

    const expectedChallenge = consumePendingChallenge(challengeKey);
    if (!expectedChallenge) {
      res.status(400).json({ error: 'Authentication challenge expired or not found.' });
      return;
    }

    const authResponse = response as Parameters<typeof finishAuthentication>[1];
    const credentialId = authResponse.id;

    const { users } = loadUsers();
    const user = findUserByCredentialId(users, credentialId);
    if (!user || !user.active) {
      res.status(401).json({ error: 'Passkey not recognised or account inactive.' });
      return;
    }

    const passkey = user.passkeys.find((pk) => pk.credentialId === credentialId)!;
    const { verified, newCounter } = await finishAuthentication(auth, authResponse, expectedChallenge, passkey);
    if (!verified) {
      res.status(401).json({ error: 'Passkey verification failed.' });
      return;
    }

    // Update counter and lastUsedAt.
    const { users: freshUsers } = loadUsers();
    const freshIdx = freshUsers.findIndex((u) => u.id === user.id);
    if (freshIdx !== -1) {
      const pk = freshUsers[freshIdx].passkeys.find((p) => p.credentialId === credentialId);
      if (pk) {
        pk.counter = newCounter;
        pk.lastUsedAt = new Date().toISOString();
      }
      saveUsers({ users: freshUsers });
    }

    // Refresh Shepherd JWT tokens at every login so sessions survive restarts
    // and role changes take effect without re-enrollment.
    const { users: tokenUsers } = loadUsers();
    const tokenIdx = tokenUsers.findIndex((u) => u.id === user.id);
    if (tokenIdx !== -1 && tokenUsers[tokenIdx].shepherdRefreshToken) {
      try {
        const resp = await shepherdApi.post<{
          accessToken: string;
          refreshToken: string;
          expiresAt?: string;
        }>('/auth/refresh', { refreshToken: tokenUsers[tokenIdx].shepherdRefreshToken });
        tokenUsers[tokenIdx] = {
          ...tokenUsers[tokenIdx],
          shepherdAccessToken: resp.data.accessToken,
          shepherdRefreshToken: resp.data.refreshToken,
          shepherdTokenExpiresAt: resp.data.expiresAt,
        };
        saveUsers({ users: tokenUsers });
      } catch {
        // Refresh failed — fall through to the credential check below.
      }
    }

    // After the refresh attempt, verify credentials exist. If not, the user's
    // Shepherd tokens were never obtained or were lost (e.g. old Shepherd restart
    // with in-memory token store). Block login with a clear message rather than
    // creating a session that immediately fails all API calls.
    const { users: credCheck } = loadUsers();
    const credUser = credCheck.find((u) => u.id === user.id);
    if (!credUser?.shepherdAccessToken) {
      res.status(403).json({
        error: 'Your Shepherd credentials are missing or have expired. Contact your administrator for a re-enrollment link.',
      });
      return;
    }

    const roleResult = await fetchShepherdRole(user.shepherdAccount, shepherdApi, serviceCert);
    if ('error' in roleResult) {
      res.status(401).json({ error: `Could not resolve shepherd account role: ${roleResult.error}` });
      return;
    }

    const sessionUser: SessionUser = {
      userId: user.id,
      shepherdAccount: user.shepherdAccount,
      identityUri: user.identityUri ?? '',
      displayName: user.displayName,
      role: roleResult.role,
      roleVerifiedAt: Date.now(),
    };
    req.session.user = sessionUser;
    res.json({ ok: true, user: sessionUser });
  }));

  // ------------------------------------------------------------------
  // Profile: passkey management
  // ------------------------------------------------------------------

  // POST /auth/passkeys/begin — add a passkey from an already-authenticated session
  router.post('/passkeys/begin', requireAuth, asyncHandler(async (req: Request, res: Response) => {
    const sessionUser = req.session.user!;
    const { users } = loadUsers();
    const user = findUserById(users, sessionUser.userId);
    if (!user) {
      res.status(404).json({ error: 'User not found.' });
      return;
    }
    const { options, challenge } = await beginRegistration(auth, user);
    storePendingChallenge(`addkey:${user.id}`, challenge);
    res.json({ registrationOptions: options });
  }));

  router.post('/passkeys/finish', requireAuth, asyncHandler(async (req: Request, res: Response) => {
    const sessionUser = req.session.user!;
    const { response, label } = req.body as { response?: unknown; label?: string };

    const expectedChallenge = consumePendingChallenge(`addkey:${sessionUser.userId}`);
    if (!expectedChallenge) {
      res.status(400).json({ error: 'Challenge expired or not found.' });
      return;
    }

    let passkey;
    try {
      passkey = await finishRegistration(auth, response as Parameters<typeof finishRegistration>[1], expectedChallenge, label ?? 'Passkey');
    } catch (err) {
      res.status(400).json({ error: String(err) });
      return;
    }

    const { users } = loadUsers();
    const idx = users.findIndex((u) => u.id === sessionUser.userId);
    if (idx === -1) {
      res.status(404).json({ error: 'User not found.' });
      return;
    }
    users[idx].passkeys.push(passkey);
    saveUsers({ users });
    res.json({ ok: true, passkey });
  }));

  router.delete('/passkeys/:credentialId', requireAuth, asyncHandler(async (req: Request, res: Response) => {
    const sessionUser = req.session.user!;
    const { credentialId } = req.params;

    const { users } = loadUsers();
    const idx = users.findIndex((u) => u.id === sessionUser.userId);
    if (idx === -1) {
      res.status(404).json({ error: 'User not found.' });
      return;
    }

    const before = users[idx].passkeys.length;
    users[idx].passkeys = users[idx].passkeys.filter((pk) => pk.credentialId !== credentialId);
    if (users[idx].passkeys.length === before) {
      res.status(404).json({ error: 'Passkey not found.' });
      return;
    }
    saveUsers({ users });
    res.json({ ok: true });
  }));

  // ------------------------------------------------------------------
  // Admin: user management
  // ------------------------------------------------------------------

  router.get('/admin/users', requireAuth, requireRole('operator'), asyncHandler(async (_req: Request, res: Response) => {
    const { users } = loadUsers();
    res.json({ users: users.map(safeUser) });
  }));

  router.post('/admin/users', requireAuth, requireRole('admin'), asyncHandler(async (req: Request, res: Response) => {
    const { shepherdAccount, displayName, email } = req.body as {
      shepherdAccount?: string;
      displayName?: string;
      email?: string;
    };

    if (!shepherdAccount || !displayName || !email) {
      res.status(400).json({ error: 'shepherdAccount, displayName, and email are required.' });
      return;
    }

    const { users } = loadUsers();
    if (findUserByShepherdAccount(users, shepherdAccount)) {
      res.status(409).json({ error: 'A user linked to that shepherd account already exists.' });
      return;
    }

    const { user, rawToken } = createUser(shepherdAccount, displayName, email, auth.enrollmentTokenTTLHours);
    users.push(user);
    saveUsers({ users });

    const enrollUrl = `${auth.origin}/enroll/${rawToken}`;
    res.status(201).json({ user: safeUser(user), enrollUrl });
  }));

  router.post('/admin/users/:id/invite', requireAuth, requireRole('admin'), asyncHandler(async (req: Request, res: Response) => {
    const { users } = loadUsers();
    const idx = users.findIndex((u) => u.id === req.params.id);
    if (idx === -1) {
      res.status(404).json({ error: 'User not found.' });
      return;
    }

    const { user: updated, rawToken } = regenerateInvite(users[idx], auth.enrollmentTokenTTLHours);
    users[idx] = updated;
    saveUsers({ users });

    const enrollUrl = `${auth.origin}/enroll/${rawToken}`;
    res.json({ enrollUrl });
  }));

  router.put('/admin/users/:id', requireAuth, requireRole('admin'), asyncHandler(async (req: Request, res: Response) => {
    const { active, displayName } = req.body as { active?: boolean; displayName?: string };

    const { users } = loadUsers();
    const idx = users.findIndex((u) => u.id === req.params.id);
    if (idx === -1) {
      res.status(404).json({ error: 'User not found.' });
      return;
    }

    if (typeof active === 'boolean') users[idx].active = active;
    if (typeof displayName === 'string' && displayName.trim()) {
      users[idx].displayName = displayName.trim();
    }
    saveUsers({ users });
    res.json({ user: safeUser(users[idx]) });
  }));

  router.delete('/admin/users/:id/passkeys/:credentialId', requireAuth, requireRole('admin'), asyncHandler(async (req: Request, res: Response) => {
    const { users } = loadUsers();
    const idx = users.findIndex((u) => u.id === req.params.id);
    if (idx === -1) {
      res.status(404).json({ error: 'User not found.' });
      return;
    }

    const before = users[idx].passkeys.length;
    users[idx].passkeys = users[idx].passkeys.filter((pk) => pk.credentialId !== req.params.credentialId);
    if (users[idx].passkeys.length === before) {
      res.status(404).json({ error: 'Passkey not found.' });
      return;
    }
    saveUsers({ users });
    res.json({ ok: true });
  }));

  return router;
}

function safeUser(user: DashboardUser) {
  return {
    id: user.id,
    shepherdAccount: user.shepherdAccount,
    displayName: user.displayName,
    email: user.email,
    active: user.active,
    createdAt: user.createdAt,
    passkeyCount: user.passkeys.length,
    passkeys: user.passkeys.map((pk) => ({
      credentialId: pk.credentialId,
      label: pk.label,
      createdAt: pk.createdAt,
      lastUsedAt: pk.lastUsedAt,
    })),
    hasInvite: user.pendingInvite !== null,
  };
}
