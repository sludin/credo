import fs from 'fs';
import path from 'path';
import { randomBytes, createHash } from 'crypto';
import { v4 as uuidv4 } from 'uuid';

export type DashboardPasskey = {
  credentialId: string;   // base64url
  publicKey: string;      // base64url, COSE key
  counter: number;
  label: string;
  createdAt: string;
  lastUsedAt: string;
};

export type PendingInvite = {
  tokenHash: string;      // SHA256 hex of raw token
  expiresAt: string;      // ISO
};

export type DashboardUser = {
  id: string;             // usr_<uuid>
  shepherdAccount: string; // account `name` in shepherd.accounts.json
  identityUri?: string;   // vigil:// URI from enrollment cert
  displayName: string;
  email: string;
  active: boolean;
  createdAt: string;
  passkeys: DashboardPasskey[];
  pendingInvite: PendingInvite | null;
  shepherdAccessToken?: string;
  shepherdRefreshToken?: string;
  shepherdTokenExpiresAt?: string;  // ISO — expiry of the refresh token (= Vigil cert notAfter)
};

export type UsersFile = {
  users: DashboardUser[];
};

let usersFilePath = '';

export function initUsersStore(filePath: string): void {
  usersFilePath = path.resolve(filePath);
}

export function loadUsers(): UsersFile {
  if (!fs.existsSync(usersFilePath)) {
    return { users: [] };
  }
  const raw = JSON.parse(fs.readFileSync(usersFilePath, 'utf8')) as UsersFile;
  return { users: Array.isArray(raw.users) ? raw.users : [] };
}

export function saveUsers(data: UsersFile): void {
  const dir = path.dirname(usersFilePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(usersFilePath, JSON.stringify(data, null, 2) + '\n', 'utf8');
}

export function findUserById(users: DashboardUser[], id: string): DashboardUser | undefined {
  return users.find((u) => u.id === id);
}

export function findUserByShepherdAccount(users: DashboardUser[], shepherdAccount: string): DashboardUser | undefined {
  return users.find((u) => u.shepherdAccount === shepherdAccount);
}

export function findUserByInviteToken(users: DashboardUser[], rawToken: string): DashboardUser | undefined {
  const tokenHash = hashToken(rawToken);
  return users.find(
    (u) =>
      u.pendingInvite !== null &&
      u.pendingInvite.tokenHash === tokenHash &&
      new Date(u.pendingInvite.expiresAt) > new Date()
  );
}

export function findUserByCredentialId(users: DashboardUser[], credentialId: string): DashboardUser | undefined {
  return users.find((u) => u.passkeys.some((pk) => pk.credentialId === credentialId));
}

export function hashToken(rawToken: string): string {
  return createHash('sha256').update(rawToken).digest('hex');
}

export function generateInviteToken(): { raw: string; hash: string } {
  const raw = randomBytes(32).toString('hex');
  return { raw, hash: hashToken(raw) };
}

export function createUser(
  shepherdAccount: string,
  displayName: string,
  email: string,
  inviteTTLHours: number,
  identityUri?: string
): { user: DashboardUser; rawToken: string } {
  const { raw, hash } = generateInviteToken();
  const expiresAt = new Date(Date.now() + inviteTTLHours * 60 * 60 * 1000).toISOString();
  const user: DashboardUser = {
    id: `usr_${uuidv4().replace(/-/g, '')}`,
    shepherdAccount,
    ...(identityUri ? { identityUri } : {}),
    displayName,
    email,
    active: true,
    createdAt: new Date().toISOString(),
    passkeys: [],
    pendingInvite: { tokenHash: hash, expiresAt },
  };
  return { user, rawToken: raw };
}

export type UserFieldUpdates = {
  displayName?: string;
  email?: string;
  identityUri?: string;
};

export function regenerateInvite(
  user: DashboardUser,
  inviteTTLHours: number,
  updates: UserFieldUpdates = {}
): { user: DashboardUser; rawToken: string } {
  const { raw, hash } = generateInviteToken();
  const expiresAt = new Date(Date.now() + inviteTTLHours * 60 * 60 * 1000).toISOString();
  return {
    user: { ...user, ...updates, passkeys: [], pendingInvite: { tokenHash: hash, expiresAt } },
    rawToken: raw,
  };
}
