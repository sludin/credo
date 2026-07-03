> ⚠️ Archived — Describes old `X-Credo-Forwarded-Identity` auth model; replaced by `docs/dashboard-guide.md`

# Dashboard Authentication Guide

This guide covers the dashboard authentication system introduced in May 2026: how users are
created and enrolled, how passkeys work for daily login, how the dashboard forwards user identity
to Shepherd, and how role-based access control is enforced in the UI.

## Overview

The dashboard uses a two-layer authentication model:

| Layer | Mechanism | Purpose |
|-------|-----------|---------|
| Browser → BFF | WebAuthn passkeys + session cookie | Human authentication |
| BFF → Shepherd | mTLS service cert + `X-Credo-Forwarded-Identity` header | Identity forwarding |

The Vigil CA is the root of trust for user identity. Each user proves who they are **once** at
enrollment time using a Vigil-issued certificate and private key. After that, a passkey (Touch ID,
Face ID, YubiKey, etc.) is the daily credential — no passwords, no certificates in the browser.

Shepherd's RBAC enforces per-user permissions on every API call. The dashboard service account
itself holds only `readonly` access; the forwarded user identity is what grants higher privileges.

---

## Identity Chain

```
Vigil CA
  └── issues cert: vigil://credo/prod/user/sludin
        └── used ONCE at enrollment: CLI signs a challenge with the private key
              └── BFF verifies cert chain + signature → passkey registered for sludin
                    └── all future logins: passkey → session cookie
                          └── BFF adds X-Credo-Forwarded-Identity: vigil://credo/prod/user/sludin
                                └── Shepherd resolves sludin → role → enforces RBAC
```

> **Two separate identity URIs are in play — both must be in `shepherd.accounts.json`:**
>
> | URI | Source | Purpose |
> |-----|--------|---------|
> | Cert SAN (e.g. `vigil://credo/admin/sludin`) | Extracted from the certificate by `credo-enroll` | Verified once at enrollment to confirm key possession |
> | Forwarded identity (e.g. `vigil://credo/prod/user/sludin`) | BFF synthesizes from `identityEnvironment` + `"user"` + `shepherdAccount` | Sent as `X-Credo-Forwarded-Identity` on every post-login Shepherd API call |
>
> The simplest setup is to issue user certs whose URI already matches the forwarded format —
> `vigil://credo/<identityEnvironment>/user/<account>` — so only one `identities` entry is
> needed. If you use an admin cert (`vigil://credo/admin/<account>`), add **both** URIs:
>
> ```json
> "identities": [
>   "vigil://credo/admin/sludin",
>   "vigil://credo/prod/user/sludin"
> ]
> ```

---

## Roles

Roles come from `shepherd.accounts.json` and are re-verified from Shepherd periodically.

| Role | Description |
|------|-------------|
| `readonly` | View-only access to all pages |
| `operator` | Can renew certs, create/edit assignments, view config |
| `admin` | Full access including user management and destructive operations |

The BFF re-validates the session user's role from Shepherd every **5 minutes**
(`auth.roleRefreshIntervalMs`). If Shepherd is unreachable and the cached role is older than
**30 minutes** (`auth.roleStaleTimeoutMs`), the session is terminated.

---

## New User Setup

### Step 1 — Create the user record (admin, on the server)

Run the bootstrap CLI from the `dashboard/` directory:

```bash
node dist/server/cli.js create-user \
  --account sludin \
  --email sludin@example.com \
  --name "Stephen Ludin"
```

This creates an entry in `dashboard.users.json` and prints an enrollment URL:

```
Enrollment URL: https://dashboard.example.com/enroll/<token>
```

The token is valid for `auth.enrollmentTokenTTLHours` (default: 24 hours). To generate a new
one for an existing user:

```bash
node dist/server/cli.js reset-user --account sludin
```

Other CLI subcommands:

```bash
node dist/server/cli.js list-users    # show all users, roles, and enrollment status
```

### Step 2 — Prove identity with the CLI enrollment tool

The user needs their Vigil-issued certificate and private key on their machine.

> **Cert requirements:** The certificate must have a `vigil://` URI in its Subject Alternative
> Names. For the cleanest setup, use a cert whose URI matches the forwarded identity format:
> `vigil://credo/<identityEnvironment>/user/<account>` (e.g. `vigil://credo/prod/user/sludin`).
> Admin certs (`vigil://credo/admin/<account>`) also work, but require both URIs in the
> Shepherd account's `identities` array — see the note in the Identity Chain section above.

Run `credo-enroll` with the challenge token from the enrollment URL:

```bash
credo-enroll \
  --cert ~/.vigil/sludin.pem \
  --key  ~/.vigil/sludin-key.pem \
  --challenge <hex-token-from-enrollment-url>
```

Output (paste this into the enrollment page):

```json
{
  "cert": "-----BEGIN CERTIFICATE-----\n...",
  "signature": "<base64url>",
  "challenge": "<hex>",
  "identityUri": "vigil://credo/prod/user/sludin",
  "issuedAt": "2026-05-13T12:00:00.000Z"
}
```

The tool extracts the identity URI from the certificate's Subject Alternative Names, builds the
message `SHA256(challenge || identityUri || issuedAt)`, signs it with the private key, and
self-verifies the signature before printing. If the cert and key don't match, it exits before
producing output.

### Step 3 — Complete enrollment in the browser

Navigate to the enrollment URL, paste the JSON output from `credo-enroll`, and click **Verify
identity**. The BFF verifies:

1. Token matches the stored invite (compared as `SHA256(raw token)`)
2. `issuedAt` is within the last 5 minutes (replay protection)
3. Certificate parses as valid X.509
4. Certificate was signed by the configured Vigil CA (`mtls.caPath`)
5. Identity URI in the token matches the URI SAN in the certificate
6. Signature over `SHA256(challenge || identityUri || issuedAt)` verifies against the cert's public key
7. Identity URI maps to a known Shepherd account

After verification, the browser prompts to register a passkey (Touch ID / Face ID / YubiKey).
Once registered, the user is logged in and the invite token is consumed.

---

## Daily Login

Navigate to the dashboard. If no session cookie is present, you are redirected to `/login`.

Click **Sign in with passkey** — the browser prompts for your registered biometric or security
key. No username or password is required. On success, a session cookie is set (valid for
`auth.sessionDurationHours`, default 24 hours) and you are redirected to your original
destination.

---

## Adding a Second Device

Log in from your first device, navigate to **Profile** (`/profile`), and click **Add another
passkey**. The browser registers a new passkey on the new device. No CLI enrollment is needed —
you are already authenticated.

To see your registered passkeys (label, creation date, last used) or remove one, visit the
Profile page.

---

## Trusted Proxy Identity Forwarding

The BFF holds a service-level mTLS certificate for Shepherd (`vigil://credo/prod/service/dashboard`
or similar). This account has minimal privilege in `shepherd.accounts.json` (typically `readonly`).

When a user is logged in, every proxied API request includes:

```
X-Credo-Forwarded-Identity: vigil://credo/prod/user/sludin
```

Shepherd's auth middleware detects that the connecting client cert belongs to a trusted proxy
(configured in `shepherd.config.json` → `auth.trustedProxies`), reads the header, resolves it
to the `sludin` account, and applies that account's role for RBAC and audit logging.

If no header is present, the dashboard service account's own role is used.

### Shepherd configuration

Add the dashboard service cert identity to `trustedProxies` in `shepherd.config.json`:

```json
{
  "auth": {
    "trustedProxies": ["vigil://credo/prod/service/dashboard"]
  }
}
```

The dashboard service account should exist in `shepherd.accounts.json` with a low-privilege
role so that unauthenticated dashboard requests (before any user logs in) have minimal access:

```json
{
  "name": "dashboard",
  "identities": ["vigil://credo/prod/service/dashboard"],
  "role": "readonly"
}
```

Each user who will log in via the dashboard also needs a Shepherd account with both identity
URIs — the cert URI (used at enrollment) and the forwarded URI (used on every API call):

```json
{
  "name": "sludin",
  "identities": [
    "vigil://credo/prod/user/sludin"
  ],
  "role": "admin"
}
```

If the user enrolled with an admin cert, add its URI too:

```json
{
  "name": "sludin",
  "identities": [
    "vigil://credo/admin/sludin",
    "vigil://credo/prod/user/sludin"
  ],
  "role": "admin"
}
```

---

## Configuration Reference

All auth settings live under the `auth` key in `dashboard.config.json`. The server **will not
start** if `auth.sessionSecret` or `auth.rpId` are missing or empty — these are required.

### Required fields

**`auth.sessionSecret`** — Signs and verifies session cookies. Generate a random value and keep
it secret. If this changes, all existing sessions are invalidated.

```bash
openssl rand -hex 32
```

**`auth.rpId`** — The WebAuthn Relying Party ID. Must be the bare hostname the browser uses to
reach the dashboard — no scheme, no port. Passkey registration and authentication will fail if
this doesn't match.

- Correct: `"dashboard.example.com"` or `"192.168.1.10"`
- Wrong: `"https://dashboard.example.com"` or `"dashboard.example.com:7030"`

**`auth.origin`** — The full origin the browser sends when visiting the dashboard. This must
include the scheme and any non-standard port. Defaults to `https://<rpId>` (port 443), which is
only correct if you serve the dashboard on the standard HTTPS port. If you use a non-standard
port, set this explicitly.

- Standard port: `"https://dashboard.example.com"` (default is fine)
- Non-standard port: `"https://dashboard.example.com:7030"` ← must set this explicitly
- IP with port: `"https://192.168.1.10:7030"` ← must set this explicitly

A mismatch between `origin` and what the browser actually sends causes passkey registration and
login to fail server-side with a verification error.

### All fields

| Field | Default | Description |
|-------|---------|-------------|
| `sessionSecret` | **required** | Secret for signing session cookies |
| `rpId` | **required** | WebAuthn Relying Party ID — bare hostname, no scheme or port |
| `origin` | `https://<rpId>` | Full origin the browser sends — include port if non-standard |
| `usersPath` | `./dashboard.users.json` | Path to the users data file |
| `sessionsDir` | `./sessions` | Directory for server-side session files |
| `rpName` | `"Credo Dashboard"` | Human-readable name shown in passkey prompts |
| `sessionDurationHours` | `24` | Session lifetime in hours |
| `enrollmentTokenTTLHours` | `24` | How long an invite token remains valid |
| `identityEnvironment` | `"prod"` | Environment segment of forwarded identity URIs (`prod`, `dev`, etc.) |
| `roleRefreshIntervalMs` | `300000` (5 min) | How often to re-validate role from Shepherd |
| `roleStaleTimeoutMs` | `1800000` (30 min) | Max stale-role age before session is terminated |

### Minimal config to get started

```bash
# Generate a session secret
openssl rand -hex 32
```

```json
{
  "auth": {
    "sessionSecret": "<output of openssl rand -hex 32>",
    "rpId": "dashboard.example.com",
    "origin": "https://dashboard.example.com:7030"
  }
}
```

If you serve on standard port 443, `origin` can be omitted (it defaults to `https://<rpId>`).
Everything else uses its default value.

### Full example

```json
{
  "auth": {
    "sessionSecret": "<output of openssl rand -hex 32>",
    "rpId": "dashboard.example.com",
    "origin": "https://dashboard.example.com:7030",
    "rpName": "Credo Dashboard",
    "usersPath": "./dashboard.users.json",
    "sessionsDir": "./sessions",
    "sessionDurationHours": 24,
    "enrollmentTokenTTLHours": 24,
    "identityEnvironment": "prod",
    "roleRefreshIntervalMs": 300000,
    "roleStaleTimeoutMs": 1800000
  }
}
```

The `identityEnvironment` must match the environment segment in users' Vigil certificates. A
user with `vigil://credo/prod/user/sludin` requires `"identityEnvironment": "prod"`.

---

## Data Files

### `dashboard.users.json`

Created automatically on first `create-user`. **Gitignore this file** — it contains passkey
credential data.

```json
{
  "users": [
    {
      "id": "usr_abc123",
      "shepherdAccount": "sludin",
      "displayName": "Stephen Ludin",
      "email": "sludin@example.com",
      "active": true,
      "createdAt": "2026-05-13T00:00:00Z",
      "passkeys": [
        {
          "credentialId": "<base64url>",
          "publicKey": "<base64url>",
          "counter": 42,
          "label": "MacBook Touch ID",
          "createdAt": "2026-05-13T00:00:00Z",
          "lastUsedAt": "2026-05-13T12:00:00Z"
        }
      ],
      "pendingInvite": null
    }
  ]
}
```

`pendingInvite` is non-null while an enrollment token has been issued but not yet consumed:

```json
{
  "tokenHash": "<SHA256 hex of raw token>",
  "expiresAt": "2026-05-14T00:00:00Z"
}
```

The raw token never appears in this file — only its SHA256 hash.

### `sessions/`

Server-side session files (one per active session). Created automatically. Gitignore this
directory. Sessions expire after `sessionDurationHours`.

---

## Permission Map

The frontend `usePermission` hook maps action strings to minimum required roles:

| Action | Minimum Role | UI Effect |
|--------|-------------|-----------|
| `cert:view` | `readonly` | Always visible |
| `cert:renew` | `operator` | Renew button in Corgis page |
| `cert:delete` | `admin` | (reserved) |
| `assignment:view` | `readonly` | Always visible |
| `assignment:create` | `operator` | + New button in Assignments |
| `assignment:edit` | `operator` | Edit button in Assignments |
| `assignment:delete` | `admin` | Delete button in Assignments edit panel |
| `corgi:view` | `readonly` | Always visible |
| `vigil:view` | `readonly` | Always visible |
| `vigil:issue` | `operator` | (reserved) |
| `user:view` | `operator` | (reserved) |
| `user:manage` | `admin` | Admin → Users nav item and page |
| `config:view` | `operator` | (reserved) |
| `config:manage` | `admin` | (reserved) |

---

## API Routes

All routes are mounted under `/auth`.

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/auth/me` | Returns `{ userId, displayName, role, shepherdAccount }` or 401 |
| `POST` | `/auth/logout` | Destroys session; redirect to `/login` |

### Enrollment

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/auth/enroll/verify` | Verifies CLI PoP JSON; begins WebAuthn registration |
| `POST` | `/auth/enroll/finish` | Completes passkey registration; creates session |

`POST /auth/enroll/verify` body:

```json
{
  "token": "<raw invite token from URL>",
  "pop": {
    "cert": "-----BEGIN CERTIFICATE-----\n...",
    "signature": "<base64url>",
    "challenge": "<hex>",
    "identityUri": "vigil://credo/prod/user/sludin",
    "issuedAt": "2026-05-13T12:00:00.000Z"
  }
}
```

### Login

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/auth/login/begin` | Issues WebAuthn authentication challenge |
| `POST` | `/auth/login/finish` | Verifies assertion; creates session |

### Passkeys (self-service)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/auth/passkeys/begin` | Begin adding a second passkey (authenticated) |
| `POST` | `/auth/passkeys/finish` | Complete second passkey registration |
| `DELETE` | `/auth/passkeys/:credentialId` | Remove a passkey |

### User Management (admin only)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/auth/admin/users` | List all users with passkey count and invite status |
| `POST` | `/auth/admin/users` | Create user; returns `enrollUrl` |
| `POST` | `/auth/admin/users/:id/invite` | Regenerate invite for existing user |
| `PUT` | `/auth/admin/users/:id` | Update `active`, `displayName` |
| `DELETE` | `/auth/admin/users/:id/passkeys/:credentialId` | Revoke any user's passkey |

---

## New Pages

| Route | Page | Access |
|-------|------|--------|
| `/login` | Login | Public |
| `/enroll/:token` | Enrollment | Public (token-gated) |
| `/profile` | Profile | Any authenticated user |
| `/admin/users` | User Management | `admin` role |

All other routes require authentication. Unauthenticated requests redirect to `/login` with the
original destination preserved.

---

## New Packages and Files

| Path | Description |
|------|-------------|
| `enroll/` | CLI tool (`credo-enroll`) for signing enrollment challenges |
| `dashboard/server/auth/users.ts` | User store CRUD; `dashboard.users.json` I/O |
| `dashboard/server/auth/session.ts` | `express-session` setup with `session-file-store` |
| `dashboard/server/auth/middleware.ts` | `requireAuth`, `requireRole`, `makeRoleRefresh` |
| `dashboard/server/auth/webauthn.ts` | WebAuthn registration and authentication helpers |
| `dashboard/server/auth/pop.ts` | CLI Proof-of-Possession token verification |
| `dashboard/server/routes-auth.ts` | All auth and user management API routes |
| `dashboard/server/cli.ts` | Bootstrap CLI: `create-user`, `list-users`, `reset-user` |
| `dashboard/src/context/AuthContext.tsx` | React auth context (`useAuth` hook) |
| `dashboard/src/hooks/usePermission.ts` | `usePermission(action)` hook |
| `dashboard/src/components/ProtectedRoute.tsx` | Redirects to `/login` if no session |
| `dashboard/src/pages/Login.tsx` | Passkey sign-in page |
| `dashboard/src/pages/Enroll.tsx` | Three-step enrollment page |
| `dashboard/src/pages/Profile.tsx` | Passkey management and second-device registration |
| `dashboard/src/pages/AdminUsers.tsx` | User management table and invite generation |

---

## Verification Checklist

**Trusted proxy forwarding:**
```bash
# With forwarded identity — expect sludin's role to be used
curl --cert dashboard.pem --key dashboard-key.pem --cacert vigil-ca.pem \
  -H "X-Credo-Forwarded-Identity: vigil://credo/prod/user/sludin" \
  https://shepherd:7011/api/accounts/me

# Without header — expect dashboard service account's own role
curl --cert dashboard.pem --key dashboard-key.pem --cacert vigil-ca.pem \
  https://shepherd:7011/api/accounts/me
```

**Enrollment:**
1. Run `node dist/server/cli.js create-user` and copy the URL
2. Run `credo-enroll --cert ... --key ... --challenge <token>` and copy the output
3. Navigate to the enrollment URL, paste the JSON, complete the passkey prompt
4. Verify `dashboard.users.json` shows the user with a passkey and `pendingInvite: null`

**Login:**
1. Open a fresh browser session (or incognito)
2. Visit any dashboard page — verify redirect to `/login`
3. Click **Sign in with passkey**, complete biometric
4. Verify redirect to original page; `GET /auth/me` returns correct user and role

**Role enforcement:**
1. Log in as a `readonly` user — Renew button in Corgis is disabled; + New and Edit in
   Assignments are hidden; Admin nav item is absent
2. Log in as `operator` — Renew and edit controls are active; Delete and Admin nav item
   are still hidden
3. Log in as `admin` — all controls active; Admin → Users page accessible

**Session expiry:**
Set `sessionDurationHours: 0.001` in test config, wait, verify next request returns 401 and
browser redirects to `/login`.

**Audit logging:**
Trigger a cert renewal while logged in. In Shepherd's logs, verify the audit entry shows
`vigil://credo/prod/user/<account>` — not the dashboard service account identity.
