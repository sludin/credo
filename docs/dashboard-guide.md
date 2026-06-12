# Dashboard Setup and Authentication Guide

This guide covers deploying the dashboard, configuring authentication, enrolling users, and understanding how the dashboard identifies users to Shepherd.

## Overview

The dashboard is a React+Vite SPA backed by an Express BFF (backend-for-frontend). The BFF holds the service-level mTLS credentials and proxies all Shepherd API calls. The browser never handles raw TLS credentials.

Authentication uses two layers:

| Layer | Mechanism | Purpose |
|-------|-----------|---------|
| Browser → BFF | WebAuthn passkeys + session cookie | Human authentication |
| BFF → Shepherd | mTLS service cert (establish connection) + Bearer JWT (identify user) | Service identity + per-user authorization |

The Vigil CA is the root of trust for user identity. Each user proves who they are **once** at enrollment time using a Vigil-issued certificate and private key. After that, a passkey (Touch ID, Face ID, YubiKey, etc.) is the daily credential — no passwords, no certificates in the browser.

---

## Identity Chain

```
Vigil CA
  └── issues cert: vigil://credo/prod/user/alice
        └── used ONCE at enrollment: CLI signs a challenge with the private key
              └── BFF verifies cert chain + signature → calls Shepherd POST /auth/token
                    └── Shepherd verifies PoP, issues JWT access + refresh token pair
                          └── JWT + passkey registered for alice; tokens stored in dashboard.users.json
                                └── all future logins: passkey → session cookie
                                      └── BFF sends Authorization: Bearer <JWT> on every Shepherd API call
                                            └── Shepherd verifies JWT, resolves alice → role → enforces RBAC
```

The dashboard service cert (mTLS) is used to establish the TLS connection to Shepherd. The JWT Bearer token is what tells Shepherd which user is making each request. These are two separate credentials with different scopes:

| Credential | Who it identifies | How it's used |
|-----------|-------------------|---------------|
| Service mTLS cert | The dashboard service itself | Authenticates the TLS connection and calls like `GET /accounts` for role refresh |
| User JWT | The logged-in human user | `Authorization: Bearer` header on all `/api/*` Shepherd calls |

---

## Roles

Roles are defined in `shepherd.accounts.json` and re-verified periodically from Shepherd.

| Role | Description |
|------|-------------|
| `readonly` | View-only access to all pages |
| `operator` | Can renew certs, create/edit assignments, view config |
| `admin` | Full access including user management and destructive operations |

The BFF re-validates the session user's role from Shepherd every **5 minutes** (`auth.roleRefreshIntervalSeconds`). If Shepherd is unreachable and the cached role is older than **30 minutes** (`auth.roleStaleTimeoutSeconds`), the session is terminated.

---

## Prerequisites

Before running the dashboard:

1. **A TLS cert + key** for the dashboard's own HTTPS server (`tls.certPath` / `tls.keyPath`). This is typically managed by corgi — add an assignment for `dashboard.example.com` to `shepherd.assignments.json`.

2. **An mTLS service cert + key** for the dashboard to use when calling Shepherd (`mtls.certPath` / `mtls.keyPath`). These are often the same cert/key pair as the TLS cert above, if the dashboard is registered as a node in the fleet.

3. **The CA trust bundle** (`credo-catrust.pem`) so the dashboard can verify Shepherd's server cert.

4. **The dashboard binary built** — run `npm run build` from the `dashboard/` directory to produce `dist/client/` (the SPA bundle) and the compiled BFF.

---

## Initial Setup

### Step 1 — Write the config file

Copy `dashboard.config.example.json` to `dashboard.config.json` in the dashboard's working directory and edit it:

```json
{
  "port": 7030,
  "bind": "127.0.0.1",
  "shepherdApiUrl": "https://shepherd.example.com:7011",

  "caPath": "/var/apps/credo/ca/credo-catrust.pem",

  "tls": {
    "certPath": "/var/apps/credo/corgi/store/live/dashboard.example.com/fullchain.pem",
    "keyPath":  "/var/apps/credo/corgi/store/live/dashboard.example.com/privkey.pem"
  },
  "mtls": {
    "certPath":          "/var/apps/credo/corgi/store/live/dashboard.example.com/fullchain.pem",
    "keyPath":           "/var/apps/credo/corgi/store/live/dashboard.example.com/privkey.pem",
    "caPath":            "/var/apps/credo/ca/credo-catrust.pem",
    "rejectUnauthorized": true
  },

  "auth": {
    "sessionSecret": "<output of: openssl rand -hex 32>",
    "rpId":          "dashboard.example.com",
    "origin":        "https://dashboard.example.com:7030"
  }
}
```

> The config path is controlled by `DASHBOARD_CONFIG_PATH` env var (default: `dashboard.config.json` in the CWD). Most auth fields use sensible defaults — only `sessionSecret`, `rpId`, and `origin` are required.

The config supports `vars` and `includes` with the same interpolation syntax as the Rust services:

```json
{
  "vars": {
    "credoRoot": "/var/apps/credo",
    "corgiStore": "${credoRoot}/corgi/store/live"
  },
  "includes": ["${credoRoot}/vars.json"],
  "tls": {
    "certPath": "${corgiStore}/dashboard.example.com/fullchain.pem",
    "keyPath":  "${corgiStore}/dashboard.example.com/privkey.pem"
  }
}
```

### Step 2 — Configure Shepherd

The dashboard service cert must have an account in `shepherd.accounts.json`. The service cert identity URI is printed at startup — check the log line:

```
[dashboard] service cert: /path/to/cert.pem | fingerprint256: ... | identity URIs: vigil://credo/service/dashboard
```

Add the service account with at least `operator` role (needed to call `GET /accounts` for role refresh):

```json
{
  "accounts": [
    {
      "name": "dashboard",
      "identities": ["vigil://credo/service/dashboard"],
      "role": "operator",
      "active": true
    }
  ]
}
```

Each user who will log in also needs a Shepherd account. The `identityUri` in their account must match the URI SAN of the cert they will use for enrollment:

```json
{
  "name": "alice",
  "identities": ["vigil://credo/prod/user/alice"],
  "role": "admin",
  "active": true
}
```

> **No `trustedProxies` config is needed.** The dashboard forwards user identity via JWT Bearer tokens, not `X-Credo-Forwarded-Identity` headers. Shepherd's JWT auth handles identity resolution directly.

### Step 3 — Start the server

**Development** (BFF + Vite HMR):

```bash
cd dashboard
npm run dev
```

**Production** (serves the built SPA bundle):

```bash
cd dashboard
npm run build
./dashboard server start
```

The config path is read from `DASHBOARD_CONFIG_PATH` or `dashboard.config.json` in the CWD. At startup, the dashboard prints its service cert identity URI — use this to set up the Shepherd account (Step 2 above).

---

## New User Setup

User setup is a three-step process: an admin creates the user record, the user proves their identity with their Vigil cert, and the browser registers a passkey.

### Step 1 — Create the user record (admin, on the server)

```bash
./dashboard user create \
  --account alice \
  --email   alice@example.com \
  --name    "Alice Example" \
  --identity vigil://credo/prod/user/alice
```

`--identity` is the Vigil URI SAN that will be in Alice's cert. It must match the identity in Alice's Shepherd account.

Output:

```
Created user: Alice Example (alice)
Identity URI: vigil://credo/prod/user/alice

Enrollment URL (expires in 24h):
https://dashboard.example.com:7030/enroll/<token>

Send this URL to the user. They will need their Vigil cert + key to complete enrollment.
```

Send the enrollment URL to the user. The token is valid for `auth.enrollmentTokenTTLHours` (default: 24 hours).

To generate a new enrollment link for an existing user (also revokes all existing passkeys):

```bash
./dashboard user reset --account alice
```

`reset` also accepts `--email`, `--name`, and `--identity` to update those fields at the same time.

To see all users:

```bash
./dashboard user list
```

### Step 2 — Generate a PoP token (user, on their machine)

The user needs their Vigil-issued certificate and private key. Run the `enroll` subcommand with the token from the enrollment URL:

```bash
./dashboard enroll \
  --cert      ~/.vigil/alice.pem \
  --key       ~/.vigil/alice-key.pem \
  --challenge <hex-token-from-enrollment-url>
```

> The challenge hex token is the path segment from the enrollment URL, not the full URL.

Output:

```json
{
  "cert": "-----BEGIN CERTIFICATE-----\n...",
  "signature": "<base64url>",
  "challenge": "<hex>",
  "identityUri": "vigil://credo/prod/user/alice",
  "issuedAt": "2026-05-13T12:00:00.000Z"
}
```

The tool extracts the identity URI from the certificate's Subject Alternative Names, builds `SHA256(challenge || identityUri || issuedAt)`, signs it with the private key, and self-verifies before printing. If the cert and key don't match, it exits without producing output.

### Step 3 — Complete enrollment in the browser

Navigate to the enrollment URL, paste the JSON output from the `enroll` command, and click **Verify identity**.

The BFF verifies:

1. Token matches the stored invite (compared as `SHA256(raw token)`)
2. `issuedAt` is within the last 5 minutes (replay protection)
3. Certificate parses as valid X.509
4. Certificate was signed by the configured CA (`mtls.caPath`)
5. Identity URI in the token matches the URI SAN in the certificate
6. Signature over `SHA256(challenge || identityUri || issuedAt)` verifies against the cert's public key
7. Identity URI matches the one registered for this user account (set at `user create --identity`)
8. Shepherd issues a JWT access + refresh token pair for the identity

After verification, the browser prompts to register a passkey. Once registered, the user is logged in and the invite token is consumed.

> **What if the cert's URI doesn't match `--identity` from `user create`?** The BFF will reject the PoP with a clear error showing the expected and actual identity URIs. Either re-run `user create` with the correct `--identity`, or re-run `user reset --identity <correct-uri>`.

---

## Daily Login

Navigate to the dashboard. If no session cookie is present, the browser redirects to `/login`.

Click **Sign in with passkey** — the browser prompts for the registered biometric or security key. On success, a session cookie is set (valid for `auth.sessionDurationHours`, default 24 hours) and the browser redirects to the original destination.

At login, the BFF refreshes the user's Shepherd JWT using the stored refresh token. If the refresh fails (e.g., Shepherd was restarted and its in-memory token store was cleared), login is blocked with a message directing the user to contact an admin for a re-enrollment link.

---

## Adding a Second Device

Log in from the first device, navigate to **Profile** (`/profile`), and click **Add another passkey**. The browser registers a new passkey on the new device. No CLI enrollment is needed — the session already proves identity.

To view or remove registered passkeys (label, creation date, last used), visit the Profile page.

---

## Configuration Reference

Config file is `dashboard.config.json` (location overridden by `DASHBOARD_CONFIG_PATH`).

The server **will not start** if `auth.sessionSecret` or `auth.rpId` are missing or empty.

### Top-level fields

| Field | Default | Description |
|-------|---------|-------------|
| `port` | `7030` | HTTPS listen port. Override with `PORT` env var. |
| `bind` | `127.0.0.1` | Listen address. Override with `BIND` env var. Set to `0.0.0.0` to expose externally. |
| `shepherdApiUrl` | **required** | Shepherd dashboard port base URL (e.g. `https://shepherd.example.com:7011`) |
| `caPath` | — | Shorthand CA bundle path used as fallback for `mtls.caPath` |
| `tls.certPath` | **required** | Dashboard HTTPS server certificate path |
| `tls.keyPath` | **required** | Dashboard HTTPS server private key path |
| `mtls.certPath` | **required** | Client cert for mTLS calls to Shepherd |
| `mtls.keyPath` | **required** | Client key for mTLS calls to Shepherd |
| `mtls.caPath` | `caPath` | CA bundle for verifying Shepherd's server cert |
| `mtls.rejectUnauthorized` | `true` | Set to `false` only for local dev with self-signed certs |
| `requestTimeoutSeconds` | `15` | Timeout for upstream Shepherd requests |
| `dnsPollingIntervalSeconds` | `5` | Minimum interval between DNS TXT polling calls |
| `dnsJobTimeoutSeconds` | `600` | Max age of an in-memory DNS TXT watcher job |
| `dnsPublicResolvers` | `[]` | Public DNS resolvers for the TXT watcher tool (each has `name` and `ip`) |

### Auth fields (`auth.*`)

| Field | Default | Description |
|-------|---------|-------------|
| `sessionSecret` | **required** | Signs and verifies session cookies. Generate with `openssl rand -hex 32`. Changing this invalidates all sessions. |
| `rpId` | **required** | WebAuthn Relying Party ID — bare hostname, no scheme or port. Must match the hostname in the browser URL bar. |
| `origin` | `https://<rpId>` | Full origin the browser sends — include port if non-standard. |
| `usersPath` | `./dashboard.users.json` | Path to the users data file (relative to `baseDir` or config file directory). |
| `sessionsDir` | `./sessions` | Directory for server-side session files. |
| `rpName` | `"Credo Dashboard"` | Human-readable name shown in passkey prompts. |
| `sessionDurationHours` | `24` | Session cookie lifetime. |
| `enrollmentTokenTTLHours` | `24` | How long an invite token remains valid. |
| `identityEnvironment` | `"prod"` | Environment segment of identity URIs — must match the environment in users' Vigil certificates (e.g. `prod` in `vigil://credo/prod/user/alice`). |
| `roleRefreshIntervalSeconds` | `300` | How often to re-validate role from Shepherd (5 minutes). |
| `roleStaleTimeoutSeconds` | `1800` | Max stale-role age before session is terminated (30 minutes). |

> **Legacy field names**: `roleRefreshIntervalMs` and `roleStaleTimeoutMs` (milliseconds) are still accepted for backward compatibility but `*Seconds` fields are preferred. Similarly, `requestTimeoutMs` is accepted but `requestTimeoutSeconds` is preferred.

### Required fields — `origin` vs `rpId`

**`auth.rpId`** — The bare hostname the browser uses to reach the dashboard. No scheme, no port.

- Correct: `"dashboard.example.com"` or `"192.168.1.10"`
- Wrong: `"https://dashboard.example.com"` or `"dashboard.example.com:7030"`

**`auth.origin`** — The full origin string. Required when serving on a non-standard port.

- Standard port 443: `"https://dashboard.example.com"` (can be omitted, default is fine)
- Non-standard port: `"https://dashboard.example.com:7030"` ← must be set explicitly
- IP with port: `"https://192.168.1.10:7030"` ← must be set explicitly

A mismatch between `origin` and what the browser actually sends causes passkey registration and login to fail.

### Minimal config

```bash
openssl rand -hex 32   # generate session secret
```

```json
{
  "shepherdApiUrl": "https://shepherd.example.com:7011",
  "caPath": "/var/apps/credo/ca/credo-catrust.pem",
  "tls": {
    "certPath": "/var/apps/credo/corgi/store/live/dashboard.example.com/fullchain.pem",
    "keyPath":  "/var/apps/credo/corgi/store/live/dashboard.example.com/privkey.pem"
  },
  "mtls": {
    "certPath": "/var/apps/credo/corgi/store/live/dashboard.example.com/fullchain.pem",
    "keyPath":  "/var/apps/credo/corgi/store/live/dashboard.example.com/privkey.pem"
  },
  "auth": {
    "sessionSecret": "<output of openssl rand -hex 32>",
    "rpId":          "dashboard.example.com",
    "origin":        "https://dashboard.example.com:7030"
  }
}
```

---

## Data Files

### `dashboard.users.json`

Created automatically on the first `user create`. **Gitignore this file** — it contains passkey credential data and Shepherd JWT tokens.

```json
{
  "users": [
    {
      "id": "usr_abc123",
      "shepherdAccount": "alice",
      "identityUri": "vigil://credo/prod/user/alice",
      "displayName": "Alice Example",
      "email": "alice@example.com",
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
      "pendingInvite": null,
      "shepherdAccessToken": "<JWT>",
      "shepherdRefreshToken": "<opaque token>",
      "shepherdTokenExpiresAt": "2026-11-13T00:00:00Z"
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

The raw token never appears in this file — only its SHA256 hash. Similarly, the Shepherd tokens are opaque credentials; treat `dashboard.users.json` as a secrets file.

`shepherdTokenExpiresAt` tracks the refresh token's expiry (tied to the Vigil cert notAfter). The BFF refreshes the access token automatically before it expires. If the refresh token expires or is invalidated (e.g. Shepherd restarts with an in-memory token store), the user must re-enroll.

### `sessions/`

Server-side session files (one per active session). Created automatically. Gitignore this directory. Sessions expire after `sessionDurationHours`.

---

## CLI Reference

All commands use the `dashboard` binary (the compiled BFF CLI).

### Server

| Command | Description |
|---------|-------------|
| `./dashboard server start` | Start the BFF server in the foreground |

### User management

| Command | Description |
|---------|-------------|
| `./dashboard user create --account <name> --email <e> --name <display> --identity <uri>` | Create a user record and print an enrollment URL |
| `./dashboard user list` | List all users, roles, passkey count, and enrollment status |
| `./dashboard user reset --account <name> [--email <e>] [--name <display>] [--identity <uri>]` | Revoke all passkeys, optionally update user fields, and print a new enrollment URL |

### Enrollment

| Command | Description |
|---------|-------------|
| `./dashboard enroll --cert <path> --key <path> --challenge <hex-token>` | Generate a PoP token to paste into the browser enrollment page |

---

## API Routes

All routes are mounted under `/auth`.

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/auth/me` | Returns `{ user: { userId, displayName, role, shepherdAccount, identityUri } }` or 401 |
| `POST` | `/auth/logout` | Destroys session |

### Enrollment

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/auth/enroll/verify` | Verifies CLI PoP JSON, calls Shepherd for JWT, begins WebAuthn registration |
| `POST` | `/auth/enroll/finish` | Completes passkey registration; creates session |

`POST /auth/enroll/verify` body:

```json
{
  "token": "<raw invite token from URL>",
  "pop": {
    "cert": "-----BEGIN CERTIFICATE-----\n...",
    "signature": "<base64url>",
    "challenge": "<hex>",
    "identityUri": "vigil://credo/prod/user/alice",
    "issuedAt": "2026-05-13T12:00:00.000Z"
  }
}
```

### Login

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/auth/login/begin` | Issues WebAuthn authentication challenge |
| `POST` | `/auth/login/finish` | Verifies assertion; refreshes Shepherd JWT; creates session |

### Passkeys (self-service)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/auth/passkeys/begin` | Begin adding a second passkey (authenticated) |
| `POST` | `/auth/passkeys/finish` | Complete second passkey registration |
| `DELETE` | `/auth/passkeys/:credentialId` | Remove a passkey |

### User Management

| Method | Path | Min Role | Description |
|--------|------|----------|-------------|
| `GET` | `/auth/admin/users` | `operator` | List all users with passkey count and invite status |
| `POST` | `/auth/admin/users` | `admin` | Create user via API; returns `enrollUrl` |
| `POST` | `/auth/admin/users/:id/invite` | `admin` | Regenerate invite for existing user |
| `PUT` | `/auth/admin/users/:id` | `admin` | Update `active`, `displayName` |
| `DELETE` | `/auth/admin/users/:id/passkeys/:credentialId` | `admin` | Revoke any user's passkey |

---

## Pages

| Route | Page | Access |
|-------|------|--------|
| `/login` | Login | Public |
| `/enroll/:token` | Enrollment | Public (token-gated) |
| `/profile` | Passkey management + add device | Any authenticated user |
| `/admin/users` | User management table + invite | `admin` role |

All other routes require authentication. Unauthenticated requests redirect to `/login` with the original destination preserved.

---

## Permission Map

The frontend `usePermission` hook maps action strings to minimum required roles:

| Action | Minimum Role |
|--------|-------------|
| `cert:view` | `readonly` |
| `cert:renew` | `operator` |
| `cert:delete` | `admin` |
| `assignment:view` | `readonly` |
| `assignment:create` | `operator` |
| `assignment:edit` | `operator` |
| `assignment:delete` | `admin` |
| `corgi:view` | `readonly` |
| `vigil:view` | `readonly` |
| `user:view` | `operator` |
| `user:manage` | `admin` |

---

## Verification Checklist

**Service cert accepted by Shepherd:**
```bash
# Expect the dashboard service account's details in the response
curl --cert dashboard.pem --key dashboard-key.pem --cacert credo-catrust.pem \
  https://shepherd.example.com:7011/accounts/me
```

**Enrollment:**
1. Run `./dashboard user create --account alice --email alice@example.com --name "Alice" --identity vigil://credo/prod/user/alice` and copy the enrollment URL
2. Run `./dashboard enroll --cert ~/.vigil/alice.pem --key ~/.vigil/alice-key.pem --challenge <token>` and copy the JSON output
3. Navigate to the enrollment URL, paste the JSON, complete the passkey prompt
4. Verify `dashboard.users.json` shows the user with a passkey, `pendingInvite: null`, and non-null `shepherdAccessToken`

**Login:**
1. Open a fresh browser session (or incognito)
2. Visit any dashboard page — verify redirect to `/login`
3. Click **Sign in with passkey**, complete biometric
4. Verify redirect to original page; `GET /auth/me` returns correct user and role

**JWT forwarding:**
```bash
# The Bearer JWT in the Authorization header identifies the user to Shepherd.
# Check Shepherd's audit log for the correct identity on a cert renewal.
```

**Role enforcement:**
1. Log in as `readonly` — Renew button disabled; + New and Edit in Assignments hidden; Admin nav absent
2. Log in as `operator` — Renew and edit controls active; Delete and Admin nav still hidden
3. Log in as `admin` — all controls active; Admin → Users page accessible

**Session expiry:**
Set `sessionDurationHours: 0.001` in test config, wait, verify next request returns 401 and browser redirects to `/login`.

**Shepherd token refresh after Shepherd restart:**
If Shepherd is restarted with an in-memory token store (default during development), stored refresh tokens become invalid. Users will see "Session credentials have expired" at next login and need a re-enrollment link from an admin.
