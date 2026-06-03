# Shepherd API Reference

Shepherd exposes two independent HTTP servers on separate ports. Both listen on the same `bind` address (default `127.0.0.1`; see `config.md`).

| Server | Port config key | Default | Purpose |
|--------|----------------|---------|---------|
| Agent API | `agentPort` | 7010 | Corgi-facing; pull assignments, cert material, renewals |
| Dashboard API | `dashboardPort` | 7011 | Admin-facing; management, accounts, cert store |

---

## Agent API

All routes on this server require mTLS. The client certificate's URI SAN must match the `identityUri` configured for the named Corgi in `shepherd.corgis.json`. The path parameter `:id` must equal the authenticated node's `name` field; mismatches are rejected with `403`.

### Route summary

| Method | Path | Auth |
|--------|------|------|
| GET | `/health` | Public |
| GET | `/agents/:id/assignments` | Corgi mTLS |
| GET | `/agents/:id/certs/:name` | Corgi mTLS |
| POST | `/agents/:id/provision/:name` | Corgi mTLS |
| POST | `/agents/:id/renew/:name` | Corgi mTLS |
| GET | `/agents/:id/renew/:name/status` | Corgi mTLS |

---

#### GET /health

Auth: none.

Response:
```json
{ "status": "healthy", "service": "shepherd-corgi" }
```

---

#### GET /agents/:id/assignments

Auth: Corgi mTLS.

Returns the full assignment list for the named Corgi. Corgi calls this on startup and periodically to detect new or removed certificate assignments.

Response:
```json
{
  "corgiId": "web-01",
  "assignments": [
    {
      "certName": "api.example.com",
      "corgi": "web-01",
      "ca": "vigil",
      "fingerprint256": "AABBCC..."
    }
  ],
  "assignmentsCount": 1
}
```

---

#### GET /agents/:id/certs/:name

Auth: Corgi mTLS.

Returns full certificate material for one assignment. Corgi calls this when the local fingerprint differs from the assignment's `fingerprint256`. `:name` is URL-encoded (e.g., `api.example.com` → `api.example.com`).

Response:
```json
{
  "certName": "api.example.com",
  "ca": "vigil",
  "fingerprint256": "AABBCC...",
  "expiresInDays": 87,
  "certPem": "-----BEGIN CERTIFICATE-----\n...",
  "chainPem": "-----BEGIN CERTIFICATE-----\n...",
  "fullchainPem": "-----BEGIN CERTIFICATE-----\n...",
  "keyPem": "-----BEGIN EC PRIVATE KEY-----\n..."
}
```

---

#### POST /agents/:id/provision/:name

Auth: Corgi mTLS.

Synchronous provision flow: Shepherd generates a CSR on behalf of the Corgi, submits it to the CA, stores the result, and returns it — all in a single request. Use when Corgi needs a certificate it has never held before.

Request body (optional):
```json
{ "currentFingerprint": "AABBCC..." }
```

Response `200`:
```json
{
  "issued": true,
  "changed": true,
  "fingerprint256": "DDEEFF...",
  "certPem": "-----BEGIN CERTIFICATE-----\n...",
  "ca": "vigil"
}
```

`certPem` is only present when `changed` is `true`. `issued: false` means the cert already exists and the fingerprint matched.

---

#### POST /agents/:id/renew/:name

Auth: Corgi mTLS.

Asynchronous renewal. Shepherd accepts the CSR, queues a background renewal job, and returns immediately with a job ID. Corgi polls `/status` until the job reaches a terminal state.

Request body (required):
```json
{
  "csrPem": "-----BEGIN CERTIFICATE REQUEST-----\n...",
  "currentFingerprint": "AABBCC..."
}
```

Response `202`:
```json
{
  "jobId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "pending",
  "certName": "api.example.com",
  "phase": "queued"
}
```

Phases (in order): `queued` → `submitting-order` → `validating` → `finalizing` → `installing`.

---

#### GET /agents/:id/renew/:name/status

Auth: Corgi mTLS.

Returns the active renewal job for the cert, or the most recent terminal job if none is active.

Response:
```json
{
  "jobId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "certName": "api.example.com",
  "ca": "vigil",
  "phase": "installing",
  "startedAt": 1748900000,
  "updatedAt": 1748900120,
  "error": null,
  "fingerprint256": "DDEEFF..."
}
```

`status` is `"completed"`, `"failed"`, or `"pending"`. `error` is a string on failure, `null` otherwise.

---

## Dashboard API

Auth model: every protected route accepts either a **JWT Bearer token** (`Authorization: Bearer <token>`) or an **mTLS client certificate** whose URI SAN matches an active account's `identities` list. Unauthenticated requests to protected routes receive `401`.

Roles: `readonly` · `operator` · `admin` (each role includes all permissions of lower roles).

### Route summary

| Method | Path | Auth |
|--------|------|------|
| GET | `/health` | Public |
| GET | `/auth/jwks` | Public |
| POST | `/auth/token` | Public |
| POST | `/auth/refresh` | Public |
| GET | `/flock` | Public |
| GET | `/flock/:name` | Public |
| GET | `/admin/assignments` | Readonly+ |
| GET | `/admin/certstore` | Readonly+ |
| GET | `/admin/certstore/:name` | Readonly+ |
| GET | `/admin/certstore/:name/pem` | Readonly+ |
| GET | `/admin/certstore/:name/fullchain` | Readonly+ |
| GET | `/admin/renewal-jobs` | Readonly+ |
| GET | `/admin/renewal-jobs/:id` | Readonly+ |
| GET | `/admin/renewal-jobs/last/:name` | Readonly+ |
| GET | `/admin/cas` | Readonly+ |
| GET | `/admin/vigil/ca` | Readonly+ |
| GET | `/admin/vigil/status` | Readonly+ |
| GET | `/admin/config-summary` | Readonly+ |
| GET | `/accounts` | Readonly+ |
| GET | `/accounts/me` | Readonly+ |
| GET | `/accounts/:id` | Readonly+ |
| POST | `/admin/renew/:name` | Admin |
| POST | `/admin/provision/:name` | Admin |
| DELETE | `/admin/renewal-jobs/:id` | Admin |
| POST | `/accounts` | Admin |
| PUT | `/accounts/:id` | Admin |
| DELETE | `/accounts/:id` | Admin |
| POST | `/admin/reload-corgis` | Admin |
| POST | `/admin/reload-assignments` | Admin |

---

### Public routes

#### GET /health

Response:
```json
{ "status": "healthy", "service": "shepherd" }
```

---

#### GET /auth/jwks

Returns the JSON Web Key Set used to verify Shepherd-issued JWTs. Clients that need to validate tokens independently (e.g., the Dashboard BFF) fetch this on startup.

Response: JWK Set (`application/json`).

---

#### POST /auth/token

Exchanges a credential for a JWT access token and a refresh token. Two modes:

**Bootstrap mode** — used once during initial deployment. Requires the `SHEPHERD_BOOTSTRAP_ADMIN_TOKEN` environment variable to be set on the Shepherd process.

Request body:
```json
{ "bootstrapToken": "<value of SHEPHERD_BOOTSTRAP_ADMIN_TOKEN>" }
```

**Proof-of-Possession (PoP) mode** — standard mode. The client signs a challenge with the private key of a Vigil-issued certificate and presents both the cert and the signature.

Request body:
```json
{
  "pop": {
    "cert": "-----BEGIN CERTIFICATE-----\n...",
    "identityUri": "vigil://credo/prod/service/dashboard",
    "issuedAt": "2026-06-03T12:00:00Z",
    "challenge": "a3f8b2...",
    "signature": "MEYCIQDx..."
  }
}
```

Shepherd verifies: PoP age < 5 minutes, cert signed by the configured CA, URI SAN in cert matches `identityUri`, account exists with that identity.

Response `200`:
```json
{
  "accessToken": "<JWT>",
  "refreshToken": "<opaque string>",
  "expiresAt": "2026-06-03T13:00:00Z"
}
```

JWT claims include `sub` (identity URI), `role`, `aud: ["shepherd"]`, and `exp` (1 hour from issuance).

---

#### POST /auth/refresh

Exchanges a valid refresh token for a new access token and a new refresh token. The old refresh token is revoked.

Request body:
```json
{ "refreshToken": "<opaque string>" }
```

Response `200`:
```json
{
  "accessToken": "<JWT>",
  "refreshToken": "<new opaque string>"
}
```

---

#### GET /flock

Returns all Corgis from `shepherd.corgis.json` with their current runtime health status.

Response:
```json
{
  "corgis": [
    {
      "name": "web-01",
      "url": "https://web-01.example.com:7001",
      "status": "reachable",
      "lastPolledAt": 1748900000,
      "flock": [],
      "error": null
    }
  ]
}
```

`status` is `"reachable"`, `"unreachable"`, or `"unknown"`.

---

#### GET /flock/:name

Returns the same shape as one element of `/flock`.

Response:
```json
{
  "corgi": {
    "name": "web-01",
    "url": "https://web-01.example.com:7001",
    "status": "reachable",
    "lastPolledAt": 1748900000,
    "flock": [],
    "error": null
  }
}
```

---

### Readonly+ routes

#### GET /admin/assignments

Response:
```json
{
  "assignments": [
    {
      "certName": "api.example.com",
      "corgi": "web-01",
      "ca": "vigil",
      "fingerprint256": "AABBCC..."
    }
  ]
}
```

---

#### GET /admin/certstore

Response:
```json
{
  "certStoreDir": "/var/credo/shepherd/store",
  "entries": [
    {
      "name": "api.example.com",
      "fingerprint256": "AABBCC...",
      "validTo": "2027-06-03T00:00:00Z",
      "expiresInDays": 365,
      "subject": "CN=api.example.com"
    }
  ]
}
```

---

#### GET /admin/certstore/:name

Response:
```json
{
  "entry": {
    "name": "api.example.com",
    "fingerprint256": "AABBCC...",
    "validTo": "2027-06-03T00:00:00Z",
    "expiresInDays": 365,
    "subject": "CN=api.example.com"
  }
}
```

---

#### GET /admin/certstore/:name/pem

Returns the certificate file as plain text (`text/plain`).

---

#### GET /admin/certstore/:name/fullchain

Returns the full chain (cert + intermediates) as plain text (`text/plain`).

---

#### GET /admin/renewal-jobs

Response:
```json
{
  "jobs": [
    {
      "id": "550e8400-...",
      "certName": "api.example.com",
      "ca": "vigil",
      "domains": ["api.example.com"],
      "phase": "completed",
      "createdAt": 1748900000,
      "updatedAt": 1748900120,
      "error": null,
      "fingerprint256": "DDEEFF...",
      "trace": []
    }
  ]
}
```

---

#### GET /admin/renewal-jobs/:id

Returns one job object (same shape as an element of `/admin/renewal-jobs`).

---

#### GET /admin/renewal-jobs/last/:name

Returns the most recent terminal (completed or failed) renewal job for the named certificate.

Response:
```json
{
  "job": { ... }
}
```

`job` is `null` if no terminal job exists for the cert.

---

#### GET /admin/cas

Response:
```json
{
  "cas": [
    {
      "name": "vigil",
      "protocol": "acme",
      "provider": "vigil",
      "directoryUrl": "https://vigil.example.com:7020/acme/directory",
      "supportedValidations": ["http-01"],
      "defaultValidation": "http-01"
    }
  ]
}
```

---

#### GET /admin/vigil/ca

Proxies to the configured Vigil instance and returns its CA metadata. Returns `400` if Vigil is not configured.

---

#### GET /admin/vigil/status

Proxies to the configured Vigil instance and returns its health response.

---

#### GET /admin/config-summary

Response:
```json
{
  "agentPort": 7010,
  "dashboardPort": 7011,
  "bind": "0.0.0.0",
  "certStoreDir": "/var/credo/shepherd/store",
  "renewBeforeDays": 7,
  "pollIntervalSeconds": 60,
  "corgiHealthCheckIntervalSeconds": 300,
  "cas": []
}
```

---

#### GET /accounts

Response:
```json
{
  "accounts": [
    {
      "id": "acct-001",
      "name": "dashboard",
      "displayName": "Dashboard Service",
      "role": "operator",
      "active": true,
      "identities": ["vigil://credo/prod/service/dashboard"],
      "notes": "",
      "createdAt": "2026-01-01T00:00:00Z"
    }
  ]
}
```

---

#### GET /accounts/me

Returns the identity and role of the currently authenticated caller.

Response:
```json
{
  "identityUri": "vigil://credo/prod/service/dashboard",
  "role": "operator",
  "accountId": "acct-001",
  "accountName": "dashboard"
}
```

---

#### GET /accounts/:id

Returns one account (same shape as an element of `/accounts`).

---

### Admin-only routes

#### POST /admin/renew/:name

Triggers an asynchronous renewal for the named certificate. Returns immediately.

Request body (optional):
```json
{ "keyAlgorithm": "ecdsa" }
```

Response `202`:
```json
{
  "jobId": "550e8400-...",
  "status": "pending",
  "certName": "api.example.com"
}
```

---

#### POST /admin/provision/:name

Same as `/admin/renew/:name` but used for initial provisioning of a certificate that does not yet exist in the cert store.

Response `202` — same shape as `/admin/renew/:name`.

---

#### DELETE /admin/renewal-jobs/:id

Cancels an active or pending renewal job.

Response:
```json
{ "cancelled": true }
```

Returns `404` if the job does not exist.

---

#### POST /accounts

Creates a new account.

Request body:
```json
{
  "id": "acct-002",
  "name": "ops-user",
  "displayName": "Ops User",
  "role": "operator",
  "active": true,
  "identities": ["vigil://credo/prod/user/ops-user"],
  "notes": ""
}
```

Response: the created account object.

---

#### PUT /accounts/:id

Updates an existing account. All fields are optional; omitted fields are unchanged.

Request body (partial):
```json
{
  "displayName": "Updated Name",
  "role": "admin",
  "active": true,
  "notes": "promoted",
  "identities": ["vigil://credo/prod/user/ops-user"]
}
```

Response: the updated account object.

---

#### DELETE /accounts/:id

Response:
```json
{ "deleted": true }
```

---

#### POST /admin/reload-corgis

Reloads `shepherd.corgis.json` from disk without restarting the process.

Response:
```json
{
  "reloaded": true,
  "corgis": 3,
  "corgisConfigPath": "/var/credo/shepherd/shepherd.corgis.json"
}
```

---

#### POST /admin/reload-assignments

Reloads `shepherd.assignments.json` from disk without restarting the process.

Response:
```json
{
  "reloaded": true,
  "assignments": 5,
  "assignmentsConfigPath": "/var/credo/shepherd/shepherd.assignments.json"
}
```
