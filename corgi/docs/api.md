# Corgi API Reference

Corgi exposes two independent HTTP listeners. They serve different purposes and have different auth requirements.

| Listener | Port config key | Default | TLS | Auth |
|----------|----------------|---------|-----|------|
| HTTP challenge | `httpChallenge.port` | 7080 | None | None (public) |
| Control API | `mtlsPort` | 7001 | mTLS | URI SAN → RBAC role |

The HTTP challenge listener is only started when `httpChallenge.enabled` is `true` in config (i.e., the `httpChallenge` block is present). It must be reachable from the ACME CA (Vigil) on port 80 or via a port-forward for HTTP-01 validation.

The control API requires a valid mTLS client certificate. The certificate's URI SAN is matched against `rbacIdentities` in config to determine the caller's role. Roles: `readonly` · `operator` · `admin`.

---

## HTTP Challenge Listener (plain HTTP)

No authentication. These endpoints must be reachable without TLS for ACME HTTP-01 validation.

### Route summary

| Method | Path | Auth |
|--------|------|------|
| GET | `/health` | None |
| GET | `/.well-known/acme-challenge/:token` | None |

---

#### GET /health

Response:
```json
{ "status": "healthy", "service": "corgi-http-challenge" }
```

---

#### GET /.well-known/acme-challenge/:token

Returns the ACME HTTP-01 challenge response for the given token. Vigil calls this during order validation to confirm Corgi controls the domain.

Response (`text/plain`): the challenge response string, or `404` if no record exists for the token.

---

## Control API (mTLS)

All routes except where noted require a client certificate whose URI SAN matches an entry in `rbacIdentities`.

### Route summary

| Method | Path | Role |
|--------|------|------|
| GET | `/health` | Readonly+ |
| GET | `/flock` | Readonly+ |
| GET | `/flock/:name` | Readonly+ |
| POST | `/flock/:name/csr` | Admin |
| POST | `/flock/:name/install` | Admin |
| POST | `/flock/:name/restart` | Admin |
| POST | `/sync/assignments` | Admin |
| POST | `/acme-challenges` | Admin |
| DELETE | `/acme-challenges/:token` | Admin |

---

### Readonly+ routes

#### GET /health

Returns node identity and flock size in addition to the health status.

Response:
```json
{
  "status": "healthy",
  "service": "corgi",
  "nodeId": "web-01",
  "shepherdUrl": "https://shepherd.example.com:7010",
  "flockSize": 2
}
```

---

#### GET /flock

Lists all certificates Corgi is managing.

Response:
```json
{
  "flock": [
    {
      "name": "api.example.com",
      "path": "/etc/ssl/certs/api.example.com.pem",
      "fingerprint256": "AABBCC...",
      "expiresInDays": 87,
      "installed": true
    }
  ]
}
```

---

#### GET /flock/:name

Returns detailed status for one certificate. Returns `404` if the name is not in the flock.

Response:
```json
{
  "certificate": {
    "name": "api.example.com",
    "path": "/etc/ssl/certs/api.example.com.pem",
    "fingerprint256": "AABBCC...",
    "expiresInDays": 87,
    "installed": true
  }
}
```

---

### Admin-only routes

#### POST /flock/:name/csr

Generates a CSR for the named certificate. If the certificate does not yet have an ECDSA key, a new one is generated and stored. Returns the CSR for submission to Shepherd.

Request body: — (no body required)

Response:
```json
{
  "name": "api.example.com",
  "csrPem": "-----BEGIN CERTIFICATE REQUEST-----\n..."
}
```

---

#### POST /flock/:name/install

Installs the certificate from Shepherd's cert store into the configured file paths, then runs any configured service hooks. Called by Shepherd after signing.

Request body (optional):
```json
{ "restart": true }
```

`restart` defaults to `true`. Set to `false` to skip hook execution.

Response:
```json
{
  "installed": true,
  "changed": true,
  "previousFingerprint": "AABBCC...",
  "fingerprint256": "DDEEFF...",
  "certificate": { ... },
  "restartResults": [
    {
      "hook": "nginx",
      "command": "systemctl reload nginx",
      "stdout": "",
      "stderr": ""
    }
  ]
}
```

`changed` is `false` when the installed fingerprint matches the previous one; hooks are not run in that case.

---

#### POST /flock/:name/restart

Runs the configured service hooks for the named certificate without reinstalling. Used to recover when hooks failed during a previous install.

Request body: —

Response:
```json
{
  "restarted": true,
  "results": [
    {
      "hook": "nginx",
      "command": "systemctl reload nginx",
      "stdout": "",
      "stderr": ""
    }
  ]
}
```

---

#### POST /sync/assignments

Triggers an immediate assignment reconciliation with Shepherd, outside the normal polling interval.

Request body: —

Response:
```json
{ "refreshed": true, "source": "shepherd-command" }
```

---

#### POST /acme-challenges

Creates an ACME HTTP-01 challenge record in memory. Shepherd calls this before triggering Vigil to validate a challenge. Optionally also writes the response to a file path (for servers that serve the challenge from disk).

Request body:
```json
{
  "token": "abc123",
  "response": "abc123.def456",
  "domain": "api.example.com",
  "filePath": "/var/www/.well-known/acme-challenge/abc123"
}
```

`domain` and `filePath` are optional.

Response `201`:
```json
{
  "challenge": {
    "token": "abc123",
    "response": "abc123.def456",
    "domain": "api.example.com",
    "filePath": "/var/www/.well-known/acme-challenge/abc123",
    "createdAt": "2026-06-03T12:00:00Z"
  }
}
```

---

#### DELETE /acme-challenges/:token

Removes a challenge record from memory and deletes the associated file if one was written.

Response:
```json
{ "removed": true }
```

`removed` is `false` if no record existed for the token.
