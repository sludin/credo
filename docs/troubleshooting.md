# Troubleshooting Guide

This guide covers the six most common failure scenarios operators encounter in a credo deployment. Each section describes observable symptoms, how to diagnose the root cause, and how to recover.

---

## 1. Vigil restart loses ACME orders

### Symptoms

After restarting Vigil, Shepherd logs show ACME errors for certificates that were mid-renewal. Certificate renewal stalls; affected certs do not update.

### Cause

Vigil holds all ACME state — nonces, orders, and authorizations — in memory only. A restart clears every in-progress order. Any order that was between `new-order` and `finalize` at restart time is gone from Vigil's perspective and cannot be continued.

### Recovery

No manual action is required for the renewal to eventually complete. Shepherd's renewal job state machine will detect the ACME failure, record the error in the job's `error` field, and move the job to `failed`. On the next renewal cycle, Shepherd will submit a fresh `new-order` and work through the ACME flow from the beginning.

To check the error from the failed job:

```
GET /admin/renewal-jobs/last/:name   (Shepherd dashboard port 7011)
```

The `error` field in the response contains the ACME error detail.

### Prevention

Avoid restarting Vigil during active renewal windows. If you must restart Vigil, do so either well before or well after your renewal schedule (the `renewBeforeDays` window, default 7 days before expiry). Restarts outside active renewal periods are safe; orders will resume from a clean state.

---

## 2. Corgi fails to pull assignments from Shepherd

### Symptoms

Corgi logs show a failed outbound call to Shepherd's assignments endpoint. Log lines matching this pattern indicate the problem:

```
C < <status> GET /agents/<node-id>/assignments <shepherd-host>:7010 <peer_ip> - <ms>
```

A non-2xx status in the `<status>` field means the pull failed.

### Causes

- Shepherd is down or unreachable
- Corgi's mTLS client certificate has expired
- Corgi's client cert URI SAN does not match any entry in `shepherd.corgis.json` (see scenario 3)
- Network path between Corgi and Shepherd is broken

### Diagnosis

Look at the status code in the log line:

| Status | Meaning |
|--------|---------|
| `401` | Corgi's identity is not recognized — URI SAN mismatch (see scenario 3) |
| `403` | Path parameter `:id` does not match the authenticated node's `name` field |
| `503` | Shepherd is down or the ACME backend is unavailable |
| TLS error (connection refused / handshake failure) | Certificate expired, trust anchor mismatch, or network issue |

For TLS errors that prevent a connection before any HTTP status is logged, inspect the Corgi process output for the raw TLS error. Then check:

```bash
# Check Corgi's client cert expiry
openssl x509 -in <corgi-client-cert.pem> -noout -dates

# Check Shepherd's server cert from Corgi's perspective
openssl s_client -connect <shepherd-host>:7010 -cert <corgi-cert.pem> -key <corgi-key.pem> \
  -CAfile <ca-bundle.pem>
```

### Recovery — Shepherd unavailable

Corgi is designed for this. When Shepherd cannot be reached, Corgi continues to operate from its last cached assignment state and keeps serving the certificates it has already installed. No action is required on the Corgi side. Restore Shepherd availability; Corgi will resume pulling on its next poll interval.

Note: while Shepherd is down, Corgi cannot renew expiring certificates. Restore Shepherd before any installed certificates reach their expiry.

### Recovery — mTLS or identity errors

See scenario 3.

---

## 3. mTLS identity mismatch (401 on agent port)

### Symptoms

Corgi repeatedly receives `401` responses from Shepherd's agent port (7010). Log lines on Corgi:

```
C < 401 GET /agents/<node-id>/assignments <shepherd-host>:7010 <peer_ip> - <ms>
```

### Cause

Shepherd's `corgi_auth_middleware` validates the client certificate's URI SAN against the Corgi fleet inventory (`shepherd.corgis.json`). If no entry in that file matches the URI SAN byte-for-byte, Shepherd returns `401`. Matching is case-sensitive and exact — a trailing slash, different scheme, or any character difference causes rejection.

### Diagnosis

**Step 1 — Extract the URI SAN from Corgi's client certificate:**

```bash
openssl x509 -in <corgi-client-cert.pem> -noout -ext subjectAltName
```

Look for a `URI:` entry in the output, for example:

```
X509v3 Subject Alternative Name:
    URI:vigil://credo/prod/node/web-01
```

**Step 2 — Compare to the Corgi inventory on Shepherd:**

Open `shepherd.corgis.json` and find the entry for this node. Its `identityUri` field must match the URI SAN from step 1 exactly.

**Step 3 — Check the Shepherd agent port log for the rejected identity:**

```
S > 401 GET /agents/web-01/assignments ... <ms>
```

Shepherd logs the URI SAN it received in debug mode (`logLevel: "debug"` in `shepherd.config.json`).

### Recovery

Two options — pick one:

**Option A — Re-issue the Corgi certificate** with a URI SAN that matches the `identityUri` already in `shepherd.corgis.json`. This is the preferred approach if the cert was issued with a typo.

**Option B — Update `shepherd.corgis.json`** to match the URI SAN in the existing cert. Edit the file, then reload the Corgi inventory without restarting Shepherd:

```
POST /admin/reload-corgis   (Shepherd dashboard port 7011, admin role)
```

---

## 4. Certificate renewal stuck

### Symptoms

A certificate is past its renewal threshold (`renewBeforeDays` before expiry, default 7 days) but has not been renewed. The cert continues to age toward expiry. Shepherd logs show repeated ACME attempts, and `GET /admin/renewal-jobs/last/:name` returns a job with `status: "failed"` and a non-null `error` field.

### Causes

- Vigil is unreachable from Shepherd
- Corgi's HTTP challenge port is not reachable from Vigil during HTTP-01 validation
- Domain DNS does not resolve to the host where Corgi is running HTTP-01 challenges
- Vigil's `issuancePolicy.allowedDnsSuffixes` does not include the certificate's domain

### Diagnosis

**Check the last failed renewal job for the error detail:**

```
GET /admin/renewal-jobs/last/<cert-name>   (Shepherd dashboard port 7011)
```

The `error` field and `trace` array in the response contain the ACME error as returned by Vigil.

**Check Shepherd-to-Vigil connectivity:**

```bash
curl -v --cert <shepherd-cert.pem> --key <shepherd-key.pem> \
  --cacert <ca-bundle.pem> \
  https://<vigil-host>:7020/health
```

A healthy Vigil returns `{"status":"healthy","service":"vigil",...}`.

**Check Corgi HTTP-01 challenge reachability:**

Vigil must be able to reach Corgi's HTTP challenge listener on port 80 (or a configured port-forward from 80 to the `httpChallenge.port` configured in Corgi, default 7080):

```bash
# From the Vigil host, verify the challenge path is reachable:
curl -v http://<corgi-domain>/.well-known/acme-challenge/test
```

A `404` response (not a connection error) means the listener is up; the `test` token just doesn't exist.

**Check DNS:**

```bash
# Confirm the domain resolves to the correct Corgi host
dig +short <domain>
```

### Recovery

Resolve the underlying connectivity, DNS, or Vigil configuration issue. Shepherd will retry the renewal on the next poll cycle. To trigger an immediate retry without waiting:

```
POST /admin/renew/<cert-name>   (Shepherd dashboard port 7011, admin role)
```

---

## 5. Bootstrap fails midway

### Symptoms

The bootstrap script or bootstrap CLI command exits with an error before completing. The deployment is partially initialized.

### What state may be left behind

The bootstrap process proceeds in phases. Depending on where it failed:

| Phase | State left behind |
|-------|-----------------|
| PKI ceremony (ceremony scripts) | Partial root/intermediate CA files on disk |
| Vigil initialization | Vigil may be running with its CA initialized |
| Shepherd bootstrap — admin cert (`/bootstrap/admin-cert`) | Vigil has signed the admin certificate; the token used for this call is spent |
| Shepherd bootstrap — Corgi enrollment (`/bootstrap/corgi`) | A Vigil-issued Corgi cert may exist; Shepherd enrollment token may be spent |

### Recovery

**Identify the failed phase** from the exit message or the last successful log line before the error. Then:

**PKI / cert generation phase** — these are file operations and can generally be re-run safely. Remove any partial output files and re-run the ceremony scripts from the beginning.

**Vigil account was registered** — ACME accounts in Vigil persist across restarts. A re-run of the Shepherd bootstrap will reuse an existing ACME account if the `accountKeyPath` on disk already contains credentials. This is safe; do not delete the account key file.

**Admin or Corgi cert was already signed by Vigil** — the cert exists in Vigil's database. You can inspect it via `GET /certificates/:id` on Vigil's admin API. The cert is still valid and can be reused — copy it to the expected file path if it was not written.

**Enrollment token was spent but bootstrap did not complete** — bootstrap secrets are one-use and ephemeral. If the token is gone and the bootstrap did not complete, re-run `shepherd bootstrap server` to generate a new token, then repeat the failed step.

**When in doubt:** Remove the partial cert directories, clear any in-memory state by restarting the services, and restart the bootstrap from the phase that failed. Earlier completed phases (PKI generation, CA initialization) do not need to be repeated if their output files are intact.

---

## 6. Dashboard auth failures

### Passkey enrollment fails

WebAuthn passkey enrollment requires HTTPS and a Relying Party ID (`rpId`) that matches the origin serving the dashboard. If the `rpId` in the dashboard configuration does not match the hostname in the browser's address bar, the browser will reject registration.

Verify:
- The dashboard is being accessed over HTTPS (WebAuthn is not available on plain HTTP)
- `rpId` in `dashboard.config.json` matches the hostname (not the full URL) used to reach the dashboard — for example, if accessed via `https://credo.example.com`, `rpId` must be `credo.example.com`

### JWT token expired

Shepherd issues ES256 JWT access tokens with a 1-hour expiry. Tokens also carry a refresh token, which can be exchanged for a new access token without re-authenticating:

```
POST /auth/refresh   (Shepherd dashboard port 7011)
Body: { "refreshToken": "<opaque string>" }
```

The old refresh token is revoked when a new one is issued. If the refresh token is also expired or was never stored by the client, the user must re-authenticate via a new proof-of-possession flow (`POST /auth/token`).

### Account not active

Shepherd rejects authentication for accounts with `"active": false`. To re-activate an account:

```
PUT /accounts/<id>   (Shepherd dashboard port 7011, admin role)
Body: { "active": true }
```

Verify the account state:

```
GET /accounts/<id>
```

The response includes the `active` field. If there is no account at all for this identity, create one via `POST /accounts`.

### Dashboard gets 401 when calling Shepherd

Shepherd's dashboard port (7011) accepts either a JWT Bearer token or an mTLS client certificate whose URI SAN matches an active account's `identities` list. A `401` on the dashboard port means neither form of authentication was accepted.

Check:

1. **JWT path** — confirm the token has not expired and was issued by the correct Shepherd instance (check the `aud` claim; it must be `["shepherd"]`).

2. **mTLS path** — extract the URI SAN from the dashboard's client certificate:

   ```bash
   openssl x509 -in <dashboard-cert.pem> -noout -ext subjectAltName
   ```

   Confirm the URI SAN appears in the `identities` array of an account in `shepherd.accounts.json`, and that the account has `"active": true`. Matching is case-sensitive and exact.
