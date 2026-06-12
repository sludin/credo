# Dashboard CLI Reference

```
dashboard <group> <command> [options]
```

Config is loaded from `dashboard.config.json` in the current directory, or from the path in `DASHBOARD_CONFIG_PATH`.

---

## `dashboard server`

### `dashboard server start`

Start the Dashboard BFF (backend-for-frontend) server in the foreground. Serves the compiled React SPA and proxies API requests to Shepherd using mTLS.

```bash
dashboard server start
```

The BFF:
- Listens on HTTPS at the configured `port` (default 7030) and `bind` (default `127.0.0.1`).
- Presents its mTLS client certificate when proxying to Shepherd's dashboard API.
- Manages passkey-based session authentication for browser users.
- Runs in-memory DNS TXT polling jobs for the DNS TXT checker tool.

To develop with hot-reload, use `npm run dev` from the `dashboard/` directory instead.

---

## `dashboard user`

User management commands read and write `dashboard.users.json` directly. The BFF does not need to be running. Changes take effect when the BFF next reads the file (on the next request that touches user data).

### `dashboard user create`

Create a new dashboard user and generate a time-limited enrollment URL. The user opens the URL in a browser to register their passkey, using their Vigil certificate to prove identity.

```bash
dashboard user create \
  --account dashboard-service \
  --email alice@example.com \
  --name "Alice Admin" \
  --identity vigil://credo/prod/admin/alice
```

| Flag | Required | Description |
|------|----------|-------------|
| `--account` | yes | Shepherd account name this user is linked to (must match an entry in `shepherd.accounts.json`) |
| `--email` | yes | User's email address |
| `--name` | yes | Display name shown in the UI |
| `--identity` | yes | Vigil identity URI — must match the URI SAN in the user's Vigil certificate |

Output:
```
Created user: Alice Admin (dashboard-service)
Identity URI: vigil://credo/prod/admin/alice

Enrollment URL (expires in 24h):
https://dashboard.example.com/enroll/abc123...

Send this URL to the user. They will need their Vigil cert + key to complete enrollment.
```

The enrollment token TTL is set by `auth.enrollmentTokenTTLHours` in config (default 24 hours). After expiry, use `dashboard user reset` to generate a fresh link.

### `dashboard user list`

Print a table of all dashboard users with their enrollment and passkey status.

```bash
dashboard user list
```

```
id     shepherdAccount  displayName  email              active  passkeys  enrolled
--     ---------------  -----------  -----              ------  --------  --------
uuid1  dashboard-svc    Alice Admin  alice@example.com  true    2         yes
uuid2  ops-user         Bob Ops      bob@example.com    true    0         pending
```

### `dashboard user reset`

Revoke all of a user's passkeys, optionally update their profile fields, and generate a new enrollment URL. Use this when a user loses their device or needs to re-enroll.

```bash
dashboard user reset --account alice-admin
dashboard user reset --account alice-admin --name "Alice A." --email newemail@example.com
```

| Flag | Required | Description |
|------|----------|-------------|
| `--account` | yes | Shepherd account name of the user to reset |
| `--email` | no | Update email address |
| `--name` | no | Update display name |
| `--identity` | no | Update Vigil identity URI |

All passkeys are revoked immediately. The user must complete enrollment again using the new URL.

---

## `dashboard enroll`

Generate a Proof-of-Possession (PoP) token from an operator's Vigil certificate and private key. The PoP is pasted into the browser's enrollment page to prove the operator controls the certificate that matches their `--identity` URI.

This command is used during the enrollment ceremony when the browser cannot directly access the private key (e.g., the key is on a separate machine or HSM).

```bash
dashboard enroll \
  --cert /etc/credo/admin/admin.fullchain.pem \
  --key  /etc/credo/admin/admin.privkey.pem \
  --challenge <TOKEN_FROM_URL>
```

| Flag | Required | Description |
|------|----------|-------------|
| `--cert` | yes | Path to the Vigil client certificate PEM |
| `--key` | yes | Path to the matching private key PEM |
| `--challenge` | yes | The enrollment token from the `/enroll/<token>` URL |

The command:
1. Reads the URI SAN from the certificate (must be a `vigil://` URI).
2. Signs `SHA256(challenge_bytes || identityUri || issuedAt)` with the private key.
3. Prints a JSON PoP object to stdout.

Paste the JSON output into the enrollment page's PoP field. The BFF verifies the signature, creates a Shepherd auth token for the user, and completes enrollment.

```json
{
  "cert": "-----BEGIN CERTIFICATE-----\n...",
  "signature": "base64url-encoded-signature",
  "challenge": "hex-encoded-token",
  "identityUri": "vigil://credo/prod/admin/alice",
  "issuedAt": "2026-01-15T12:00:00.000Z"
}
```

---

## Environment variables

| Variable | Description |
|----------|-------------|
| `DASHBOARD_CONFIG_PATH` | Override the default config file path (`dashboard.config.json`) |
| `PORT` | Override `port` from config |
| `BIND` | Override `bind` from config |
| `SHEPHERD_API_URL` | Override `shepherdApiUrl` from config |
| `DASHBOARD_CA_PATH` | Override `caPath` from config |
| `DASHBOARD_TLS_CERT_PATH` | Override `tls.certPath` |
| `DASHBOARD_TLS_KEY_PATH` | Override `tls.keyPath` |
| `DASHBOARD_MTLS_CERT_PATH` | Override `mtls.certPath` |
| `DASHBOARD_MTLS_KEY_PATH` | Override `mtls.keyPath` |
| `DASHBOARD_MTLS_CA_PATH` | Override `mtls.caPath` |
| `DASHBOARD_MTLS_REJECT_UNAUTHORIZED` | Override `mtls.rejectUnauthorized` (`1`/`true`/`yes` or `0`/`false`/`no`) |
| `DASHBOARD_REQUEST_TIMEOUT_SECONDS` | Override `requestTimeoutSeconds` |
| `DASHBOARD_DNS_POLLING_INTERVAL_SECONDS` | Override `dnsPollingIntervalSeconds` |
| `DASHBOARD_DNS_JOB_TIMEOUT_SECONDS` | Override `dnsJobTimeoutSeconds` |
