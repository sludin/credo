# Operator Hardening Guide

This guide is a deployment checklist — every item here is a default that is acceptable for development but must be reviewed before a production deployment. Items are grouped by service and ordered by severity.

## Before you deploy

All four services share the same config loading pipeline:

- `_prefixed` keys are silently stripped before parsing — use them as JSON comments.
- `vars` blocks and `includes` arrays let you share values across config files.
- Variable placeholders (`${VAR}`) are interpolated from `vars` blocks and the process environment.
- Config files often contain paths to private key material. Treat them as secrets: store them outside version control, restrict file permissions, and verify ownership after deployment.

---

## Shepherd

Config file: `shepherd.config.json`

### `auth.jwtSigningKeyPath`

| | |
|---|---|
| Default | none (required) |
| Risk | **Low** |
| Set to | An absolute path outside the working directory |

Shepherd auto-generates the key if the file does not exist and sets mode `0600`. However, a relative path means the key location depends on which directory Shepherd is started from. Use an absolute path to eliminate ambiguity:

```json
"auth": {
  "jwtSigningKeyPath": "/var/apps/credo/shepherd/shepherd.jwt.key.pem"
}
```

### `bind`

| | |
|---|---|
| Default | `127.0.0.1` |
| Risk | **Low** (correct default) |
| Action | Do not change to `0.0.0.0` without network controls |

Shepherd opens two ports: `agentPort` (Corgi-facing, default 7010) and `dashboardPort` (admin-facing, default 7011). Both use the same `bind` value. The default restricts both to loopback, which is the correct starting point.

If Corgi and Shepherd are on different machines, bind the agent port to the specific interface Corgis reach. Keep the dashboard port on a loopback or internal management interface:

```json
"bind": "10.0.0.1"
```

If you need the two ports on different interfaces, run a reverse proxy in front of one of them rather than binding Shepherd to `0.0.0.0`.

### `renewalJobsDir`

| | |
|---|---|
| Default | none (in-memory only) |
| Risk | **Medium** |
| Set to | An absolute path |

Without `renewalJobsDir`, all pending and in-progress renewal jobs are lost if Shepherd restarts. Shepherd re-triggers renewal on the next poll cycle, but there is a delay of one poll interval and any partial ACME progress is abandoned. Set this in production:

```json
"renewalJobsDir": "/var/apps/credo/shepherd/renewal-jobs"
```

---

## Corgi

Config file: `corgi.config.json`

### `bind`

| | |
|---|---|
| Default | `127.0.0.1` |
| Risk | **Low** (correct default) |
| Action | Set to the specific interface Shepherd reaches this node on |

The mTLS control port (`mtlsPort`, default 7001) accepts inbound connections from Shepherd and any other authorized client. The default `127.0.0.1` is appropriate when Shepherd and Corgi share a host. For a multi-machine setup, bind to the specific interface your network topology uses for Shepherd–Corgi traffic — not `0.0.0.0`:

```json
"bind": "10.0.0.1"
```

### `httpChallenge.bind`

| | |
|---|---|
| Default | `0.0.0.0` (when `httpChallenge` block is present) |
| Risk | **Medium** |
| Set to | The interface your ACME CA reaches, or `127.0.0.1` if Vigil is co-located |

The HTTP-01 challenge listener has no authentication — challenge tokens are public by design (RFC 8555). Binding it to `0.0.0.0` exposes the endpoint on all interfaces. If Vigil is on the same host, bind to loopback. If Vigil reaches Corgi over an internal network, bind to that interface:

```json
"httpChallenge": {
  "enabled": true,
  "port": 7080,
  "bind": "10.0.0.1"
}
```

If HTTP-01 is not needed (you are using DNS-01 or a CA that supports `none-01`), omit the `httpChallenge` block entirely.

### `auth.mode`

| | |
|---|---|
| Default | `"mtls"` (correct default) |
| Risk | **High** if changed incorrectly |
| Action | Do not set to `"proxy-headers"` without a trusted TLS-terminating proxy in front |

`auth.mode: "proxy-headers"` tells Corgi to trust identity information from HTTP headers (`x-corgi-client-cert`, `x-corgi-san-uri`, etc.) instead of verifying client certificates itself. This mode exists for deployments where a load balancer or ingress terminates mTLS and forwards identity headers.

If `proxy-headers` mode is used without a trusted proxy that actually enforces mTLS, any caller can forge the headers and impersonate any identity. Only enable this mode if:

- A TLS-terminating proxy is in front of Corgi that is not accessible to external clients.
- The proxy is configured to strip and re-populate the identity headers from the verified client cert.

In all other cases, keep the default `"mtls"` mode.

### `filePolicy.keyMode`

| | |
|---|---|
| Default | `0640` |
| Risk | **Low** |
| Set to | `"0600"` |

The example config already sets `"keyMode": "0600"`. Confirm this is present. A mode of `0640` allows the group to read private keys — acceptable if the group is tightly controlled (e.g., `ssl-cert`) but `0600` is safer and sufficient for the service user:

```json
"filePolicy": {
  "owner":    "root",
  "group":    "ssl-cert",
  "certMode": "0644",
  "keyMode":  "0600"
}
```

---

## Vigil

Config file: `vigil.config.json`

### `issuancePolicy.allowedDnsSuffixes`

| | |
|---|---|
| Default | `[]` |
| Risk | **Medium** |
| Set to | The DNS suffixes your deployment owns |

An empty list denies all DNS certificate issuance — Vigil will reject any CSR containing a DNS SAN. This is secure by default. To enable issuance, set the suffixes your deployment owns. To permit any domain (not recommended), use `["*"]`.

```json
"issuancePolicy": {
  "allowedDnsSuffixes": ["example.com"],
  "allowSubdomains": true,
  "allowBareSuffix": true,
  "allowedIdentityUriPrefixes": ["vigil://credo/prod/"],
  "allowIpSans": false
}
```

Once `allowedDnsSuffixes` is non-empty, `allowSubdomains` and `allowBareSuffix` control whether `*.example.com` and `example.com` (without a subdomain) are permitted. Both default to `true` when the suffix list is populated.

### `issuancePolicy.allowedIdentityUriPrefixes`

| | |
|---|---|
| Default | `[]` |
| Risk | **Medium** |
| Set to | Your identity URI prefix (e.g., `"vigil://credo/prod/"`) |

Same as DNS suffixes: an empty list means any URI SAN can be included in an issued certificate. Set this to your deployment's identity namespace.

### `bind`

| | |
|---|---|
| Default | `127.0.0.1` |
| Risk | — (correct default) |
| Action | Do not change to `0.0.0.0` |

Vigil defaults to loopback — intentional, because it holds the intermediate CA private key. If Vigil is on a separate host from Shepherd, bind to the specific private interface they share, not to all interfaces.

### `caEcdsaIntermediateKeyPath`

| | |
|---|---|
| Default | `./ca/int-ecdsa/private/int-ecdsa.key.pem` |
| Risk | **High** |
| Set to | An absolute path |

A CWD-relative path means the key location depends on the directory Vigil is started from. Use an absolute path to eliminate ambiguity. The file must be owned by the Vigil process user with mode `0600`:

```bash
chmod 600 /etc/credo/vigil/ca/int-ecdsa/private/int-ecdsa.key.pem
chown vigil:vigil /etc/credo/vigil/ca/int-ecdsa/private/int-ecdsa.key.pem
```

### Root CA key: take offline after the PKI ceremony

After running the PKI ceremony and signing the intermediate certificate, the root CA private key must be removed from the Vigil host. Only the intermediate key needs to be present for day-to-day issuance. The root key should be stored offline (encrypted USB, HSM, or equivalent) and brought online only to issue or rotate the intermediate.

---

## Dashboard

Config file: `dashboard.config.json`

### `auth.sessionSecret`

| | |
|---|---|
| Default | none (required field) |
| Risk | **High** |
| Action | Generate a strong random secret before first start |

The Dashboard BFF enforces this at startup: it refuses to start if the value matches a known placeholder or is shorter than 32 characters. A deployment with a weak or placeholder secret fails loudly at boot rather than silently at runtime.

Generate a secret before deployment:

```bash
openssl rand -base64 32
```

Store the result outside version control. Do not commit it.

### `bind`

| | |
|---|---|
| Default | `127.0.0.1` |
| Risk | **Low** (correct default) |
| Action | Do not change to `0.0.0.0` without network controls |

The Dashboard BFF serves the admin UI and proxies to Shepherd's dashboard port. Both should remain on an internal interface. The default loopback binding is appropriate when a reverse proxy (nginx, Caddy, etc.) fronts the dashboard for external access.

### `mtls.rejectUnauthorized`

| | |
|---|---|
| Default | `true` |
| Risk | **High** if changed |
| Action | Never set to `false` in production |

This controls whether the dashboard verifies Shepherd's server certificate when making outbound mTLS calls. `false` disables certificate verification entirely, making man-in-the-middle attacks trivial. It exists only to ease local development with self-signed certs. Set to `true` in any non-development environment:

```json
"mtls": {
  "rejectUnauthorized": true
}
```

---

## Quick-reference checklist

| # | Service | Field | Default | Action |
|---|---------|-------|---------|--------|
| 1 | Dashboard | `auth.sessionSecret` | *(enforced at startup — placeholder or short value refuses to start)* | Generate with `openssl rand -base64 32` |
| 2 | Vigil | `issuancePolicy.allowedDnsSuffixes` | `[]` (deny-all) | Set to your domain(s); `["*"]` to allow any |
| 3 | Vigil | `issuancePolicy.allowedIdentityUriPrefixes` | `[]` | Set to your identity URI prefix |
| 4 | Any | `bind` | `127.0.0.1` | If changed to expose a port externally, confirm firewall rules restrict access |
| 5 | Corgi | `auth.mode` | `"mtls"` | Do not set to `"proxy-headers"` without a verified TLS-terminating proxy |

Verify after deployment:

```bash
# Vigil issuance policy has at least one DNS suffix
python3 -c "import json,sys; p=json.load(open('vigil.config.json')); s=p.get('issuancePolicy',{}).get('allowedDnsSuffixes',[]); sys.exit(0 if s else 1)" && echo "OK" || echo "MISSING"

# Vigil issuance policy has at least one URI prefix
python3 -c "import json,sys; p=json.load(open('vigil.config.json')); s=p.get('issuancePolicy',{}).get('allowedIdentityUriPrefixes',[]); sys.exit(0 if s else 1)" && echo "OK" || echo "MISSING"

# Intermediate CA key permissions
stat -c "%a %U" /etc/credo/vigil/ca/int-ecdsa/private/int-ecdsa.key.pem
# Expected: 600 vigil (or your service user)

# Dashboard session secret is not the example placeholder
python3 -c "import json,sys; c=json.load(open('dashboard.config.json')); s=c.get('auth',{}).get('sessionSecret',''); sys.exit(1 if 'replace' in s.lower() else 0)" && echo "OK" || echo "PLACEHOLDER NOT REPLACED"
```

---

## File permissions reference

| File type | Mode | Notes |
|-----------|------|-------|
| TLS/mTLS certificate (`.pem`, fullchain) | `0644` | Readable by service; group/world-readable is fine |
| Private key | `0600` | Owner read/write only — no group, no world |
| Config file containing credentials | `0600` | `shepherd.config.json`, `vigil.config.json`, `dashboard.config.json` |
| CA data directory | `0700` | The directory itself; contains cert DB and key material |
| Assignment/accounts JSON (no secrets) | `0640` | Group-readable for shared-service scenarios |
| JWT signing key | `0600` | Shepherd auto-sets this on creation |
| Issuance ledger (`shepherd.issuance-log.json`) | `0640` | Contains domain names and issuance timestamps; no key material |
