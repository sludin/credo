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
| Default | `./shepherd.jwt.key.pem` |
| Risk | **Low** |
| Set to | An absolute path outside the working directory |

The default is a predictable CWD-relative path. If Shepherd is started from an unexpected directory, the key will be created or looked up in the wrong place. Shepherd auto-generates the key if it does not exist and sets mode `0600`, but the operator should own the path explicitly.

### `bind`

| | |
|---|---|
| Default | `0.0.0.0` |
| Risk | **Low** |
| Set to | A specific interface address |

Shepherd opens two ports: `agentPort` (Corgi-facing, default 7010) and `dashboardPort` (admin-facing, default 7011). Both use the same `bind` value. On a multi-homed host, binding `0.0.0.0` exposes both ports on every interface.

For most deployments:
- Agent port can bind to `0.0.0.0` (or the specific interface Corgis reach) with a network-level firewall restricting inbound to known Corgi addresses.
- Dashboard port should bind to a loopback or internal management interface.

If you need the two ports on different interfaces, consider running a reverse proxy in front of the dashboard port.

### `alerts[].secure`

| | |
|---|---|
| Default | `false` |
| Risk | **Medium** |
| Set to | `true` |

When an SMTP alert channel is configured and `secure` is `false`, the connection to the mail server is unencrypted. Credentials and alert content (which may include certificate names and domain information) are sent in cleartext.

```json
"alerts": [
  {
    "type": "email",
    "host": "smtp.example.com",
    "port": 465,
    "secure": true,
    "user": "alerts@example.com",
    "password": "...",
    "from": "credo-alerts@example.com",
    "to": ["ops@example.com"]
  }
]
```

---

## Corgi

Config file: `corgi.config.json`

### `bind`

| | |
|---|---|
| Default | `0.0.0.0` |
| Risk | **Low** |
| Set to | The interface Shepherd reaches this node on |

The mTLS control port (`mtlsPort`, default 7001) accepts inbound connections from Shepherd and any other authorized client. Binding `0.0.0.0` exposes it on all interfaces. Restrict to the specific interface your network topology uses for Shepherd–Corgi traffic.

### `httpChallenge.bind`

| | |
|---|---|
| Default | `0.0.0.0` (when `httpChallenge` block is present) |
| Risk | **Medium** |
| Set to | The interface your ACME CA reaches, or `127.0.0.1` if Vigil is co-located |

The HTTP-01 challenge listener has no authentication — challenge tokens are public by design (RFC 8555). Binding it to `0.0.0.0` exposes the endpoint on all interfaces, including any public-facing ones. If Vigil is on the same host, bind to loopback. If Vigil reaches Corgi over an internal network, bind to that interface.

```json
"httpChallenge": {
  "enabled": true,
  "port": 7080,
  "bind": "10.0.0.1"
}
```

If HTTP-01 is not needed (you are not using ACME or use DNS-01), omit the `httpChallenge` block entirely.

### `filePolicy.keyMode`

| | |
|---|---|
| Default | `0640` |
| Risk | **Low** |
| Set to | `"0600"` |

The example config already sets `"keyMode": "0600"`. Confirm this is present. A mode of `0640` allows the group to read private keys — acceptable if the group is tightly controlled (e.g., `ssl-cert`) but `0600` is safer and sufficient for the service user.

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

An empty list disables DNS name filtering entirely — Vigil will issue certificates for any domain name a client requests. This is the largest policy gap in a default Vigil deployment.

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

Vigil is the only service that defaults to loopback. This is intentional: it holds the intermediate CA private key. If Vigil is on a separate host from Shepherd, bind to the specific private interface they share — not to all interfaces.

### `caEcdsaIntermediateKeyPath`

| | |
|---|---|
| Default | `./ca/int-ecdsa/private/int-ecdsa.key.pem` |
| Risk | **High** |
| Set to | An absolute path |

A CWD-relative path means the key location depends on the directory Vigil is started from. Use an absolute path to eliminate ambiguity. The file must be owned by the Vigil process user with mode `0600`.

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

The example file ships with the literal placeholder `"replace-with-a-long-random-secret"`. The service will start with this value — there is no startup check that the placeholder was replaced. A deployment that copies the example verbatim uses a publicly known session secret, making all sessions forgeable.

Generate a secret before deployment:

```bash
openssl rand -base64 48
```

Store the result outside version control. Do not commit it.

### `bind`

| | |
|---|---|
| Default | `0.0.0.0` |
| Risk | **Low** |
| Set to | A loopback or internal management interface |

The Dashboard BFF serves the admin UI and proxies to Shepherd's dashboard port. Both should be on an internal interface.

---

## Quick-reference checklist

The five items that most commonly cause security issues in a first deployment:

| # | Service | Field | Default | Action |
|---|---------|-------|---------|--------|
| 1 | Dashboard | `auth.sessionSecret` | placeholder | Replace with `openssl rand -base64 48` output |
| 2 | Vigil | `issuancePolicy.allowedDnsSuffixes` | `[]` | Set to your domain(s) |
| 3 | Shepherd | `alerts[].secure` | `false` | Set to `true` if using SMTP alerts |
| 4 | All | `bind` | `0.0.0.0` | Restrict to specific interface(s) |

Verify after deployment:

```bash
# Vigil issuance policy has at least one suffix
python3 -c "import json,sys; p=json.load(open('vigil.config.json')); s=p.get('issuancePolicy',{}).get('allowedDnsSuffixes',[]); sys.exit(0 if s else 1)" && echo "OK" || echo "MISSING"

# Intermediate CA key permissions
stat -c "%a %U" /etc/credo/vigil/ca/int-ecdsa/private/int-ecdsa.key.pem
# Expected: 600 vigil (or your service user)
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
