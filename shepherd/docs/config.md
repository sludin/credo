# Shepherd Configuration Reference

Shepherd loads its config from `shepherd.config.json` in the working directory, or from the path in `SHEPHERD_CONFIG_PATH`.

Config files support variable interpolation (`${VAR}`) from the `vars` block and from environment variables, and `includes` arrays for splitting config across multiple files. Keys prefixed with `_` are stripped before parsing (use them as JSON comments).

## Meta Fields

| Field | Type | Description |
|-------|------|-------------|
| `vars` | object | Variable definitions, referenced as `${name}` elsewhere in the config |
| `includes` | string[] | Paths to additional JSON config files to merge in (resolved relative to this file) |
| `baseDir` | string | Base directory for resolving relative paths. Defaults to the config file's directory |

## Network

| Field | Type | Default | Env override | Description |
|-------|------|---------|--------------|-------------|
| `agentPort` | number | `7010` | `SHEPHERD_AGENT_PORT` | Port for the Corgi-facing agent API |
| `dashboardPort` | number | `7011` | `SHEPHERD_DASHBOARD_PORT` | Port for the dashboard / admin API |
| `bind` | string | `"127.0.0.1"` | — | Interface to bind both servers. Set to `"0.0.0.0"` to bind all interfaces |

## TLS

All three paths are **required**.

| Field | Type | Description |
|-------|------|-------------|
| `tls.certPath` | string | Path to the server certificate (PEM, full chain) |
| `tls.keyPath` | string | Path to the server private key (PEM) |
| `tls.clientCaPath` | string | Path to the client CA bundle used to validate Corgi mTLS client certificates |

## Auth

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `auth.jwtSigningKeyPath` | string | **required** | Path to the PEM private key used to sign JWT tokens for dashboard sessions |

## Identity (Vigil integration)

These fields are optional but required when Shepherd registers itself with Vigil.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `commonName` | string | — | Shepherd's TLS common name (e.g. `"shepherd.example.com"`) |
| `identityUri` | string | — | Shepherd's URI SAN identity (e.g. `"vigil://credo/dev/service/shepherd"`) |
| `vigilUrl` | string | — | Base URL of the Vigil CA (e.g. `"https://vigil.example.com:7020"`) |
| `shepherdCaPath` | string | — | Path to the CA trust bundle used to verify Vigil's server cert |

## Companion Config File Paths

Shepherd reads several companion JSON files. Each has a default path relative to `baseDir`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `corgisConfigPath` | string | `"shepherd.corgis.json"` | Corgi node inventory. Hot-reloaded on each poll cycle |
| `assignmentsConfigPath` | string | `"shepherd.assignments.json"` | Managed certificate assignments |
| `caConfigPath` | string | `"shepherd.ca.json"` | CA configuration (ACME providers) |
| `accountsPath` | string | `"shepherd.accounts.json"` | RBAC identity registry |

## Cert Store

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `certStoreDir` | string | `"store"` | Root directory for issued certificate material (`archive/` + `live/` layout) |
| `renewalJobsDir` | string | — | Directory for persisting in-progress renewal job state. If unset, renewal jobs are in-memory only |
| `issuanceLedgerPath` | string | `"shepherd.issuance-log.json"` | Append-only log of certificate issuance events used to enforce per-domain (50/7 days) and per-identifier-set (5/7 days) rate limits. Missing or corrupt file starts fresh with a warning |

## Timers

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `reconcileIntervalSeconds` | number | `300` | How often Shepherd runs its combined reconcile probe against each Corgi (`GET /flock`): one jittered request per corgi per interval answers both liveness and cert-state questions. The first sweep runs immediately at startup |
| `renewalCheckIntervalSeconds` | number | `43200` | How often Shepherd sweeps all assignments for certificates needing renewal (default twice daily). Assignment changes made via the API trigger maintenance for the affected corgi immediately, outside this sweep |
| `renewBeforeDays` | number | `30` | Start renewal this many days before a certificate expires |

Deprecated aliases: `pollIntervalSeconds` is accepted as an alias for `reconcileIntervalSeconds` (logged as a warning); `corgiHealthCheckIntervalSeconds` is accepted but ignored — the reconcile probe covers health checking and there is no separate `/health` loop.

## DNS Override

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `dnsOverride` | object | `{}` | (**Not yet implemented**) Map of hostname → IP for outbound Corgi connections. Useful when DNS is not yet configured. Currently parsed but not applied |

## Logging

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `logLevel` | string | `"info"` | One of `"fatal"`, `"warn"`, `"info"`, `"debug"` |
| `logging.enabled` | boolean | `false` | Enable a size-rotated log file (in addition to stdout) with a live broadcast, so the `/admin/logs` endpoint has historical + live-tail data to serve. Omit the whole `logging` block for current stdout-only behavior |
| `logging.dir` | string | `"logs"` | Directory for the rotating log file, relative to the service's working directory |
| `logging.rotateOn.sizeMb` | number | `100` | Rotate to a new file once the current one reaches this size |
| `logging.rotateOn.keepFiles` | number | `12` | Number of rotated backups to retain |
| `logging.alsoStdout` | boolean | `true` | Also emit to stdout when file logging is enabled (set `false` for file-only) |

---

## GET /admin/logs

Query params: `target` (`"shepherd"` default, `"vigil"`, or `"corgi:<name>"`), `since`, `until`, `last` (duration shorthand like `"5m"`/`"1h"`), `level` (`"error"`/`"warn"`/`"info"`/`"debug"`, minimum severity), `q` (case-insensitive substring), `limit`. Returns a JSON array of log lines. Requires Readonly role or higher. Live tail (`?follow=true`) is not yet supported on this endpoint.

---

## Companion Files

### `shepherd.corgis.json`

Defines the Corgi fleet. Shepherd polls each node in this file. The file is hot-reloaded without restart when its mtime changes.

```json
{
  "defaults": {
    "mtls": {
      "certPath": "/etc/shepherd/certs/fullchain.pem",
      "keyPath":  "/etc/shepherd/certs/privkey.pem",
      "caPath":   "/etc/credo/credo-catrust.pem"
    }
  },
  "corgis": [
    {
      "name":        "corgi-01",
      "url":         "https://corgi-01.example.com:7001",
      "identityUri": "vigil://credo/dev/node/corgi-01"
    }
  ]
}
```

Each Corgi entry:

| Field | Required | Description |
|-------|----------|-------------|
| `name` | yes | Unique identifier for this node |
| `url` | yes | mTLS API base URL |
| `identityUri` | yes | Expected URI SAN in Corgi's client certificate |
| `mtls.certPath` | no | Override client cert for this node (falls back to `defaults.mtls.certPath`) |
| `mtls.keyPath` | no | Override client key for this node |
| `mtls.caPath` | no | Override CA bundle for this node |

### `shepherd.ca.json`

Defines the certificate authorities Shepherd uses for ACME issuance. Each entry under `cas` has a name, `protocol` (`"acme"`), `provider`, and `config` block.

**Vigil (internal CA, http-01):**
```json
{
  "cas": {
    "vigil": {
      "protocol": "acme",
      "provider": "vigil",
      "config": {
        "directoryUrl": "https://vigil.example.com:7020/acme/directory",
        "days": 45,
        "renewBeforeDays": 7,
        "accountEmail": "ops@example.com",
        "accountKeyPath": "./shepherd-acme-account.pem",
        "supportedValidations": ["http-01"],
        "defaultValidation": "http-01",
        "tlsCert": "/etc/shepherd/certs/fullchain.pem",
        "tlsKey":  "/etc/shepherd/certs/privkey.pem",
        "ca":      "/etc/credo/credo-catrust.pem"
      }
    }
  }
}
```

> **Note:** `none-01` is no longer the recommended default. Vigil rejects `none-01` challenges unless `allowNoneValidation: true` is set in `vigil.config.json` (off by default; not for production). Use `http-01` (requires Corgi's HTTP challenge listener on port 7080) or `dns-01` (requires a DNS provider adapter) instead.

**Let's Encrypt (DNS-01 via Hurricane Electric):**
```json
{
  "cas": {
    "letsencrypt": {
      "protocol": "acme",
      "provider": "letsencrypt",
      "config": {
        "directoryUrl": "https://acme-v02.api.letsencrypt.org/directory",
        "days": 90,
        "renewBeforeDays": 30,
        "accountEmail": "ops@example.com",
        "accountKeyPath": "./shepherd-acme-account-le.pem",
        "supportedValidations": ["dns-01"],
        "defaultValidation": "dns-01",
        "validation": {
          "dns-01": {
            "provider": "he",
            "providerConfig": { "ddnsKey": "${SHEPHERD_DDNS_KEY}" }
          }
        }
      }
    }
  }
}
```

#### `rateLimits` (optional)

Per-CA rate limiting for certificate issuance. If absent, no rate limits are enforced for this CA. Configure this for public CAs (e.g. Let's Encrypt) to track and respect their quotas; omit for private CAs (e.g. Vigil) and staging environments.

```json
"rateLimits": {
  "certificatesPerDomain": { "count": 50, "windowDays": 7 },
  "duplicateCertificates": { "count": 5, "windowDays": 7 }
}
```

| Field | Type | Description |
|---|---|---|
| `certificatesPerDomain` | object \| omit | Limit issuances per registered domain (eTLD+1). Omit for no limit on this category. |
| `duplicateCertificates` | object \| omit | Limit re-issuances of the exact same SAN set. Omit for no limit on this category. |
| `count` | integer | Maximum certificates allowed within the window. |
| `windowDays` | integer | Rolling window duration in days. |

**Examples:**
- Let's Encrypt production: `certificatesPerDomain: {count: 50, windowDays: 7}`, `duplicateCertificates: {count: 5, windowDays: 7}`
- Vigil / LE Staging: omit `rateLimits` (no limits enforced)

> **Note:** The issuance ledger's prune window is set at startup to the maximum `windowDays` across all configured CAs (default: 7 days). If you add a CA with a longer window after startup, restart shepherd to avoid pruning needed events.

### `shepherd.accounts.json`

RBAC identity registry. Each account maps one or more Vigil URI SANs to a role (`admin`, `operator`, `readonly`).

```json
{
  "accounts": [
    {
      "id":          "acct-001",
      "name":        "alice",
      "displayName": "Alice Admin",
      "role":        "admin",
      "active":      true,
      "identities":  ["vigil://credo/dev/admin/alice"],
      "notes":       ""
    },
    {
      "id":          "acct-002",
      "name":        "dashboard",
      "displayName": "Dashboard Service",
      "role":        "operator",
      "active":      true,
      "identities":  ["vigil://credo/prod/service/dashboard"],
      "notes":       ""
    }
  ]
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `id` | yes | Unique account identifier |
| `name` | yes | Short machine-readable name |
| `displayName` | yes | Human-readable label |
| `role` | yes | `"admin"`, `"operator"`, or `"readonly"` |
| `active` | no (default `true`) | Inactive accounts are rejected at auth time |
| `identities` | no | URI SANs that map to this account |
| `notes` | no | Free-text operator notes |

### `shepherd.assignments.json`

Managed certificate assignments. Each entry maps a certificate name to a Corgi node and CA. The `certName` field defaults to the value of `domain` when omitted.

```json
{
  "assignments": [
    {
      "certName":    "api.example.com",
      "corgi":       "corgi-01",
      "ca":          "vigil",
      "domain":      "api.example.com",
      "identityUri": "vigil://credo/prod/service/api"
    }
  ]
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `certName` | no | Certificate name. Defaults to `domain` when omitted |
| `corgi` | no | Corgi node name from `shepherd.corgis.json`. Omit for operator-managed (non-corgi) certs |
| `ca` | yes | CA name from `shepherd.ca.json` |
| `domain` | no | Primary domain for ACME ordering and the default cert name |
| `sans` | no | Additional DNS SANs beyond `domain` |
| `identityUri` | no | URI SAN to embed in the certificate |
| `days` | no | Certificate validity in days (overrides CA default) |
| `renewBeforeDays` | no | Renewal threshold in days (overrides CA default) |
| `monitor` | no | Endpoint monitor endpoint(s). A single object `{ "host": "...", "port": 443, "protocol": "https" }`, or an array of such objects to check several endpoints for one cert (e.g. a SAN cert served from multiple hosts). The corgi periodically TLS-handshakes each `host:port` (SNI = assignment `domain`, falling back to `host`) and reports `cert-mismatch` when the served leaf differs from the installed cert. `port` defaults to `443`; `protocol` is `"https"` (default) or `"tls"` — both are a plain TLS handshake in v1. Two more fields are optional per endpoint: `caPath`, a PEM CA bundle (e.g. `credo-catrust.pem`) the served chain is additionally checked against — diagnostic only, reported as `chainTrusted` and never itself flips ok/cert-mismatch/unreachable, since the fingerprint compare remains the sole source of truth for that; and `resolveIp`, which pins the TCP connection to a specific address instead of resolving `host` via DNS (useful when `host` is dynamic DNS and you want to rule out DNS drift). With multiple endpoints, overall status is `ok` only if every endpoint matches, `partial-success` if some do and some don't, and otherwise the same single-endpoint priority as before. Omit for no monitoring |
| `forceRevalidate` | no | (**Not yet implemented**) Force a full ACME revalidation cycle regardless of cert age. Intended for testing |
