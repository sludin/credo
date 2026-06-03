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

## Timers

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `pollIntervalSeconds` | number | `60` | How often Shepherd polls each Corgi for flock status |
| `corgiHealthCheckIntervalSeconds` | number | `300` | How often Shepherd sends a lightweight `/health` ping to each Corgi |
| `renewBeforeDays` | number | `7` | Start renewal this many days before a certificate expires |

## DNS Override

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `dnsOverride` | object | `{}` | Map of hostname → IP used for outbound connections to Corgi nodes. Useful when DNS is not yet configured |

## Logging

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `logLevel` | string | `"info"` | One of `"fatal"`, `"warn"`, `"info"`, `"debug"` |

---

## Companion Files

### `shepherd.corgis.json`

Defines the Corgi fleet. Shepherd polls each node in this file. The file is hot-reloaded without restart when its mtime changes.

```json
{
  "defaults": {
    "mtlsCert": "/etc/shepherd/certs/fullchain.pem",
    "mtlsKey":  "/etc/shepherd/certs/privkey.pem",
    "mtlsCa":   "/etc/credo/credo-catrust.pem"
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
| `mtlsCert` | no | Override client cert for this node (falls back to `defaults.mtlsCert`) |
| `mtlsKey` | no | Override client key for this node |
| `mtlsCa` | no | Override CA bundle for this node |

### `shepherd.ca.json`

Defines the certificate authorities Shepherd uses for ACME issuance. Each entry under `cas` has a name, `protocol` (`"acme"`), `provider`, and `config` block.

**Vigil (internal CA):**
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
        "supportedValidations": ["none-01"],
        "defaultValidation": "none-01",
        "tlsCert": "/etc/shepherd/certs/fullchain.pem",
        "tlsKey":  "/etc/shepherd/certs/privkey.pem",
        "ca":      "/etc/credo/credo-catrust.pem"
      }
    }
  }
}
```

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

### `shepherd.accounts.json`

RBAC identity registry. Maps Vigil URI SANs or certificate fingerprints to roles (`admin`, `operator`, `readonly`).

```json
{
  "accounts": [
    {
      "name":        "alice",
      "identityUri": "vigil://credo/dev/admin/alice",
      "role":        "admin"
    },
    {
      "name":        "ci-reader",
      "fingerprint": "abcd1234...",
      "role":        "readonly"
    }
  ]
}
```

### `shepherd.assignments.json`

Managed certificate assignments. Each entry maps a certificate name to a Corgi node and CA.

```json
{
  "assignments": [
    {
      "name":    "api.example.com",
      "corgi":   "corgi-01",
      "ca":      "vigil",
      "domains": ["api.example.com"]
    }
  ]
}
```
