# Configuration File Overview

This document maps every config file in the credo system to its purpose, its default path, and how it is loaded. Use it to understand the full shape of a deployment before digging into per-service reference docs.

---

## How config loading works (all services)

Every service uses the same config-loading pipeline:

- **Primary config path**: set by an environment variable (e.g., `SHEPHERD_CONFIG_PATH`) or defaults to a filename in the current working directory.
- **`baseDir`**: path resolution anchor. Defaults to the directory containing the primary config file. Override it with a `baseDir` field in the config.
- **`vars` blocks**: define local variables, referenced as `${name}` anywhere in the same file.
- **`includes` arrays**: paths to additional JSON files merged in before parsing. Useful for splitting secrets from non-secrets.
- **`_prefixed` keys**: stripped before parsing — use them as JSON comments.
- **Env var overrides**: most individual fields have an env var override (listed in the per-service config reference).

---

## Shepherd

Config files live in the Shepherd working directory (commonly `/var/apps/shepherd/` or whatever the wizard set in `shepherdRoot`).

| File | Default path | Env var | Purpose | Reload |
|------|-------------|---------|---------|--------|
| `shepherd.config.json` | `./shepherd.config.json` | `SHEPHERD_CONFIG_PATH` | Main config: ports, TLS paths, timers, companion file paths | `SIGHUP` |
| `shepherd.accounts.json` | `./shepherd.accounts.json` | set in main config → `accountsPath` | RBAC identity registry: maps Vigil URI SANs to roles (`admin`/`operator`/`readonly`) | mtime-based hot-reload |
| `shepherd.corgis.json` | `./shepherd.corgis.json` | set in main config → `corgisConfigPath` | Corgi fleet inventory: node names, mTLS API URLs, expected URI SANs | mtime-based hot-reload |
| `shepherd.ca.json` | `./shepherd.ca.json` | set in main config → `caConfigPath` | CA definitions: ACME directory URLs, validation methods, account key paths | `SIGHUP` |
| `shepherd.assignments.json` | `./shepherd.assignments.json` | set in main config → `assignmentsConfigPath` | Managed certificate assignments: which cert goes to which Corgi via which CA | mtime-based hot-reload |
| `shepherd.issuance-log.json` | `./shepherd.issuance-log.json` | set in main config → `issuanceLedgerPath` | Append-only issuance event log for rate-limit enforcement (50/domain/7d, 5/identifier-set/7d) | read on each rate-limit check |
| `shepherd.jwt.key.pem` | set in main config → `auth.jwtSigningKeyPath` | — | ES256 private key for signing dashboard JWT tokens; auto-generated at mode 0600 if missing | `SIGHUP` |

**Per-service references:** `shepherd/docs/config.md` | `shepherd/docs/cli.md` | `shepherd/docs/api.md`

---

## Corgi

Config files live in the Corgi working directory (commonly `/var/apps/corgi/` on the managed node).

| File | Default path | Env var | Purpose | Reload |
|------|-------------|---------|---------|--------|
| `corgi.config.json` | `./corgi.config.json` | `CORGI_CONFIG_PATH` | Main config: node identity, Shepherd URL, TLS paths, flock, hooks, auth mode | `SIGHUP` |
| `corgi.fleet-accounts.json` | `./corgi.fleet-accounts.json` | set in main config → `accountsPath` | Local RBAC account registry for Corgi's control API | `SIGHUP` |
| `corgi.assignments.cache.json` | `./corgi.assignments.cache.json` | set in main config → `shepherdSync.assignmentsCachePath` | Persisted copy of the last successful assignment pull from Shepherd. Read on startup if Shepherd is unreachable | updated after each successful sync |

**Cert store** (not config, but part of Corgi's runtime state):

| Path pattern | Description |
|--------------|-------------|
| `<certStoreDir>/live/<name>/fullchain.pem` | Current full-chain certificate for each assigned cert |
| `<certStoreDir>/live/<name>/privkey.pem` | Private key (generated locally; never leaves the node) |
| `<certStoreDir>/archive/<name>/` | Previous certificate generations |

**Per-service references:** `corgi/docs/config.md` | `corgi/docs/cli.md` | `corgi/docs/api.md`

---

## Vigil

Config files live in the Vigil working directory (commonly `/var/apps/vigil/`).

| File | Default path | Env var | Purpose | Reload |
|------|-------------|---------|---------|--------|
| `vigil.config.json` | `./vigil.config.json` | `VIGIL_CONFIG_PATH` | Main config: port, TLS, CA key paths, issuance policy, RBAC | `SIGHUP` |
| `<dataDir>/users.json` | `./data/users.json` | — | User registry: client cert public key fingerprints → active/inactive. Required for non-ACME endpoint access | read per-request |
| `<dataDir>/certificates.json` | `./data/certificates.json` | — | Index of all issued certificates (serial, status, expiry, fingerprint) | read/written per-issuance |
| `<dataDir>/acme-accounts.json` | `./data/acme-accounts.json` | — | ACME account key store (JWK format) | read at startup; written on new account registration |
| `<ctLogPath>` | `./logs/ct.log` | — | Append-only Certificate Transparency log (not submitted externally) | appended on each issuance |

**CA material** (created offline by `ceremony/`; never generated at runtime):

| File | Default path | Env var | Description |
|------|-------------|---------|-------------|
| Intermediate CA key | `./ca/int-ecdsa/private/int-ecdsa.key.pem` | `VIGIL_CA_KEY_PATH` | ECDSA P-384 private key. Mode `0400`. Most sensitive file in the system |
| Intermediate CA cert | `./ca/int-ecdsa/certs/int-ecdsa.cert.pem` | `VIGIL_CA_CERT_PATH` | Intermediate CA certificate |

**Per-service references:** `vigil/docs/config.md` | `vigil/docs/cli.md` | `vigil/docs/api.md`

---

## Dashboard

Config files live in the Dashboard working directory (commonly `/var/apps/dashboard/`).

| File | Default path | Env var | Purpose | Reload |
|------|-------------|---------|---------|--------|
| `dashboard.config.json` | `./dashboard.config.json` | `DASHBOARD_CONFIG_PATH` | Main config: port, TLS, Shepherd URL, auth settings | restart required |
| `dashboard.users.json` | `./dashboard.users.json` (or `auth.usersPath`) | — | User registry: passkeys, enrollment tokens, Shepherd JWT tokens. Managed by `dashboard user` commands and the enrollment flow | read per-request |
| `<auth.sessionsDir>/` | `./sessions/` | — | Server-side session store. Persists sessions across BFF restarts | managed by the session middleware |

**Per-service references:** `dashboard/docs/config.md` | `dashboard/docs/cli.md`

---

## Shared CA trust bundle

All four services need a CA trust bundle to verify the certificates issued by Vigil. This file is not service-specific — it is the same across the entire deployment.

| File | Conventional path | Referenced by |
|------|------------------|---------------|
| `credo-catrust.pem` | `/etc/credo/credo-catrust.pem` | All services: `tls.clientCaPath`, `mtls.caPath`, `caPath`, `shepherdCaPath` |

The trust bundle contains the intermediate CA certificate (and optionally the root CA certificate). It is generated during the `ceremony/` PKI ceremony and distributed to every host.

---

## Reload behavior summary

| Change | How to apply |
|--------|-------------|
| Shepherd `shepherd.corgis.json` | Automatic — mtime-checked on each poll cycle |
| Shepherd `shepherd.accounts.json` | Automatic — mtime-checked on each authenticated request |
| Shepherd `shepherd.assignments.json` | Automatic — mtime-checked on each Corgi pull |
| Shepherd main config (`shepherd.config.json`) | `SIGHUP` to the Shepherd process |
| Corgi main config (`corgi.config.json`) | `SIGHUP` to the Corgi process |
| Vigil main config (`vigil.config.json`) | `SIGHUP` to the Vigil process |
| Dashboard main config (`dashboard.config.json`) | Restart the Dashboard BFF |
| Any TLS certificate renewal | `SIGHUP` (Shepherd/Corgi/Vigil) or restart (Dashboard) |

---

## Deployment layout example

```
/var/apps/
├── shepherd/
│   ├── shepherd.config.json         # main config
│   ├── shepherd.accounts.json       # RBAC registry
│   ├── shepherd.corgis.json         # fleet inventory
│   ├── shepherd.ca.json             # CA definitions
│   ├── shepherd.assignments.json    # cert assignments
│   ├── shepherd.issuance-log.json   # rate-limit ledger (auto-created)
│   ├── shepherd.jwt.key.pem         # JWT signing key (auto-created)
│   └── store/                       # cert store (archive/ + live/)
│
├── corgi/                           # per node; replicated on each managed host
│   ├── corgi.config.json
│   ├── corgi.fleet-accounts.json
│   ├── corgi.assignments.cache.json # auto-updated by sync loop
│   └── store/                       # cert store (archive/ + live/)
│
├── vigil/
│   ├── vigil.config.json
│   ├── ca/
│   │   └── int-ecdsa/
│   │       ├── private/int-ecdsa.key.pem   # mode 0400
│   │       └── certs/int-ecdsa.cert.pem
│   ├── data/
│   │   ├── users.json
│   │   ├── certificates.json
│   │   └── acme-accounts.json
│   └── logs/ct.log
│
└── dashboard/
    ├── dashboard.config.json
    ├── dashboard.users.json
    └── sessions/

/etc/credo/
└── credo-catrust.pem                # shared trust bundle, all hosts
```
