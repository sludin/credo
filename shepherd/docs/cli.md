# Shepherd CLI Reference

```
shepherd <group> <command> [options]
```

Config is loaded from `shepherd.config.json` in the current directory, or from the path in `SHEPHERD_CONFIG_PATH`. All commands that talk to the running server use the `commonName` from config as the TLS hostname, resolved to `127.0.0.1` via an internal `.resolve()` — no external DNS needed.

---

## `shepherd server`

### `shepherd server start`

Start the Shepherd control plane. Loads config, starts both the agent API (Corgi-facing) and the dashboard API (admin-facing), and begins the poll and health-check background loops.

Responds to `SIGHUP` by reloading config and TLS material without dropping active connections.

```bash
shepherd server start
```

### `shepherd server check-config`

Validate config file, check that all referenced TLS and key files exist, and verify the JWT signing key can be loaded (generating it if absent). Exits with code 0 if everything looks good, 1 if any file is missing or a check fails.

```bash
shepherd server check-config
```

Output example:
```
Config: /var/apps/shepherd/shepherd.config.json
  Agent port:     127.0.0.1:7010
  Dashboard port: 127.0.0.1:7011
  Cert store:     /var/apps/shepherd/store
  Renew before:   7 days
  Poll interval:  60s

  [ok] tls.certPath
  [ok] tls.keyPath
  [ok] tls.clientCaPath
  [ok] JWT signing key: /var/apps/shepherd/shepherd.jwt.key.pem

Config looks good.
```

---

## `shepherd bootstrap`

Bootstrap commands are used once during initial deployment. After bootstrap is complete, use the production `server start` / `account` commands instead.

### `shepherd bootstrap server --vigil-secret <SECRET>`

Start Shepherd in bootstrap mode. In this mode Shepherd:

1. Generates its own key and CSR in memory.
2. Calls Vigil's `/bootstrap` endpoint using the provided `vigil-secret` to obtain a signed certificate.
3. Starts both API servers using that in-memory certificate (nothing is written to disk yet).
4. Prints a one-time admin token to stdout.
5. Accepts one call to `POST /bootstrap/admin-cert` (authenticated with the admin token) to issue the first admin certificate.
6. Accepts one call to `POST /bootstrap/corgi` to pre-register the first Corgi node.

The wizard captures the printed admin token automatically. If running manually, copy it before proceeding.

```bash
shepherd bootstrap server --vigil-secret <SECRET>
```

Config must include `commonName`, `identityUri`, `vigilUrl`, and `shepherdCaPath` (or `tls.clientCaPath` as the CA for verifying Vigil).

### `shepherd bootstrap admin`

Issue the first admin certificate. Contacts the running bootstrap server using the one-time admin token. The private key is generated locally and never sent to Shepherd; only the CSR is transmitted.

```bash
shepherd bootstrap admin \
  --admin-token <TOKEN> \
  --identity-uri vigil://credo/prod/admin/alice \
  --domain shepherd.example.com \
  --out-cert /etc/credo/admin/admin.fullchain.pem \
  --out-key  /etc/credo/admin/admin.privkey.pem
```

| Flag | Required | Description |
|------|----------|-------------|
| `--admin-token` | yes | One-time token printed by `bootstrap server` |
| `--identity-uri` | yes | URI SAN to embed in the admin certificate |
| `--domain` | yes | Used as the DNS SAN and to derive the common name (`admin.<domain>`) |
| `--out-cert` | yes | Path to write the issued certificate PEM |
| `--out-key` | yes | Path to write the generated private key PEM |

### `shepherd bootstrap corgi`

Register a Corgi node with Shepherd. Can be called during the bootstrap window (using `--admin-token`) or later in production (using `--admin-cert` + `--admin-key`).

**Bootstrap window:**
```bash
shepherd bootstrap corgi \
  --admin-token <TOKEN> \
  --name corgi-01 \
  --token <CORGI_BOOTSTRAP_TOKEN> \
  --fingerprint <SHA256_HEX> \
  --identity-uri vigil://credo/prod/node/corgi-01
```

**Production (after bootstrap):**
```bash
shepherd bootstrap corgi \
  --admin-cert /etc/credo/admin/admin.fullchain.pem \
  --admin-key  /etc/credo/admin/admin.privkey.pem \
  --name corgi-02 \
  --token <CORGI_BOOTSTRAP_TOKEN> \
  --fingerprint <SHA256_HEX> \
  --identity-uri vigil://credo/prod/node/corgi-02
```

| Flag | Required | Description |
|------|----------|-------------|
| `--admin-token` | bootstrap only | One-time token from `bootstrap server` |
| `--admin-cert` | production only | Path to admin certificate PEM |
| `--admin-key` | production only | Path to admin private key PEM |
| `--name` | yes | Corgi node name (must match entry in `shepherd.corgis.json`) |
| `--token` | yes | Bootstrap token Corgi printed when it started in bootstrap mode |
| `--fingerprint` | yes | SHA-256 fingerprint of Corgi's certificate (printed by Corgi bootstrap) |
| `--identity-uri` | yes | URI SAN from Corgi's certificate |
| `--corgi-url` | no | Corgi API URL. Defaults to looking up `name` in `shepherd.corgis.json` |

The bootstrap token and fingerprint come from Corgi's `bootstrap` command output. The wizard captures them automatically.

---

## `shepherd cert`

Cert commands read the local cert store and interact with the running dashboard API.

### `shepherd cert store`

List all entries in the cert store. Reads directly from `certStoreDir` on disk — Shepherd does not need to be running.

```bash
shepherd cert store
```

### `shepherd cert inspect <CERT_NAME>`

Print JSON metadata for a single cert store entry. Includes fingerprint, expiry, SANs, and the last renewal status.

```bash
shepherd cert inspect api.example.com
```

### `shepherd cert renew <CERT_NAME>`

Trigger an immediate renewal for a certificate, bypassing the `renewBeforeDays` threshold. Calls `POST /admin/renew/:name` on the running dashboard API. Requires admin mTLS credentials.

```bash
shepherd cert renew api.example.com \
  --admin-cert /etc/credo/admin/admin.fullchain.pem \
  --admin-key  /etc/credo/admin/admin.privkey.pem
```

| Argument/Flag | Required | Description |
|---------------|----------|-------------|
| `CERT_NAME` (positional) | yes | Certificate name as listed in `shepherd.assignments.json` |
| `--admin-cert` | yes | Path to admin certificate PEM |
| `--admin-key` | yes | Path to admin private key PEM |

---

## `shepherd account`

`add` and `rotate` require a running Shepherd instance (they call `/admin/identity-cert` to issue a cert via Vigil). `list` and `remove` read and write `shepherd.accounts.json` directly on disk; Shepherd does not need to be running.

### `shepherd account add`

Issue a certificate and register a new account in one step. The private key is generated locally and never sent to Shepherd; only the CSR is transmitted. Fails if an account with the given name already exists.

```bash
shepherd account add \
  --name alice \
  --display-name "Alice Admin" \
  --role admin \
  --admin-cert ~/.vigil/admin.pem \
  --admin-key  ~/.vigil/admin.key
# prompts for --out-cert and --out-key if not supplied
```

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--name` | yes | — | Short machine-readable account name (must be unique) |
| `--display-name` | yes | — | Human-readable label |
| `--role` | no | `admin` | One of `admin`, `operator`, `readonly` |
| `--identity-uri` | no | `vigil://credo/admin/<name>` | URI SAN embedded in the issued certificate |
| `--out-cert` | no | prompted | Path to write the issued certificate PEM |
| `--out-key` | no | prompted | Path to write the generated private key PEM |
| `--admin-cert` | yes | — | Path to an admin certificate PEM (for Shepherd mTLS auth) |
| `--admin-key` | yes | — | Path to the admin private key PEM |

### `shepherd account rotate`

Issue a new certificate for an existing account, preserving its identity URIs. The old private key is replaced on disk; no change is made to `shepherd.accounts.json`.

```bash
shepherd account rotate \
  --name alice \
  --admin-cert ~/.vigil/alice.pem \
  --admin-key  ~/.vigil/alice.key
# prompts for --out-cert and --out-key if not supplied (safe to overwrite in-place)
```

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--name` | yes | — | Account name to rotate the cert for |
| `--out-cert` | no | prompted | Path to write the new certificate PEM |
| `--out-key` | no | prompted | Path to write the new private key PEM |
| `--admin-cert` | yes | — | Path to an admin cert (own cert if still valid, or another admin's) |
| `--admin-key` | yes | — | Path to the admin key |

### `shepherd account list`

Print all accounts with their roles and identity URIs.

```bash
shepherd account list
```

### `shepherd account remove`

Remove an account by name. The change is written to `shepherd.accounts.json` immediately.

```bash
shepherd account remove --name alice
```

---

## Environment variables

| Variable | Description |
|----------|-------------|
| `SHEPHERD_CONFIG_PATH` | Override the default config file path (`shepherd.config.json`) |
| `SHEPHERD_AGENT_PORT` | Override `agentPort` from config |
| `SHEPHERD_DASHBOARD_PORT` | Override `dashboardPort` from config |
