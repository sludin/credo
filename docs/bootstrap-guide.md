# Credo Bootstrap Guide

This guide covers bringing up a fresh Credo deployment from zero — no existing certs, no running services. By the end, vigil, shepherd, and at least one corgi will be running with production-lifetime certificates and automatic cert rotation operational.

Two paths are available:

- **[Path A — Scripted](#path-a--scripted)**: The `scripts/bootstrap` orchestrator walks through decisions, generates all config files, and runs the entire bootstrap sequence automatically. Recommended for new deployments.
- **[Path B — Manual](#path-b--manual)**: A step-by-step walkthrough of each phase. Required when you need precise control over every step or for multi-machine topologies beyond the single-corgi case.

Both paths share the same prerequisite: a completed PKI ceremony (Phase 1).

---

## Operator flow summary

```
git pull && cargo build --release
scripts/install init          # generate .install.json (interactive)
scripts/install setup         # create users/groups + systemd units on remote
scripts/install               # build + rsync binaries to remote
scripts/bootstrap             # ceremony + service configs + bootstrap sequence
systemctl enable --now credo-vigil credo-shepherd credo-corgi
```

---

## Topology

Every machine (vigil host, shepherd host, each managed node) runs a local corgi instance. Corgi manages that machine's runtime certs, including the cert the local service uses for TLS. Shepherd and vigil can share a machine, but do not need to.

```
Machine A (vigil host)
  ├── vigil      ← ACME-compatible private CA
  └── corgi-A    ← manages vigil's TLS cert + its own node identity cert

Machine B (shepherd host)
  ├── shepherd   ← control plane
  └── corgi-B    ← manages shepherd's TLS cert + its own node identity cert

Machine C (managed node)
  └── corgi-C    ← manages application service certs + its own node identity cert
```

`scripts/bootstrap` handles a **single-corgi topology** (all three services on one machine or closely co-located). For multi-machine topologies, use Path B for the later phases.

---

## Path A — Scripted

### Prerequisites

- `jq` installed on your local machine (`brew install jq` or `apt install jq`)
- `.install.json` created (`scripts/install init`)
- Binaries deployed to the remote host (`scripts/install`)
- Users, groups, and systemd units created (`scripts/install setup`)

### Phase 1 — PKI Ceremony

`scripts/bootstrap` runs the ceremony scripts automatically (Phase 1 of the bootstrap wizard). Ceremony runs **locally** on your operator machine — the intermediate CA key and cert are then pushed to the remote vigil host.

For a non-interactive ceremony (unattended / CI):

```bash
export CREDO_ROOT_CA_PASSPHRASE="your-root-ca-passphrase"
scripts/bootstrap --auto
```

For an interactive ceremony (default):

```bash
scripts/bootstrap
```

The ceremony output is written to `scripts/ceremony/ca/` (git-ignored). If you already ran the ceremony, use `--skip-ceremony` to skip Phase 1.

### Running the bootstrap

**Interactive (recommended for first run):**

```bash
scripts/bootstrap
```

The wizard prompts section by section: Base, Vigil, Shepherd, Corgi, then Admin. Press Enter to accept a default; type a new value to override. Answers are saved to `bootstrap.json` after each section so you can resume after an interrupted run.

**Non-interactive (unattended / CI):**

```bash
# Copy and edit bootstrap-default.json → bootstrap.json first
cp bootstrap-default.json bootstrap.json
$EDITOR bootstrap.json          # set domain, hostnames, etc.
CREDO_ROOT_CA_PASSPHRASE=... scripts/bootstrap --auto
```

**Dry run (preview configs only, no services started):**

```bash
scripts/bootstrap --dry-run
```

Generates configs locally and shows what would be pushed. No SSH connections to start services.

**Skip ceremony (CA already in place):**

```bash
scripts/bootstrap --skip-ceremony
```

**Run one phase only:**

```bash
scripts/bootstrap --phase 1    # ceremony only
scripts/bootstrap --phase 2    # config gen + push only
scripts/bootstrap --phase 3    # remote bootstrap sequence only
scripts/bootstrap --phase 4    # health check only
```

### What scripts/bootstrap does

**Phase 0 — Answer collection.** Reads `.install.json` for connection details; prompts for service configuration values (hostnames, ports, identity URIs). Saves answers to `bootstrap.json`.

**Phase 1 — Ceremony.** Runs `scripts/ceremony/generate-openssl-cnf.sh` → `bootstrap-roots.sh` → `issue-intermediary.sh` locally. Outputs to `scripts/ceremony/ca/` (git-ignored). The root CA key stays on your local machine and is never pushed.

**Phase 2 — Config generation and file push.** Generates all service config JSON files (vigil, shepherd, corgi) and pushes them to the remote host along with the intermediate CA chain. The intermediate CA private key is pushed to the vigil directory only, owned by the `vigil` user.

Config files written:
- `<credoRoot>/vars.json` — shared path variable definitions
- `<vigil.dir>/vigil.config.json`
- `<shepherd.dir>/shepherd.config.json`
- `<shepherd.dir>/shepherd.ca.json`
- `<shepherd.dir>/shepherd.corgis.json`
- `<shepherd.dir>/shepherd.assignments.json`
- `<corgi.dir>/corgi.config.json`

**Phase 3 — Remote bootstrap sequence.** Generates a self-contained bootstrap script, uploads it to the remote, and executes it via SSH. The remote script:

1. Starts vigil in bootstrap mode; captures the bootstrap secret
2. Starts shepherd in bootstrap mode with the secret; captures the admin token
3. Starts corgi in bootstrap mode; captures the bootstrap token and fingerprint
4. Registers the admin account
5. Enrolls corgi with shepherd
6. Restarts corgi in server mode; waits for production certs to be issued for all three services
7. Starts vigil and shepherd in server mode; stops all services on exit

**Phase 4 — Health verification.** Hits health endpoints on vigil and shepherd via curl, verifying TLS with the local root CA cert.

### The bootstrap.json file

`bootstrap.json` holds operator-specific answers for `scripts/bootstrap`. It is git-ignored. `bootstrap-default.json` (committed) provides sensible defaults for single-host deployments on `example.com` — copy and edit it for your domain.

Key fields:

| Field | Default | Notes |
|-------|---------|-------|
| `credoRoot` | `/var/apps/credo` | Remote base directory. All other paths default under here. |
| `caTrustPath` | `<credoRoot>/ca/root-ecdsa.cert.pem` | Remote path to root CA trust anchor. |
| `domain` | `example.com` | Base domain. Used to construct default hostnames. |
| `vigil.hostname` | `vigil.<domain>` | Vigil's FQDN — TLS CN and DNS SAN. |
| `vigil.port` | `7020` | Vigil's HTTPS port. |
| `vigil.intCaKeyPath` | `<credoRoot>/ca/int-ecdsa/private/int-ecdsa.key.pem` | Remote path to the intermediate CA private key. |
| `vigil.intCaCertPath` | `<credoRoot>/ca/int-ecdsa/certs/int-ecdsa.chain.pem` | Remote path to the intermediate CA chain. |
| `shepherd.hostname` | `shepherd.<domain>` | Shepherd's FQDN. |
| `shepherd.agentPort` | `7010` | Corgi-facing agent port. |
| `shepherd.dashboardPort` | `7011` | Dashboard / admin API port. |
| `corgi.name` | `corgi-01` | Node name. Used in shepherd's corgi inventory. |
| `corgi.hostname` | `<corgi.name>.<domain>` | Corgi's FQDN. |
| `corgi.port` | `7001` | Corgi's mTLS port (normal mode). |
| `corgi.bootstrapPort` | `7002` | Corgi's bootstrap-mode port. |
| `admin.identityUri` | `vigil://credo/admin` | URI SAN for the admin account. |
| `admin.outCert` | `~/.vigil/admin.pem` | Local path for the admin certificate. |
| `admin.outKey` | `~/.vigil/admin.key` | Local path for the admin private key. |

### After the bootstrap

Production TLS certificates are on disk and all services are stopped. Your next steps:

```bash
# On the remote host:
sudo systemctl enable --now credo-vigil credo-shepherd credo-corgi
```

Then add service restart hooks so cert rotation triggers service restarts automatically:

```json
{
  "serviceHooks": {
    "vigil.example.com":    ["systemctl", "restart", "credo-vigil"],
    "shepherd.example.com": ["systemctl", "restart", "credo-shepherd"]
  }
}
```

> **For additional corgi nodes** beyond the one enrolled by bootstrap, follow Phase 5 from Path B below.

---

## Path B — Manual

This path gives you explicit control over each step. Follow it for multi-machine topologies, additional corgi nodes beyond the first, or when you need to audit every command.

Bootstrap runs in six phases after Phase 1 (PKI Ceremony):

1. **PKI Ceremony** — done below
2. **Start Vigil** — vigil self-issues a 1-day TLS cert and prints an ephemeral secret
3. **Start Shepherd** — shepherd fetches a 1-day cert from vigil using the secret; starts serving
4. **Enroll Admin Account** — issue a personal admin cert and register it in shepherd's RBAC accounts file
5. **Enroll Each Corgi** — shepherd's CLI enrolls each corgi node; corgis transition to normal mode
6. **Automatic Rotation** — corgis issue production-lifetime certs for all services; services restart

Each bootstrap cert is valid for one day. All bootstrap secrets and certs are held in memory only — nothing ephemeral is written to disk.

### Phase 1 — PKI Ceremony

Run on an air-gapped machine or secure terminal before starting either path. The ceremony scripts now live in `scripts/ceremony/`:

```bash
# Edit scripts/ceremony/ca-vars.env.example → scripts/ceremony/ca-vars.env (git-ignored)
scripts/ceremony/generate-openssl-cnf.sh   # generate OpenSSL configs
scripts/ceremony/bootstrap-roots.sh        # generate root CA key + self-signed cert
scripts/ceremony/issue-intermediary.sh     # generate ECDSA intermediate CA
```

After the ceremony, copy the intermediate CA key and cert to vigil's machine:

```bash
scp scripts/ceremony/ca/int-ecdsa/certs/int-ecdsa.cert.pem   vigil:/var/apps/credo/ca/int-ecdsa/certs/
scp scripts/ceremony/ca/int-ecdsa/certs/int-ecdsa.chain.pem  vigil:/var/apps/credo/ca/int-ecdsa/certs/
scp scripts/ceremony/ca/int-ecdsa/private/int-ecdsa.key.pem  vigil:/var/apps/credo/ca/int-ecdsa/private/
scp scripts/ceremony/ca/root-ecdsa/certs/root-ecdsa.cert.pem vigil:/var/apps/credo/ca/
```

> **The root CA key never leaves the ceremony environment.** Copy only the certificate files to vigil's machine, not the root key. Once the intermediate cert is created, archive the root key to offline storage.

Distribute the root CA cert to every machine as the trust anchor:

```bash
# On each host:
sudo mkdir -p /var/apps/credo/ca
sudo cp root-ecdsa.cert.pem /var/apps/credo/ca/root-ecdsa.cert.pem
```

---

### Phase 2 — Configure and Start Vigil

#### 2.1 — Configure vigil

On vigil's machine, write `vigil.config.json`:

```json
{
  "includes": ["/var/apps/credo/vars.json"],
  "port": 7020,
  "bind": "0.0.0.0",
  "commonName": "vigil.example.com",
  "caEcdsaIntermediateKeyPath":  "${credoRoot}/ca/int-ecdsa/private/int-ecdsa.key.pem",
  "caEcdsaIntermediateCertPath": "${credoRoot}/ca/int-ecdsa/certs/int-ecdsa.chain.pem",
  "tls": {
    "keyPath":      "${corgiStore}/vigil.example.com/privkey.pem",
    "certPath":     "${corgiStore}/vigil.example.com/fullchain.pem",
    "clientCaPath": "${caTrustPath}"
  },
  "rbacIdentities": [
    {"uri": "vigil://credo/service/shepherd", "role": "admin", "name": "shepherd"}
  ],
  "issuancePolicy": {
    "allowedDnsSuffixes":         ["example.com"],
    "allowSubdomains":            true,
    "allowBareSuffix":            true,
    "allowedIdentityUriPrefixes": ["vigil://credo/"],
    "allowIpSans":                false
  },
  "allowedHttpChallengePorts": [80, 7080],
  "dataDir":     "${vigilRoot}/data",
  "usersDbPath": "${vigilRoot}/data/users.json",
  "certDbPath":  "${vigilRoot}/data/certificates.json",
  "certsDir":    "${vigilRoot}/data/certs",
  "ctLogPath":   "${vigilRoot}/logs/ct.log",
  "logLevel":    "info"
}
```

And `vars.json` at `/var/apps/credo/vars.json`:

```json
{
  "vars": {
    "credoRoot":    "/var/apps/credo",
    "caTrustPath":  "${credoRoot}/ca/root-ecdsa.cert.pem",
    "vigilRoot":    "${credoRoot}/vigil",
    "shepherdRoot": "${credoRoot}/shepherd",
    "corgiRoot":    "${credoRoot}/corgi",
    "corgiStore":   "${corgiRoot}/store/live"
  }
}
```

#### 2.2 — Start vigil in bootstrap mode

```bash
VIGIL_CONFIG_PATH=/var/apps/credo/vigil/vigil.config.json ./vigil bootstrap
```

Vigil prints:

```
Vigil bootstrap secret: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

**Copy this secret immediately.** It is ephemeral — once shepherd successfully enrolls, vigil discards the secret.

---

### Phase 3 — Configure and Start Shepherd

#### 3.1 — Configure shepherd

Write `shepherd.config.json`:

```json
{
  "includes": ["/var/apps/credo/vars.json"],
  "commonName":    "shepherd.example.com",
  "identityUri":   "vigil://credo/service/shepherd",
  "vigilUrl":      "https://vigil.example.com:7020",
  "agentPort":     7010,
  "dashboardPort": 7011,
  "bind":          "0.0.0.0",
  "shepherdCaPath": "${caTrustPath}",
  "tls": {
    "certPath":     "${corgiStore}/shepherd.example.com/fullchain.pem",
    "keyPath":      "${corgiStore}/shepherd.example.com/privkey.pem",
    "clientCaPath": "${caTrustPath}"
  },
  "corgisConfigPath":      "${shepherdRoot}/shepherd.corgis.json",
  "caConfigPath":          "${shepherdRoot}/shepherd.ca.json",
  "assignmentsConfigPath": "${shepherdRoot}/shepherd.assignments.json",
  "certStoreDir":          "${shepherdRoot}/store",
  "accountsPath":          "${shepherdRoot}/shepherd.accounts.json",
  "renewalJobsDir":        "${shepherdRoot}/renewal-jobs",
  "logLevel": "info",
  "auth": {
    "jwtSigningKeyPath": "${shepherdRoot}/shepherd.jwt.key.pem"
  }
}
```

Write `shepherd.ca.json`, `shepherd.corgis.json`, and `shepherd.assignments.json` — see the Path A field reference for examples; `scripts/bootstrap --dry-run` will also generate these for review.

#### 3.2 — Start shepherd in bootstrap mode

```bash
SHEPHERD_CONFIG_PATH=/var/apps/credo/shepherd/shepherd.config.json \
  ./shepherd bootstrap server --vigil-secret <secret-from-vigil>
```

Shepherd prints a one-time admin token — copy it for Phase 4.

---

### Phase 4 — Enroll Admin Account

```bash
SHEPHERD_CONFIG_PATH=/var/apps/credo/shepherd/shepherd.config.json \
  ./shepherd bootstrap admin \
  --identity-uri vigil://credo/admin \
  --out-cert     ~/.vigil/admin.pem \
  --out-key      ~/.vigil/admin.key \
  --admin-token  <token-printed-at-shepherd-startup> \
  --domain       example.com
```

Verify admin access:

```bash
curl -s \
  --cert ~/.vigil/admin.pem \
  --key  ~/.vigil/admin.key \
  --cacert /var/apps/credo/ca/root-ecdsa.cert.pem \
  https://shepherd.example.com:7011/accounts/me | jq
```

---

### Phase 5 — Enroll Each Corgi

#### 5.1 — Configure corgi

Write `corgi.config.json`:

```json
{
  "includes": ["/var/apps/credo/vars.json"],
  "nodeId":      "corgi-01",
  "commonName":  "corgi.example.com",
  "identityUri": "vigil://credo/node/corgi-01",
  "shepherdUrl": "https://shepherd.example.com:7010",
  "certStoreDir": "${corgiRoot}/store",
  "tls": {
    "certPath": "${corgiStore}/corgi.example.com/fullchain.pem",
    "keyPath":  "${corgiStore}/corgi.example.com/privkey.pem"
  },
  "mtls": {
    "certPath": "${corgiStore}/corgi.example.com/fullchain.pem",
    "keyPath":  "${corgiStore}/corgi.example.com/privkey.pem",
    "caPath":   "${caTrustPath}"
  },
  "flock": [],
  "httpChallenge": {"enabled": true, "port": 7080, "bind": "0.0.0.0"},
  "mtlsPort":      7001,
  "bootstrapPort": 7002,
  "bind":          "0.0.0.0",
  "logLevel": "info",
  "auth": {"mode": "mtls", "identityOnly": false},
  "rbacIdentities": [
    {"uri": "vigil://credo/service/shepherd", "role": "admin", "name": "shepherd"}
  ],
  "shepherdSync": {
    "enabled":              true,
    "intervalSeconds":      60,
    "staleWarningSeconds":  300,
    "assignmentsCachePath": "${corgiRoot}/corgi.assignments.cache.json"
  },
  "monitorIntervalSeconds": 30,
  "serviceHooks": {},
  "defaultHooks": []
}
```

#### 5.2 — Start corgi in bootstrap mode

```bash
CORGI_CONFIG_PATH=/var/apps/credo/corgi/corgi.config.json ./corgi bootstrap
```

Corgi prints a token and fingerprint — copy both.

#### 5.3 — Enroll corgi from shepherd's machine

```bash
SHEPHERD_CONFIG_PATH=/var/apps/credo/shepherd/shepherd.config.json \
  ./shepherd bootstrap corgi \
  --name         corgi-01 \
  --corgi-url    https://corgi.example.com:7002 \
  --identity-uri vigil://credo/node/corgi-01 \
  --token        <corgi-bootstrap-token> \
  --fingerprint  <corgi-fingerprint> \
  --admin-token  <shepherd-admin-token>
```

#### 5.4 — Restart corgi in normal mode

```bash
CORGI_CONFIG_PATH=/var/apps/credo/corgi/corgi.config.json ./corgi server start
```

> Repeat steps 5.1–5.4 for every corgi node before continuing.

---

### Phase 6 — Automatic Rotation to Production Certs

No operator action required after Phase 5. Each corgi pulls its assignments on the first sync and issues production-lifetime certs.

Add service restart hooks to each corgi's `serviceHooks` config so restarts happen automatically:

```json
{
  "serviceHooks": {
    "vigil.example.com":    ["systemctl", "restart", "credo-vigil"],
    "shepherd.example.com": ["systemctl", "restart", "credo-shepherd"]
  }
}
```

---

## Confirming a Successful Bootstrap

```bash
# Check service status
systemctl status credo-vigil credo-shepherd credo-corgi

# Confirm production cert dates
openssl x509 -in /var/apps/credo/corgi/store/live/vigil.example.com/fullchain.pem \
  -noout -dates -subject

# Health checks
curl -s --cacert /var/apps/credo/ca/root-ecdsa.cert.pem \
  https://vigil.example.com:7020/health

curl -s --cacert /var/apps/credo/ca/root-ecdsa.cert.pem \
  https://shepherd.example.com:7011/health

# Verify admin access
curl -s \
  --cert ~/.vigil/admin.pem \
  --key  ~/.vigil/admin.key \
  --cacert /var/apps/credo/ca/root-ecdsa.cert.pem \
  https://shepherd.example.com:7011/flock | jq
```

---

## Recovery

### Vigil crashes before shepherd enrolls

Restart vigil with `./vigil bootstrap` — a new ephemeral cert and secret are generated. Pass the new secret to shepherd with `--vigil-secret`.

### Shepherd crashes before its production cert is issued

Restart vigil and shepherd in bootstrap mode. Corgis that already have production certs are unaffected.

### Corgi crashes before receiving its cert from shepherd

Restart corgi with `./corgi bootstrap` (a new token and fingerprint are generated). Run `shepherd bootstrap corgi` again with the new values. `shepherd.corgis.json` and `shepherd.assignments.json` do not need to change.

### The 1-day bootstrap cert expired

All services still need to be running for rotation to complete. Restart any service whose bootstrap cert expired using its `bootstrap` command, then re-enroll the dependent services. Corgis that already have unexpired production certs do not need re-enrollment.

---

## Bootstrap CLI Reference

### scripts/bootstrap

| Command | Description |
|---------|-------------|
| `scripts/bootstrap` | Fully interactive — prompts for all values, runs ceremony, pushes configs, runs bootstrap sequence |
| `scripts/bootstrap --auto` | Non-interactive — reads all values from `bootstrap.json` |
| `scripts/bootstrap --dry-run` | Generate configs only, preview file push, do not start services |
| `scripts/bootstrap --skip-ceremony` | Skip Phase 1 (CA already in place locally) |
| `scripts/bootstrap --phase N` | Run only phase N (0–4) |
| `scripts/bootstrap --auto --phase 4` | Health check only |

### Vigil

| Command | Description |
|---------|-------------|
| `vigil bootstrap` | Start in bootstrap mode |
| `vigil server start` | Start in normal mode |

### Shepherd

| Command | Description |
|---------|-------------|
| `shepherd bootstrap server --vigil-secret <secret>` | Start in bootstrap mode |
| `shepherd bootstrap admin --admin-token <token> ...` | Issue and register admin cert |
| `shepherd bootstrap corgi --admin-token <token> ...` | Enroll a corgi node |
| `shepherd server start` | Start in normal mode |

### Corgi

| Command | Description |
|---------|-------------|
| `corgi bootstrap` | Start in bootstrap mode |
| `corgi server start` | Start in normal mode |

---

## Security Properties

- **Secrets are ephemeral.** Bootstrap secrets live in memory only and are discarded after one successful use.
- **Certs are ephemeral.** Bootstrap TLS certs are never written to disk. A crash or restart clears them.
- **Every bootstrap cert expires in 24 hours.** If the rotation window closes before production certs are issued, no service can present a valid cert — forcing re-enrollment rather than leaving a stale bootstrap cert in place.
- **Vigil enforces issuance policy on the bootstrap endpoint.** A leaked secret cannot be used to sign certs for domains or URI prefixes outside the configured policy.
- **Secret comparison uses constant-time equality.** Timing attacks against the vigil bootstrap secret are not possible.
- **TLS is verified throughout.** Shepherd verifies vigil's bootstrap cert using the root CA trust anchor. Shepherd pins to corgi's ephemeral cert fingerprint during corgi enrollment.
- **Admin private keys never leave the operator's machine.** `shepherd bootstrap admin` generates the key pair locally and submits only the CSR.
- **Root CA key stays offline.** `scripts/bootstrap` runs the ceremony locally and pushes only the intermediate CA — never the root key — to the remote host.
