# Credo Bootstrap Guide

This guide covers bringing up a fresh Credo deployment from zero — no existing certs, no running services. By the end, vigil, shepherd, and at least one corgi will be running with production-lifetime certificates and automatic cert rotation operational.

Two paths are available:

- **[Path A — Wizard](#path-a--wizard)**: An interactive shell script that walks through the decisions, generates all config files, and runs the entire bootstrap sequence automatically. Recommended for new deployments.
- **[Path B — Manual](#path-b--manual)**: A step-by-step walkthrough of each phase. Required when the wizard's single-corgi scope doesn't cover your topology, or when you want precise control over every step.

Both paths share the same prerequisite: a completed PKI ceremony (Phase 1 below).

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

The wizard handles a **single-corgi topology** (all three services on one machine or closely co-located). For multi-machine topologies, use Path B.

---

## Phase 1 — PKI Ceremony

This phase is identical for both paths. Run it on an air-gapped machine or secure terminal before starting either path.

```bash
cd ceremony
# Edit ca-vars.env.example → ca-vars.env (git-ignored)
./generate-openssl-cnf.sh --env-file ca-vars.env   # generate OpenSSL configs for intermediates
./bootstrap-roots.sh          # generate root CA key + self-signed cert
./issue-intermediary.sh       # generate ECDSA intermediate (for ECDSA certs)
```

After the ceremony, build the CA trust bundle:

```bash
cat ca/root-ecdsa/certs/root-ecdsa.cert.pem \
    ca/int-ecdsa/certs/int-ecdsa.cert.pem \
    > ca/credo-catrust.pem
```

Distribute `credo-catrust.pem` to every machine. This file is not a secret — it is the CA certificate chain that lets any node verify certs signed by your private CA.

> **The root CA key never leaves this ceremony environment.** Copy only the certificate files to vigil's machine, not the key. Once the intermediate cert is created, the root key should be archived in a secure location.

Copy the intermediate CA key and cert to vigil's machine:

```bash
scp ceremony:/path/to/ceremony/ca/int-ecdsa/certs/int-ecdsa.cert.pem  vigil:/var/apps/credo/ca/int-ecdsa/certs/
scp ceremony:/path/to/ceremony/ca/int-ecdsa/private/int-ecdsa.key.pem vigil:/var/apps/credo/ca/int-ecdsa/private/
```

---

## Path A — Wizard

The wizard (`wizard/bootstrap-wizard`) is a bash script that:

1. Collects your deployment settings interactively (or reads them from a `defaults.json` file)
2. Generates all config files for vigil, shepherd, and corgi
3. Orchestrates the full bootstrap sequence — starting each service, capturing secrets, running enrollment, and waiting for production certs to be issued
4. Stops all services and hands off to your process manager

### Prerequisites

- `jq` must be installed (`brew install jq` or `apt install jq`)
- The vigil, shepherd, and corgi binaries must already be deployed to the directories you specify (the wizard does not build or copy binaries)
- The intermediate CA key and cert must be in place (from Phase 1 above)
- `credo-catrust.pem` must be in place

### The defaults.json file

The wizard accepts a `--defaults` flag pointing to a JSON file of pre-filled answers. Using a defaults file lets you:

- Skip re-typing values on subsequent runs (the wizard saves answers back to the file after each section)
- Run in fully non-interactive `--auto` mode for CI or scripted environments
- Do a `--dry-run` to preview generated configs before committing to a live run

An annotated defaults file (see `wizard/examples/defaults.json` for a starting point):

```json
{
  "credoRoot":   "/var/apps/credo",
  "caTrustPath": "/var/apps/credo/credo-catrust.pem",
  "domain":      "example.com",

  "vigil": {
    "hostname":      "vigil.example.com",
    "port":          7020,
    "intCaKeyPath":  "/var/apps/credo/ca/int-ecdsa/private/int-ecdsa.key.pem",
    "intCaCertPath": "/var/apps/credo/ca/int-ecdsa/certs/int-ecdsa.cert.pem",
    "dir":           "/var/apps/credo/vigil",
    "identityUri":   "vigil://credo/service/vigil"
  },

  "shepherd": {
    "hostname":      "shepherd.example.com",
    "agentPort":     7010,
    "dashboardPort": 7011,
    "dir":           "/var/apps/credo/shepherd",
    "identityUri":   "vigil://credo/service/shepherd"
  },

  "corgi": {
    "name":               "corgi-A",
    "hostname":           "corgi.example.com",
    "port":               7001,
    "bootstrapPort":      7002,
    "httpChallengePort":  7080,
    "dir":                "/var/apps/credo/corgi",
    "identityUri":        "vigil://credo/node/corgi-A"
  },

  "admin": {
    "identityUri": "vigil://credo/admin/alice",
    "outCert":     "~/.vigil/admin.pem",
    "outKey":      "~/.vigil/admin.key"
  }
}
```

#### Field reference

| Field | Default | Notes |
|-------|---------|-------|
| `credoRoot` | — | Root directory for all credo data. Every other path defaults under here. |
| `caTrustPath` | — | Path to `credo-catrust.pem`. Must exist before the wizard runs. |
| `domain` | — | Base domain (e.g. `example.com`). Used to construct default hostnames. |
| `vigil.hostname` | `vigil.<domain>` | Vigil's FQDN. Used as the TLS CN and DNS SAN. |
| `vigil.port` | `7020` | Vigil's HTTPS port. |
| `vigil.intCaKeyPath` | `<credoRoot>/ca/int-ecdsa/private/int-ecdsa.key.pem` | Intermediate CA private key. Must be in place before vigil starts. |
| `vigil.intCaCertPath` | `<credoRoot>/ca/int-ecdsa/certs/int-ecdsa.cert.pem` | Intermediate CA certificate. |
| `vigil.dir` | `<credoRoot>/vigil` | Vigil's working directory. The binary must be here as `vigil`. |
| `vigil.identityUri` | `vigil://credo/service/vigil` | Vigil's own identity URI SAN. Used internally; change only if you have a custom URI scheme. |
| `shepherd.hostname` | `shepherd.<domain>` | Shepherd's FQDN. |
| `shepherd.agentPort` | `7010` | Port for the corgi-facing agent server. |
| `shepherd.dashboardPort` | `7011` | Port for the dashboard/admin API. |
| `shepherd.dir` | `<credoRoot>/shepherd` | Shepherd's working directory. The binary must be here as `shepherd`. |
| `shepherd.identityUri` | `vigil://credo/service/shepherd` | Shepherd's identity URI SAN. Must match the entry in vigil's `rbacIdentities`. |
| `corgi.name` | — | Node name (e.g. `corgi-A`). Used in shepherd's corgi inventory. **No default — must be set.** |
| `corgi.hostname` | `<corgi.name>.<domain>` | Corgi's FQDN. |
| `corgi.port` | `7001` | Corgi's mTLS port (used in normal mode). |
| `corgi.bootstrapPort` | `<corgi.port> + 1` | Corgi's bootstrap-mode port. Must be reachable from where you run shepherd's enrollment command. |
| `corgi.httpChallengePort` | `7080` | Port corgi listens on for HTTP-01 ACME challenges. Must be reachable as port 80 if using DNS-based challenge routing, or mapped via a load balancer rule. |
| `corgi.dir` | `<credoRoot>/corgi` | Corgi's working directory. The binary must be here as `corgi`. |
| `corgi.identityUri` | `vigil://credo/node/<corgi.name>` | Corgi's node identity URI SAN. |
| `admin.identityUri` | `vigil://credo/admin/admin` | The URI SAN for the admin account being created. Choose something that identifies the operator. |
| `admin.outCert` | `~/.vigil/admin.pem` | Where to write the admin certificate. |
| `admin.outKey` | `~/.vigil/admin.key` | Where to write the admin private key (mode 0600). |
| `dnsOverride` | `null` | Optional DNS override map for the wizard's internal hostname resolution. Not prompted interactively; set in the file only if your test environment needs it. |

#### Identity URI conventions

Identity URIs (`vigil://…`) are the mTLS identity tokens that tie services and accounts together across the system. The wizard uses a flat prefix by default (`vigil://credo/`), but you can use any URI scheme as long as:

- `vigil.identityUri` appears in vigil's `rbacIdentities` under the ACME-admin role
- `shepherd.identityUri` appears in vigil's `rbacIdentities` under the admin role
- Vigil's `issuancePolicy.allowedIdentityUriPrefixes` covers all URIs you intend to issue

### Running the wizard

**Interactive (recommended for first run):**

```bash
cd wizard
./bootstrap-wizard
```

The wizard prompts section by section: Base, Vigil, Shepherd, Corgi, then (mid-run after all services are started) Admin. Press Enter to accept a default; type a new value to override. Answers are saved to `./defaults.json` after each section so you can resume after an interrupted run.

**Interactive with a pre-filled defaults file:**

```bash
./bootstrap-wizard --defaults /path/to/defaults.json
```

Prompts appear with your values pre-filled as defaults. Press Enter to accept, or type to override.

**Non-interactive (auto mode):**

```bash
./bootstrap-wizard --defaults /path/to/defaults.json --auto
```

No prompts. All values come from the defaults file. The wizard fails immediately if any required field is missing.

**Dry run (preview configs only, no services started):**

```bash
./bootstrap-wizard --defaults /path/to/defaults.json --dry-run
```

Prints all config files that would be written. Use this to review before committing to a live run.

**Preserve runtime data from a previous run:**

```bash
./bootstrap-wizard --defaults /path/to/defaults.json --preserve-data
```

By default the wizard purges cert stores, accounts, and renewal state before starting. Use `--preserve-data` to skip the purge (useful when re-running after a partial failure where certs were already issued).

### What the wizard does

After collecting answers the wizard runs these steps automatically:

**Config generation** — Writes all config files:

- `<credoRoot>/vars.json` — shared path variable definitions
- `<vigil.dir>/vigil.config.json`
- `<shepherd.dir>/shepherd.config.json`
- `<shepherd.dir>/shepherd.ca.json`
- `<shepherd.dir>/shepherd.corgis.json`
- `<shepherd.dir>/shepherd.assignments.json`
- `<corgi.dir>/corgi.config.json`

**Step 1 — Start vigil in bootstrap mode.** The wizard starts vigil, waits for it to print its bootstrap secret, and captures it automatically. You do not need to copy the secret manually.

**Step 2 — Start shepherd in bootstrap mode.** The wizard passes the captured vigil secret to shepherd, waits for shepherd to print its one-time admin token, and captures it.

**Step 3 — Start corgi in bootstrap mode.** The wizard captures corgi's bootstrap token and fingerprint from its startup output.

**Admin account prompts (interactive mode only)** — At this point the wizard pauses to collect admin account details (`admin.identityUri`, `admin.outCert`, `admin.outKey`). In `--auto` mode these come from the defaults file.

**Step 4 — Register the admin account.** The wizard runs `shepherd bootstrap admin` using the captured admin token, writing your admin cert and key to disk.

**Corgi enrollment.** The wizard runs `shepherd bootstrap corgi` using the captured corgi token and fingerprint.

**Step 5 — Restart corgi in server mode.** Corgi exits bootstrap mode and restarts in normal mode. It immediately pulls its assignments from shepherd and starts issuing production-lifetime certs for all three services (vigil, shepherd, corgi). The wizard tails all service logs and waits up to 5 minutes for all cert files to appear.

**Smoke-check.** Once the certs are on disk, the wizard kills the bootstrap vigil and shepherd processes and starts them in normal server mode using the new production certs. This confirms the certs load correctly.

**Shutdown.** The wizard stops all services via its exit trap and exits. Services do not stay running after the wizard exits.

### After the wizard

The wizard leaves production TLS certificates on disk and all services stopped. Your next steps:

1. Configure your process manager (systemd, launchd, supervisor) to start and restart vigil, shepherd, and corgi.
2. Add service restart hooks to corgi's `serviceHooks` config so cert rotation triggers service restarts automatically:

```json
{
  "serviceHooks": {
    "vigil.example.com":    ["systemctl", "restart", "vigil"],
    "shepherd.example.com": ["systemctl", "restart", "shepherd"]
  }
}
```

3. Verify the deployment using the [confirmation steps](#confirming-a-successful-bootstrap) below.

> **For additional corgi nodes** beyond the one enrolled by the wizard, follow the manual Phase 5 (corgi enrollment) steps from Path B.

---

## Path B — Manual

This path gives you explicit control over each step. Follow it for multi-machine topologies, additional corgi nodes beyond the first, or when you need to audit every command.

Bootstrap runs in six phases after Phase 1 (PKI Ceremony):

1. **PKI Ceremony** — done above
2. **Start Vigil** — vigil self-issues a 1-day TLS cert and prints an ephemeral secret
3. **Start Shepherd** — shepherd fetches a 1-day cert from vigil using the secret; starts serving
4. **Enroll Admin Account** — issue a personal admin cert and register it in shepherd's RBAC accounts file
5. **Enroll Each Corgi** — shepherd's CLI enrolls each corgi node; corgis transition to normal mode
6. **Automatic Rotation** — corgis issue production-lifetime certs for all services; services restart

Each bootstrap cert is valid for one day. All bootstrap secrets and certs are held in memory only — nothing ephemeral is written to disk.

### Phase 2 — Configure and Start Vigil

#### 2.1 — Configure vigil

On vigil's machine, write `vigil.config.json`:

```json
{
  "vars": {
    "credoRoot":  "/var/apps/credo",
    "caTrustPath": "${credoRoot}/ca/credo-catrust.pem",
    "corgiStore":  "${credoRoot}/corgi/store/live"
  },

  "commonName": "vigil.example.com",
  "port": 7020,
  "bind": "0.0.0.0",

  "caEcdsaIntermediateKeyPath":  "${credoRoot}/ca/int-ecdsa/private/int-ecdsa.key.pem",
  "caEcdsaIntermediateCertPath": "${credoRoot}/ca/int-ecdsa/certs/int-ecdsa.cert.pem",

  "tls": {
    "keyPath":      "${corgiStore}/vigil.example.com/privkey.pem",
    "certPath":     "${corgiStore}/vigil.example.com/fullchain.pem",
    "clientCaPath": "${caTrustPath}"
  },

  "rbacIdentities": [
    {
      "uri":  "vigil://credo/service/shepherd",
      "role": "admin",
      "name": "shepherd"
    }
  ],

  "issuancePolicy": {
    "allowedDnsSuffixes":         ["example.com"],
    "allowSubdomains":            true,
    "allowBareSuffix":            true,
    "allowedIdentityUriPrefixes": ["vigil://credo/"],
    "allowIpSans":                false
  },

  "allowedHttpChallengePorts": [80, 7080],

  "dataDir":     "${credoRoot}/vigil/data",
  "usersDbPath": "${credoRoot}/vigil/data/users.json",
  "certDbPath":  "${credoRoot}/vigil/data/certificates.json",
  "certsDir":    "${credoRoot}/vigil/data/certs",
  "ctLogPath":   "${credoRoot}/vigil/logs/ct.log",
  "logLevel":    "info"
}
```

Key points:

- `vars` defines named path aliases resolved top-to-bottom. Each var can reference env vars and any var defined above it.
- `commonName` is vigil's own hostname. In bootstrap mode, vigil self-issues a TLS cert with this as the CN and DNS SAN.
- `tls.keyPath` / `tls.certPath` are where corgi will write vigil's **production** cert. Vigil reads them on normal startup.
- `rbacIdentities` must include shepherd's `identityUri` before vigil starts. Shepherd authenticates to vigil's ACME and admin endpoints by this URI.
- `issuancePolicy` controls what CSRs will be signed. It must cover shepherd's hostname and all URI prefixes you intend to issue.

#### 2.2 — Start vigil in bootstrap mode

```bash
VIGIL_CONFIG_PATH=/var/apps/credo/vigil/vigil.config.json ./vigil bootstrap
```

Vigil prints:

```
Vigil bootstrap secret: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

**Copy this secret immediately.** It is ephemeral — once shepherd successfully enrolls, vigil discards the secret and removes the `/bootstrap` endpoint. If you lose the secret before shepherd enrolls, restart vigil with `bootstrap` to get a new one.

What vigil does:
- Generates an ephemeral ECDSA key pair in memory
- Self-issues a 1-day TLS cert signed by the intermediate CA (CN = `commonName`)
- Starts the HTTPS server using this in-memory cert
- Registers the one-time `POST /bootstrap` endpoint (no mTLS client cert required on this endpoint only)

---

### Phase 3 — Configure and Start Shepherd

#### 3.1 — Configure shepherd

On shepherd's machine, write `shepherd.config.json`:

```json
{
  "vars": {
    "credoRoot":   "/var/apps/credo",
    "caTrustPath": "${credoRoot}/ca/credo-catrust.pem",
    "corgiStore":  "${credoRoot}/corgi/store/live"
  },

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

  "corgisConfigPath":      "${credoRoot}/shepherd/shepherd.corgis.json",
  "caConfigPath":          "${credoRoot}/shepherd/shepherd.ca.json",
  "assignmentsConfigPath": "${credoRoot}/shepherd/shepherd.assignments.json",
  "certStoreDir":          "${credoRoot}/shepherd/store",
  "accountsPath":          "${credoRoot}/shepherd/shepherd.accounts.json",
  "renewalJobsDir":        "${credoRoot}/shepherd/renewal-jobs",
  "logLevel":              "info",

  "auth": {
    "jwtSigningKeyPath": "${credoRoot}/shepherd/shepherd.jwt.key.pem"
  }
}
```

> Bind to `127.0.0.1` if shepherd will not be accessed from off the machine.

> **Secrets and environment-specific values** can be placed in a `.env` file next to `shepherd.config.json`. Shepherd loads it automatically at startup. Any field in any shepherd config file can reference env vars using `${VAR_NAME}` syntax.

Key points:

- `identityUri` must exactly match the URI in vigil's `rbacIdentities`. Shepherd presents this URI SAN in its cert; vigil matches it to grant the admin role.
- `vigilUrl` is used in bootstrap mode to call `POST /bootstrap`. In normal mode, vigil's URL comes from `shepherd.ca.json`.
- `tls.certPath` / `tls.keyPath` are where corgi will write shepherd's **production** cert.
- `shepherdCaPath` is the shared CA bundle used for outbound mTLS calls and client cert validation.

#### 3.2 — Pre-configure shepherd config files

Before starting shepherd, create three additional config files.

**`shepherd.ca.json`** — configures shepherd's CA backend:

```json
{
  "cas": {
    "vigil": {
      "protocol": "acme",
      "provider": "vigil",
      "config": {
        "directoryUrl":         "https://vigil.example.com:7020/acme/directory",
        "renewBeforeDays":      1,
        "days":                 45,
        "accountEmail":         "shepherd@example.com",
        "accountKeyPath":       "/var/apps/credo/shepherd/vigil-account.key.pem",
        "supportedValidations": ["none-01"],
        "defaultValidation":    "none-01",
        "tlsCert": "/var/apps/credo/corgi/store/live/shepherd.example.com/fullchain.pem",
        "tlsKey":  "/var/apps/credo/corgi/store/live/shepherd.example.com/privkey.pem",
        "ca":      "/var/apps/credo/ca/credo-catrust.pem"
      }
    }
  }
}
```

**`shepherd.corgis.json`** — one entry per corgi. The `shepherd bootstrap corgi` command does not modify this file; add entries manually before starting shepherd:

```json
{
  "defaults": {
    "mtls": {
      "certPath": "/var/apps/credo/corgi/store/live/shepherd.example.com/fullchain.pem",
      "keyPath":  "/var/apps/credo/corgi/store/live/shepherd.example.com/privkey.pem",
      "caPath":   "/var/apps/credo/ca/credo-catrust.pem"
    }
  },
  "corgis": [
    {
      "name":              "corgi-A",
      "url":               "https://corgi.example.com:7001",
      "identityUri":       "vigil://credo/node/corgi-A",
      "httpChallengePort": 7080
    }
  ]
}
```

**`shepherd.assignments.json`** — one assignment per service cert that corgis will manage. This must include vigil's cert, shepherd's cert, and each corgi's node identity cert:

```json
{
  "assignments": [
    {
      "certName":    "vigil.example.com",
      "corgi":       "corgi-A",
      "ca":          "vigil",
      "domain":      "vigil.example.com",
      "sans":        ["vigil.example.com"],
      "identityUri": "vigil://credo/service/vigil",
      "validation":  {"type": "http-01"},
      "hooks":       [],
      "endpoints":   []
    },
    {
      "certName":    "shepherd.example.com",
      "corgi":       "corgi-A",
      "ca":          "vigil",
      "domain":      "shepherd.example.com",
      "sans":        ["shepherd.example.com"],
      "identityUri": "vigil://credo/service/shepherd",
      "validation":  {"type": "http-01"},
      "hooks":       [],
      "endpoints":   []
    },
    {
      "certName":    "corgi.example.com",
      "corgi":       "corgi-A",
      "ca":          "vigil",
      "domain":      "corgi.example.com",
      "sans":        ["corgi.example.com"],
      "identityUri": "vigil://credo/node/corgi-A",
      "validation":  {"type": "http-01"},
      "hooks":       [],
      "endpoints":   []
    }
  ]
}
```

#### 3.3 — Start shepherd in bootstrap mode

```bash
SHEPHERD_CONFIG_PATH=/var/apps/credo/shepherd/shepherd.config.json \
  ./shepherd bootstrap server --vigil-secret a3f2b1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5e6f7a8b9c0d1e2
```

What shepherd does:

1. Generates its own key pair in memory
2. Generates a CSR: CN = `commonName`, URI SAN = `identityUri`
3. Connects to `vigilUrl/bootstrap` over verified TLS
4. Posts the secret and CSR; vigil validates, signs a 1-day cert, removes the `/bootstrap` endpoint
5. Holds the signed cert + key in memory — **nothing written to disk**
6. Starts serving on both ports using the in-memory cert
7. Prints a one-time admin token — copy it for Phase 4

> **The `--vigil-secret` value is never written to disk or logged.**

---

### Phase 4 — Enroll Admin Account

Shepherd prints an ephemeral admin token at bootstrap startup. Use it now to issue a personal admin cert and register it in `shepherd.accounts.json`.

```bash
SHEPHERD_CONFIG_PATH=/var/apps/credo/shepherd/shepherd.config.json \
  ./shepherd bootstrap admin \
  --identity-uri vigil://credo/admin/alice \
  --out-cert     ~/.vigil/admin.pem \
  --out-key      ~/.vigil/admin.key \
  --admin-token  <token-printed-at-shepherd-startup> \
  --domain       alice.admin.example.com
```

What this does:

1. Generates an ECDSA key pair locally — **the private key never leaves this machine**
2. Builds a CSR with the `vigil://` URI as a Subject Alternative Name
3. Issues the cert from vigil via shepherd's API, using the bootstrap admin token
4. Writes the signed cert to `--out-cert` and the key to `--out-key` (mode 0600)
5. Creates an admin account entry in `shepherd.accounts.json` bound to your identity URI

> `--identity-uri` must match a URI prefix allowed by vigil's `issuancePolicy`.

Verify admin access:

```bash
curl -s \
  --cert ~/.vigil/admin.pem \
  --key  ~/.vigil/admin.key \
  --cacert /var/apps/credo/ca/credo-catrust.pem \
  https://shepherd.example.com:7011/accounts/me | jq
```

---

### Phase 5 — Enroll Each Corgi

Repeat this section for every corgi node.

#### 5.1 — Configure corgi

On each corgi's machine, write `corgi.config.json`:

```json
{
  "vars": {
    "credoRoot":  "/var/apps/credo",
    "caTrustPath": "${credoRoot}/ca/credo-catrust.pem",
    "corgiStore":  "${credoRoot}/corgi/store/live"
  },

  "nodeId":      "corgi-A",
  "commonName":  "corgi.example.com",
  "identityUri": "vigil://credo/node/corgi-A",
  "shepherdUrl": "https://shepherd.example.com:7010",
  "certStoreDir": "${credoRoot}/corgi/store",

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

  "httpChallenge": {
    "enabled": true,
    "port":    7080,
    "bind":    "0.0.0.0"
  },

  "mtlsPort":      7001,
  "bootstrapPort": 7002,
  "bind":          "0.0.0.0",
  "logLevel":      "info",

  "auth": {
    "mode":         "mtls",
    "identityOnly": false
  },

  "rbacIdentities": [
    {"uri": "vigil://credo/service/shepherd", "role": "admin", "name": "shepherd"}
  ],

  "shepherdSync": {
    "enabled":              true,
    "intervalSeconds":      60,
    "staleWarningSeconds":  300,
    "assignmentsCachePath": "${credoRoot}/corgi/corgi.assignments.cache.json"
  },

  "monitorIntervalSeconds": 30,
  "serviceHooks": {},
  "defaultHooks": []
}
```

#### 5.2 — Start corgi in bootstrap mode

On corgi's machine:

```bash
CORGI_CONFIG_PATH=/var/apps/credo/corgi/corgi.config.json ./corgi bootstrap
```

Corgi prints:

```
  Node ID:               corgi-A
  Common name:           corgi.example.com
  Bootstrap port:        7002

  Corgi bootstrap fingerprint: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
  Corgi bootstrap token:       d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2
```

**Copy both values.** The token authenticates shepherd's enrollment call. The fingerprint lets shepherd pin to corgi's ephemeral self-signed cert.

#### 5.3 — Run `bootstrap corgi` from shepherd's machine

```bash
SHEPHERD_CONFIG_PATH=/var/apps/credo/shepherd/shepherd.config.json \
  ./shepherd bootstrap corgi \
  --name         corgi-A \
  --corgi-url    https://corgi.example.com:7002 \
  --identity-uri vigil://credo/node/corgi-A \
  --token        d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2 \
  --fingerprint  a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2 \
  --admin-token  3a4b5c6d7e8f9a0b1c2d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5e6f7a8b9c0d1e2f
```

What shepherd does:

1. Connects to corgi's bootstrap server, pinning to the fingerprint, authenticating with the token
2. Fetches corgi's CSR — corgi generates its ECDSA key pair + CSR with URI SAN; private key stays on corgi's machine
3. Issues a 1-day cert from vigil, using shepherd's in-memory cert for mTLS
4. Pushes the CA trust bundle to corgi — corgi writes it to `mtls.caPath`
5. Pushes the signed cert to corgi — corgi validates it matches its key, installs to `certStoreDir/live/<commonName>/`
6. Finalizes — corgi invalidates the token and exits bootstrap mode

> This command does **not** modify `shepherd.corgis.json` or `shepherd.assignments.json`. Those must be pre-populated (see Section 3.2).

#### 5.4 — Restart corgi in normal mode

```bash
CORGI_CONFIG_PATH=/var/apps/credo/corgi/corgi.config.json ./corgi server start
```

Corgi reads its 1-day cert, connects to shepherd, and begins pulling assignments.

> **Repeat steps 5.1–5.4 for every corgi node before moving on.**

---

### Phase 6 — Automatic Rotation to Production Certs

No operator action required after Phase 5. Each corgi immediately picks up its assignments on the first sync and issues production-lifetime certs.

**corgi-A (on vigil's machine, or whichever corgi owns the vigil assignment):**

1. Pulls assignment: manage `vigil.example.com` cert
2. No cert exists yet at vigil's `tls.certPath` — requests cert from shepherd → shepherd issues via vigil ACME
3. Writes cert to vigil's `tls.certPath` / `tls.keyPath`
4. Runs service hook: `systemctl restart vigil`
5. Vigil restarts without `bootstrap`, reads production cert — **vigil is now in normal mode** ✓
6. corgi-A then issues its own production identity cert (same flow)

**The corgi managing shepherd's cert:**

1. Issues production cert via vigil ACME
2. Writes cert to shepherd's `tls.certPath` / `tls.keyPath`
3. Runs service hook: `systemctl restart shepherd`
4. Shepherd restarts without `bootstrap` — **shepherd is in normal mode** ✓

Add service restart hooks to each corgi's `serviceHooks` config before this phase so the restarts happen automatically:

```json
{
  "serviceHooks": {
    "vigil.example.com":    ["systemctl", "restart", "vigil"],
    "shepherd.example.com": ["systemctl", "restart", "shepherd"]
  }
}
```

---

## Confirming a Successful Bootstrap

After all services have rotated to production certs:

**On vigil's machine:**

```bash
systemctl status vigil
# Confirm production cert — not a 1-day cert
openssl x509 -in /var/apps/credo/corgi/store/live/vigil.example.com/fullchain.pem \
  -noout -dates -subject
```

**On shepherd's machine:**

```bash
systemctl status shepherd
openssl x509 -in /var/apps/credo/corgi/store/live/shepherd.example.com/fullchain.pem \
  -noout -dates -subject
```

**On any corgi node:**

```bash
curl -sk https://localhost:7001/health | jq
```

**From shepherd's dashboard API:**

```bash
curl -s \
  --cert ~/.vigil/admin.pem \
  --key  ~/.vigil/admin.key \
  --cacert /var/apps/credo/ca/credo-catrust.pem \
  https://shepherd.example.com:7011/flock | jq
```

---

## Recovery

### Vigil crashes before shepherd enrolls

Restart vigil with `./vigil bootstrap` — a new ephemeral cert and secret are generated. Pass the new secret to shepherd with `--vigil-secret`.

### Shepherd crashes before its production cert is issued

Restart vigil with `./vigil bootstrap` and shepherd with `./shepherd bootstrap server --vigil-secret <new-secret>`. Corgis that already have production certs are unaffected.

### Corgi crashes before receiving its cert from shepherd

Restart corgi with `./corgi bootstrap` (a new token and fingerprint are generated). Run `shepherd bootstrap corgi` again with the new token and fingerprint. `shepherd.corgis.json` and `shepherd.assignments.json` do not need to change.

### The 1-day bootstrap cert expired before rotation completed

All services still need to be running for rotation to complete. Restart any service whose bootstrap cert expired using its `bootstrap` command, then re-enroll the dependent services. Corgis that already have unexpired production certs do not need re-enrollment.

---

## Bootstrap CLI Reference

### Vigil

| Command | Description |
|---------|-------------|
| `vigil bootstrap` | Start in bootstrap mode — generates an ephemeral TLS cert, prints a one-time secret, and listens for one enrollment request |
| `vigil server start` | Start in normal mode — reads `tls.certPath` / `tls.keyPath` from config |
| `vigil server check-config` | Validate config and CA key material; exit 1 if anything is missing |

### Shepherd

| Command | Description |
|---------|-------------|
| `shepherd bootstrap server --vigil-secret <secret>` | Start in bootstrap mode — enrolls with vigil, starts both API ports with an in-memory cert, prints a one-time admin token |
| `shepherd bootstrap admin --admin-token <token> --identity-uri <uri> --out-cert <path> --out-key <path> --domain <domain>` | Issue a personal admin certificate and register it in `shepherd.accounts.json` |
| `shepherd bootstrap corgi --admin-token <token> --name <name> --corgi-url <url> --identity-uri <uri> --token <corgi-token> --fingerprint <hex>` | Enroll a corgi node — fetches its CSR, signs it via vigil, and installs the cert and CA bundle on corgi |
| `shepherd server start` | Start in normal mode — reads `tls.certPath` / `tls.keyPath` from config |
| `shepherd server check-config` | Validate config paths and JWT key; exit 1 if anything is missing |
| `shepherd cert store` | List all entries in the cert store |
| `shepherd cert inspect <certName>` | Show metadata for one cert store entry |

### Corgi

| Command | Description |
|---------|-------------|
| `corgi bootstrap` | Start in bootstrap mode — generates an ephemeral self-signed cert, prints a token and fingerprint, and waits for shepherd to enroll it |
| `corgi server start` | Start in normal mode — reads `tls.certPath` / `tls.keyPath` from config |
| `corgi server check-config` | Validate config, check cert paths, and probe shepherd connectivity |

### Wizard

| Command | Description |
|---------|-------------|
| `bootstrap-wizard` | Fully interactive — prompts for all values, generates configs, runs bootstrap sequence |
| `bootstrap-wizard --defaults <file>` | Interactive with pre-filled defaults |
| `bootstrap-wizard --defaults <file> --auto` | Non-interactive — reads all values from file, fails on any missing |
| `bootstrap-wizard --defaults <file> --dry-run` | Generate configs only, do not start services |
| `bootstrap-wizard --defaults <file> --preserve-data` | Skip purging runtime data from a previous run |

---

## Security Properties

- **Secrets are ephemeral.** The vigil bootstrap secret and each corgi's bootstrap token are generated fresh at startup, live in memory only, and are discarded after one successful use.
- **Certs are ephemeral.** Vigil's bootstrap TLS cert, shepherd's bootstrap cert, and each corgi's bootstrap self-signed cert are never written to disk. A crash or restart clears them.
- **Every bootstrap cert expires in 24 hours.** If the rotation window closes before production certs are issued, no service can present a valid cert — forcing re-enrollment rather than leaving a stale bootstrap cert in place.
- **Vigil enforces issuance policy on the bootstrap endpoint.** A leaked secret cannot be used to sign certs for domains or URI prefixes outside the configured policy.
- **Secret comparison uses constant-time equality.** Timing attacks against the vigil bootstrap secret are not possible.
- **TLS is verified throughout.** Shepherd verifies vigil's bootstrap cert using `credo-catrust.pem`. Shepherd pins to corgi's ephemeral cert fingerprint during corgi enrollment. There is no `--insecure-skip-verify` path in the bootstrap flow.
- **Admin private keys never leave the operator's machine.** `shepherd bootstrap admin` generates the key pair locally and submits only the CSR.
