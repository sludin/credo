# Credo Bootstrap Guide

This guide walks through bringing up a fresh Credo deployment from zero — no existing certs, no running services. By the end, vigil, shepherd, and at least one corgi will be running in normal mode with production-lifetime certificates managed by Corgi, and automatic cert rotation will be operational.

## Overview

Bootstrap runs in six phases:

1. **PKI Ceremony** — generate root CA + intermediate CA offline; distribute the CA trust bundle
2. **Start Vigil** — vigil self-issues a 1-day TLS cert and prints an ephemeral secret
3. **Start Shepherd** — shepherd fetches a 1-day cert from vigil using the secret; starts serving
4. **Enroll Admin Account** — issue a personal admin cert and register it in shepherd's RBAC accounts file
5. **Enroll a Corgi** — shepherd's CLI enrolls a corgi node on the vigil machine (and shepherd if different); corgis start in normal mode
6. **Automatic Rotation** — corgis issue production-lifetime certs for all services; services restart; bootstrap window closes

Each bootstrap cert is valid for one day. All bootstrap secrets and certs are held in memory only — nothing ephemeral is written to disk, and nothing needs to be cleaned up.

---

## Topology

Every machine (vigil host, shepherd host, each managed node) runs a local corgi instance. Corgi manages that machine's runtime certs, including the cert the local service uses for TLS.  Note that Shepherd can certain run on the same machine as Vigil, but does not need to.

```
Machine A (vigil host)
  ├── vigil      ← ACME-compatible private CA
  └── corgi-01   ← manages vigil's TLS cert + its own node identity cert

Machine B (shepherd host)
  ├── shepherd   ← control plane
  └── corgi-02   ← manages shepherd's TLS cert + its own node identity cert

Machine C (managed node)
  └── corgi-03   ← manages application service certs + its own node identity cert
```

---

## Phase 1 — PKI Ceremony

Run on an air-gapped machine or secure terminal. This creates the root CA and intermediate CA that sign all service certs.

```bash
cd ceremony
# Edit ca-vars.env.example → ca-vars.env (git-ignored)
./generate-openssl-cnf.sh --env-file ca-vars.env   # generate OpenSSL configs for intermediates
./bootstrap-roots.sh          # generate root CA key + self-signed cert
./issue-intermediary.sh       # generate ECDSA intermediate (for ECDSA certs)
```

After the ceremony, build the trust bundle that every machine needs:

```bash
cat ca/root-ecdsa/certs/root-ecdsa.cert.pem \
    ca/int-ecdsa/certs/int-ecdsa.cert.pem \
    > ca/credo-catrust.pem
```

Distribute `credo-catrust.pem` to every machine. This file is not a secret — it is the CA certificate chain that lets any node verify certs signed by your private CA.

> **The root CA key never leaves this ceremony environment.** Copy only the certificate files to vigil's machine, not the key.  Once the intermediate cert is created, the root key should be archived in a secure location.

---

## Phase 2 — Configure and Start Vigil in Bootstrap Mode

### 2.1 — Configure vigil

On vigil's machine, edit `vigil.config.json`:

```json
{
  "vars": {
    "credoRoot":  "/var/apps/credo",
    "ca":         "${credoRoot}/ca/credo-catrust.pem",
    "corgiLive":  "${credoRoot}/corgi/store/live"
  },

  "commonName": "vigil.example.com",

  "tls": {
    "keyPath":      "${corgiLive}/vigil.example.com/privkey.pem",
    "certPath":     "${corgiLive}/vigil.example.com/fullchain.pem",
    "clientCaPath": "${ca}"
  },

  "rbacIdentities": [
    {
      "uri":  "vigil://credo/dev/service/shepherd",
      "role": "admin",
      "name": "shepherd"
    }
  ],

  "issuancePolicy": {
    "allowedDnsSuffixes":         ["example.com"],
    "allowSubdomains":            true,
    "allowedIdentityUriPrefixes": ["vigil://credo/dev/"]
  }
}
```

Key points:

- The `vars` block defines named path aliases. Each var can reference env vars and any var defined above it (top-down cascade). `${credoRoot}` becomes `/var/apps/credo` everywhere below.
- `commonName` is vigil's own hostname. In bootstrap mode, vigil self-issues a TLS cert with this as the CN and DNS SAN.
- `tls.keyPath` / `tls.certPath` are the paths corgi-A will later write vigil's **production** cert to. Vigil reads them on normal startup. They must match the install paths in corgi-A's assignment.
- `rbacIdentities` must include shepherd's URI SAN **before** vigil starts. Shepherd authenticates to all vigil endpoints (including ACME) by this URI.
- `issuancePolicy` controls what CSRs the bootstrap endpoint (and ACME) will sign. It must cover shepherd's hostname and the `vigil://credo/dev/` URI prefix.

### 2.2 — Copy intermediate CA material to vigil's machine

Vigil's CA backend needs the intermediate key and cert to sign certificates:

```bash
# On vigil's machine — paths match caEcdsa* fields in vigil.config.json (relative to baseDir)
scp ceremony:/path/to/ceremony/ca/int-ecdsa/certs/int-ecdsa.cert.pem  vigil:/var/apps/credo/ca/int-ecdsa/certs/
scp ceremony:/path/to/ceremony/ca/int-ecdsa/private/int-ecdsa.key.pem vigil:/var/apps/credo/ca/int-ecdsa/private/
```

### 2.3 — Start vigil in bootstrap mode

```bash
./vigil bootstrap
```

Vigil prints:

```
Vigil bootstrap secret: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

**Copy this secret immediately.** It is ephemeral — once shepherd successfully enrolls, vigil discards the secret and removes the `/bootstrap` endpoint. If you lose the secret before shepherd enrolls, restart vigil with `bootstrap` to get a new one.

What vigil did:

- Generated an ephemeral ECDSA key pair in memory
- Self-issued a 1-day TLS cert signed by the intermediate CA (CN = `commonName`)
- Started the HTTPS server using this in-memory cert
- Registered the one-time `POST /bootstrap` endpoint (no mTLS client cert required on this endpoint only)

> **Vigil is now ready for shepherd to enroll.** Vigil's server cert is verified by clients using `vigil-catrust.pem`.

---

## Phase 3 — Configure and Start Shepherd in Bootstrap Mode

### 3.1 — Configure shepherd

On shepherd's machine, edit `shepherd.config.json`:

```json
{
  "vars": {
    "credoRoot":  "/var/apps/credo",
    "ca":         "${credoRoot}/ca/credo-catrust.pem",
    "corgiLive":  "${credoRoot}/corgi/store/live"
  },

  "commonName":  "shepherd.example.com",
  "identityUri": "vigil://credo/dev/service/shepherd",
  "vigilUrl":    "https://vigil.example.com:7020",
  "agentPort":     7010,
  "dashboardPort": 7011,
  "bind":          "0.0.0.0",

  "caPath": "${ca}",

  "tls": {
    "certPath":     "${corgiLive}/shepherd.example.com/fullchain.pem",
    "keyPath":      "${corgiLive}/shepherd.example.com/privkey.pem",
    "clientCaPath": "${ca}"
  },

  "corgisConfigPath":      "${credoRoot}/shepherd/shepherd.corgis.json",
  "assignmentsConfigPath": "${credoRoot}/shepherd/shepherd.assignments.json",
  "caConfigPath":          "${credoRoot}/shepherd.ca.json",
  "accountsPath":          "${credoRoot}/shepherd/shepherd.accounts.json",
  "fleetAccountsPath":     "${credoRoot}/shepherd/shepherd.fleet-accounts.json",
  "certStoreDir":          "${credoRoot}/shepherd/store"
}
```
> Bind to localhost/127.0.0.1 if shepherd will never be accessed from off machine

> **Secrets and environment-specific values** can be placed in a `.env` file next to `shepherd.config.json`. Shepherd loads it automatically at startup. Any field in any shepherd config file can reference env vars using `${VAR_NAME}` syntax — for example `"tls": { "certPath": "${SHEPHERD_TLS_CERT}" }`. Put secrets (tokens, passwords, private key paths) in `.env` rather than in the JSON files.

Key points:

- The `vars` block is the same pattern as vigil. `${ca}` and `${corgiLive}` resolve from the vars defined above.
- `identityUri` must exactly match the URI in vigil's `rbacIdentities`. Shepherd presents this URI SAN in its cert; vigil matches it to grant the `admin` role.
- `vigilUrl` is used only in bootstrap mode to call `POST /bootstrap`. In normal mode, vigil's URL comes from the ACME CA config (`cas` section).
- `tls.certPath` / `tls.keyPath` are the paths corgi-B will write shepherd's **production** cert to. They must match corgi-B's assignment install paths.
- `caPath` is a top-level shorthand for the shared CA bundle; it cascades to `tls.clientCaPath` and outbound mTLS CA when neither is set explicitly.
- `caConfigPath` is an absolute path here because `shepherd.ca.json` is a separate file and resolves its own paths relative to its own location.

### 3.2 — Pre-configure shepherd config files

Before starting shepherd, create three config files.

**`shepherd.corgis.json`** — add one entry per corgi. Each entry must have `name`, `url`, and `identityUri`. The `shepherd bootstrap corgi` command does not modify this file; the operator must add entries manually.

```json
{
  "corgis": [
    {
      "name":        "corgi-01",
      "url":         "https://192.0.2.10:7001",
      "identityUri": "vigil://credo/dev/node/corgi-01"
    }
  ]
}
```

**`shepherd.ca.json`** — configure shepherd's CA backends. For a vigil-backed ACME setup:

```json
{
  "vars": {
    "credoRoot":  "/var/apps/credo",
    "ca":         "${credoRoot}/ca/credo-catrust.pem",
    "corgiLive":  "${credoRoot}/corgi/store/live"
  },
  "cas": {
    "vigil": {
      "protocol": "acme",
      "config": {
        "directoryUrl":   "https://vigil.example.com:7020/acme/directory",
        "accountEmail":   "certs@example.com",
        "accountKeyPath": "${credoRoot}/shepherd/acme-account.key",
        "tls": {
          "certPath": "${corgiLive}/shepherd.example.com/fullchain.pem",
          "keyPath":  "${corgiLive}/shepherd.example.com/privkey.pem",
          "caPath":   "${ca}"
        }
      }
    }
  }
}
```

**`shepherd.assignments.json`** — write assignments for every service cert that corgis will manage. This must include vigil's cert, shepherd's own cert, and each corgi's node identity cert. Corgi derives install paths automatically from its own `certStoreDir` config — do not specify `path` or `keyPath` here.

```json
{
  "assignments": [
    {
      "corgi":       "corgi-01",
      "ca":          "vigil",
      "domain":      "vigil.example.com",
      "identityUri": "vigil://credo/dev/service/vigil"
    },
    {
      "corgi":       "corgi-01",
      "ca":          "vigil",
      "domain":      "shepherd.example.com",
      "identityUri": "vigil://credo/dev/service/shepherd"
    },
    {
      "corgi":       "corgi-01",
      "ca":          "vigil",
      "domain":      "corgi-01.example.com",
      "identityUri": "vigil://credo/dev/node/corgi-01"
    }
  ]
}
```

### 3.3 — Start shepherd in bootstrap mode

```bash
./shepherd bootstrap server --vigil-secret a3f2b1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5e6f7a8b9c0d1e2
```

What shepherd does:

1. Generates its own key pair in memory
2. Generates a CSR: CN = `commonName`, URI SAN = `identityUri`
3. Connects to `vigilUrl/bootstrap` over verified TLS (using `vigil-catrust.pem`)
4. Posts the secret and CSR; vigil validates, signs a 1-day cert, removes the `/bootstrap` endpoint
5. Holds the signed cert + key in memory — **nothing written to disk**
6. Starts serving on both ports using the in-memory cert
7. All subsequent calls to vigil (ACME and cert fetch) use this in-memory cert for mTLS

> **The `--vigil-secret` value is never written to disk or logged.**

If shepherd crashes before corgi-B issues it a production cert, restart vigil with `bootstrap` (get a new secret) and restart shepherd with `bootstrap --vigil-secret <new-secret>`.

---

## Phase 4 — Enroll Admin Account

Shepherd starts in bootstrap mode with an ephemeral admin token (printed at startup). Use it now to issue a personal admin cert and register your identity in `shepherd.accounts.json`. After this step all future CLI access uses this cert for mTLS — no admin token needed.

### 4.1 — Run `bootstrap admin`

On the machine where you will run the shepherd CLI (typically shepherd's own host):

```bash
shepherd bootstrap admin \
  --identity-uri vigil://credo/dev/admin/alice \
  --out-cert     ~/.vigil/admin.pem \
  --out-key      ~/.vigil/admin.key \
  --admin-token  <token-printed-at-shepherd-startup> \
  --domain       alice.users.vigilcert.com
```

What this does:

1. Generates an ECDSA key pair locally — **the private key never leaves this machine**
2. Builds a CSR with the `vigil://` URI as a Subject Alternative Name
3. Adds an assignment entry to `shepherd.assignments.json` (no corgi — this cert is operator-managed)
4. Issues the cert from vigil via shepherd's API, using the bootstrap admin token
5. Writes the signed cert to `--out-cert` and the key to `--out-key` (mode 0600)
6. Creates an admin account entry in `shepherd.accounts.json` bound to your identity URI

> **`--identity-uri` must match a URI prefix allowed by vigil's `issuancePolicy`.** Using the same URI prefix configured for shepherd (e.g. `vigil://credo/dev/`) is the simplest approach.

> **Cert lifetime** is controlled by `adminCertDays` in `shepherd.config.json` (default: 365 days). There is no command-line override. Admin certs are not managed by corgi — renew them manually before expiry by re-running this command with your existing cert for mTLS authentication instead of `--admin-token`.

### 4.2 — Verify admin access

```bash
curl -s \
  --cert ~/.vigil/admin.pem \
  --key  ~/.vigil/admin.key \
  --cacert /var/apps/credo/ca/credo-catrust.pem \
  https://shepherd.example.com:7011/accounts/me | jq
```

You should see your identity URI and role. Shepherd's logs will show `identity-based` auth — no fingerprint fallback.

After confirming access, shepherd no longer needs the bootstrap admin token for day-to-day API access. Use the cert and key for all subsequent admin CLI calls.

---

## Phase 5 — Enroll Each Corgi

Repeat this section for every corgi node: corgi-A (vigil's machine), corgi-B (shepherd's machine), and all additional managed nodes.

### 5.1 — Configure corgi

On each corgi's machine, write `corgi.config.json`:

```json
{
  "vars": {
    "credoRoot":  "/var/apps/credo",
    "ca":         "${credoRoot}/ca/credo-catrust.pem",
    "corgiLive":  "${credoRoot}/corgi/store/live",
    "myCert":     "${corgiLive}/corgi-01.example.com/fullchain.pem",
    "myKey":      "${corgiLive}/corgi-01.example.com/privkey.pem"
  },

  "nodeId":      "corgi-01",
  "commonName":  "corgi-01.example.com",
  "identityUri": "vigil://credo/dev/node/corgi-01",
  "shepherdUrl": "https://shepherd.example.com:7010",
  "certStoreDir": "${credoRoot}/corgi/store",

  "tls": {
    "certPath": "${myCert}",
    "keyPath":  "${myKey}"
  },

  "mtls": {
    "certPath": "${myCert}",
    "keyPath":  "${myKey}",
    "caPath":   "${ca}"
  },

  "bootstrapPort": 7001,
  "mtlsPort":      7001,

  "auth": {
    "mode": "mtls"
  },

  "shepherdSync": {
    "enabled":              true,
    "intervalSeconds":      60,
    "assignmentsCachePath": "${credoRoot}/corgi/assignments.cache.json"
  }
}
```

### 5.2 — Start corgi in bootstrap mode

On corgi's machine:

```bash
./corgi bootstrap
```

Corgi prints:

```
  Node ID:               corgi-01
  Common name:           corgi-01.example.com
  Bootstrap port:        7001

  Corgi bootstrap fingerprint: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
  Corgi bootstrap token:       d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2
```

**Copy both values.** The token authenticates shepherd's enrollment call. The fingerprint lets shepherd pin to corgi's ephemeral self-signed cert (preventing MITM during enrollment).

### 5.3 — Run `bootstrap corgi` from shepherd's machine

```bash
shepherd bootstrap corgi \
  --name         corgi-01 \
  --corgi-url    https://192.0.2.10:7001 \
  --identity-uri vigil://credo/dev/node/corgi-01 \
  --token        d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2 \
  --fingerprint  a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2 \
  --admin-token  3a4b5c6d7e8f9a0b1c2d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5e6f7a8b9c0d1e2f
```

All flags are required. This command does **not** modify `shepherd.corgis.json` or `shepherd.assignments.json` — those must be pre-populated (see Section 3.2).

What shepherd does:

1. Connects to corgi's bootstrap server, pinning to the fingerprint, authenticating with the token
2. Fetches corgi's CSR (`GET /bootstrap/csr`) — corgi generates its ECDSA key pair + CSR with URI SAN; private key stays on corgi's machine
3. Issues a 1-day cert from Vigil, using shepherd's in-memory cert for mTLS
4. Pushes the CA trust bundle to corgi (`POST /bootstrap/ca`) — corgi writes it to `mtls.caPath`
5. Pushes the signed cert to corgi (`POST /bootstrap/cert`) — corgi validates it matches its key, installs to `certStoreDir/live/<commonName>/`
6. Finalizes (`POST /bootstrap/finalize`) — corgi invalidates the token and exits bootstrap mode

### 5.4 — Restart corgi in normal mode

The process manager (systemd, supervisor, etc.) should be configured to restart corgi automatically. Once corgi exits after `POST /bootstrap/finalize`, the manager restarts it in normal mode:

```bash
./corgi server start   # normal mode — reads production cert from tls.certPath/tls.keyPath
```

Corgi starts, reads its 1-day production cert, connects to shepherd, and begins pulling assignments.

> **Repeat steps 5.1–5.4 for every corgi node before moving on.**

---

## Phase 6 — Automatic Rotation to Production Certs

No operator action required. This phase completes on its own within the first sync cycle after each corgi starts in normal mode.

**How it works:**

Because `shepherd.assignments.json` was pre-configured with assignments for all service certs (vigil, shepherd, each corgi), each corgi immediately picks up its assignments on the first sync and starts issuing production-lifetime certs.

**corgi-A (on vigil's machine):**

1. Pulls assignment: manage `vigil-server` cert for vigil
2. No cert exists yet at vigil's `tls.certPath` (or fingerprint differs from shepherd's record)
3. Requests cert from shepherd → shepherd issues a production cert via vigil ACME
4. Writes cert to vigil's `tls.certPath` / `tls.keyPath` paths
5. Runs service hook: `systemctl restart vigil`
6. Vigil restarts without `bootstrap`, reads production cert — **vigil is now in normal mode** ✓
7. corgi-A then issues its own production identity cert (same flow; self-referential)

**corgi-B (on shepherd's machine):**

1. Pulls assignment: manage `shepherd-server` cert for shepherd
2. Issues production cert via vigil ACME
3. Writes cert to shepherd's `tls.certPath` / `tls.keyPath` paths
4. Runs service hook: `systemctl restart shepherd`
5. Shepherd restarts without `bootstrap`, reads production cert — **shepherd is in normal mode** ✓

All services are now running in normal mode with production-lifetime certs. Cert rotation is permanently automatic — corgi renews each cert before expiry, writes the new cert, and restarts the service via its hook. No operator involvement required.

---

## Confirming a Successful Bootstrap

After all services have rotated to production certs:

**On vigil's machine:**

```bash
# Confirm vigil is running without bootstrap mode
systemctl status vigil
# Confirm production cert is in place and is not a 1-day cert
openssl x509 -in /etc/vigil/certs/fullchain.pem -noout -dates -subject
```

**On shepherd's machine:**

```bash
systemctl status shepherd
openssl x509 -in /etc/shepherd/certs/fullchain.pem -noout -dates -subject
```

**On any corgi node:**

```bash
# Confirm corgi is connected and pulling assignments
curl -sk https://localhost:7001/health | jq
```

**From shepherd's dashboard API (use the admin cert from Phase 4):**

```bash
# List all corgis and their health status
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

### Shepherd crashes before corgi-B issues it a production cert

Restart vigil with `./vigil bootstrap` and shepherd with `./shepherd bootstrap server --vigil-secret <new-secret>`. Vigil generates a new secret; shepherd enrolls again. Corgis that already have production certs are unaffected.

### Corgi crashes before receiving its cert from shepherd

Restart corgi with `./corgi bootstrap` (a new token and fingerprint are generated). Run `shepherd bootstrap corgi` again with the new token and fingerprint values. `shepherd.corgis.json` and `shepherd.assignments.json` do not need to change — the enrollment sequence only issues and installs the cert.

### The 1-day bootstrap cert expired before rotation completed

All services still need to be running for rotation to complete. Restart any service whose bootstrap cert expired using its `bootstrap` command, then re-enroll the dependent services. Corgis that already have unexpired production certs do not need re-enrollment.

---

## Config Field Reference

### Vigil (`vigil.config.json`)

| Field                    | Bootstrap use                                                                                |
| ------------------------ | -------------------------------------------------------------------------------------------- |
| `vars`                   | Named path aliases resolved top-to-bottom; each var can reference env vars and earlier vars  |
| `commonName`             | CN and DNS SAN for vigil's self-issued bootstrap TLS cert                                    |
| `tls.keyPath`            | Production TLS key path (read on normal startup; written by corgi-A)                         |
| `tls.certPath`           | Production TLS cert path (read on normal startup; written by corgi-A)                        |
| `tls.clientCaPath`       | CA bundle used to verify client certs on all endpoints                                       |
| `rbacIdentities[].uri`   | Must include shepherd's `identityUri` before vigil starts                                    |
| `issuancePolicy`         | Enforced by `POST /bootstrap` and by ACME — must cover shepherd's hostname and URI prefix   |

### Shepherd (`shepherd.config.json`)

| Field              | Bootstrap use                                                                          |
| ------------------ | -------------------------------------------------------------------------------------- |
| `vars`             | Named path aliases; each var can reference env vars and earlier vars (top-down cascade)|
| `commonName`       | CN for shepherd's bootstrap CSR sent to vigil                                          |
| `identityUri`      | URI SAN in shepherd's cert; must match vigil's `rbacIdentities` entry                 |
| `vigilUrl`         | Vigil base URL; used in bootstrap mode to call `POST /bootstrap`                      |
| `caPath`           | Top-level CA bundle; cascades to `tls.clientCaPath` and outbound mTLS CA              |
| `tls.certPath`     | Production TLS cert path (read on normal startup; written by corgi-B)                  |
| `tls.keyPath`      | Production TLS key path (read on normal startup; written by corgi-B)                   |
| `tls.clientCaPath` | CA bundle to verify vigil's server cert and validate inbound corgi client certs        |
| `agentPort`        | Port for the corgi-facing agent server (default: 7010)                                 |
| `dashboardPort`    | Port for the dashboard/admin API server (default: 7011)                                |
| `adminCertDays`    | Validity period for admin certs issued via `bootstrap admin` (default: 365)            |

### Corgi (`corgi.config.json`)

| Field            | Bootstrap use                                                                                   |
| ---------------- | ----------------------------------------------------------------------------------------------- |
| `vars`           | Named path aliases; each var can reference env vars and earlier vars (top-down cascade)         |
| `nodeId`         | Node name; used in shepherd's corgi inventory                                                   |
| `commonName`     | Default CN for this corgi's node identity CSR                                                   |
| `identityUri`    | URI SAN embedded in this corgi's node identity CSR; must match shepherd's corgi inventory entry |
| `tls.certPath`   | Production TLS cert path (written by bootstrap enrollment; read on normal startup)              |
| `tls.keyPath`    | Production TLS key path                                                                         |
| `mtls.certPath`  | Client cert used when connecting to Shepherd (outbound mTLS)                                    |
| `mtls.keyPath`   | Client key for outbound mTLS                                                                    |
| `mtls.caPath`    | CA bundle path; shepherd pushes `credo-catrust.pem` here during enrollment                     |
| `certStoreDir`   | Root directory for all cert material managed by corgi                                           |
| `bootstrapPort`  | Port for the temporary bootstrap HTTPS server                                                   |
| `shepherdUrl`    | Shepherd's agent port URL; used to pull assignments in normal mode                              |

---

## Bootstrap CLI Reference

### Vigil

| Command | Description |
|---------|-------------|
| `vigil bootstrap` | Start in bootstrap mode — generates an ephemeral TLS cert using the intermediate CA, prints a one-time secret, and listens for one enrollment request |
| `vigil server start` | Start in normal mode — reads `tls.certPath` / `tls.keyPath` from config |
| `vigil server check-config` | Validate config and CA key material; exit 1 if anything is missing |
| `vigil server status` | Print CA fingerprint, validity, and certificate statistics |
| `vigil ca add-user --id <id> --name <name> --public-key-pem-file <path>` | Register a new mTLS user in the users registry |
| `vigil ca export-crl [--out <path>] [--format json\|pem\|der]` | Export the current CRL |
| `vigil ca ocsp-check [--id <id>] [--serial <hex>]` | Check revocation status of a certificate |

### Shepherd

| Command | Description |
|---------|-------------|
| `shepherd bootstrap server --vigil-secret <secret>` | Start in bootstrap mode — enrolls shepherd with Vigil using the secret, starts both API ports with an in-memory cert, and prints a one-time admin token |
| `shepherd bootstrap admin --admin-token <token> --identity-uri <uri> --out-cert <path> --out-key <path> --domain <domain>` | Issue a personal admin certificate and register it in `shepherd.accounts.json`. The private key is generated locally and never sent over the wire |
| `shepherd bootstrap corgi --admin-token <token> --name <name> --corgi-url <url> --identity-uri <uri> --token <corgi-token> --fingerprint <hex>` | Enroll a Corgi node — fetches its CSR, signs it via Vigil, and installs the cert and CA bundle on the Corgi |
| `shepherd server start` | Start in normal mode — reads `tls.certPath` / `tls.keyPath` from config |
| `shepherd server check-config` | Validate config paths and JWT key; exit 1 if anything is missing |
| `shepherd cert store` | List all entries in the cert store |
| `shepherd cert inspect <certName>` | Show metadata for one cert store entry |

### Corgi

| Command | Description |
|---------|-------------|
| `corgi bootstrap [--out <path>] [--dry-run]` | Start in bootstrap mode — generates an ephemeral self-signed cert, prints a token and fingerprint, and waits for Shepherd to enroll it |
| `corgi server start` | Start in normal mode — reads `tls.certPath` / `tls.keyPath` from config |
| `corgi server check-config` | Validate config, check cert paths, and probe Shepherd connectivity |

---

## Security Properties

- **Secrets are ephemeral.** The vigil bootstrap secret and each corgi's bootstrap token are generated fresh at startup, live in memory only, and are discarded after one successful use.
- **Certs are ephemeral.** Vigil's bootstrap TLS cert, shepherd's bootstrap cert, and each corgi's bootstrap self-signed cert are never written to disk. A crash or restart clears them.
- **Every bootstrap cert expires in 24 hours.** If the rotation window closes before production certs are issued, no service can present a valid cert after that deadline — forcing the operator to re-enroll rather than leaving a stale bootstrap cert in place indefinitely.
- **Vigil enforces issuance policy on the bootstrap endpoint.** A leaked secret cannot be used to sign certs for domains or URI prefixes outside the configured policy.
- **Secret comparison uses constant-time equality.** Timing attacks against the vigil bootstrap secret are not possible.
- **TLS is verified throughout.** Shepherd verifies vigil's bootstrap cert using `vigil-catrust.pem`. Shepherd pins to corgi's ephemeral cert fingerprint during corgi enrollment. There is no `--insecure-skip-verify` path in the bootstrap flow.
