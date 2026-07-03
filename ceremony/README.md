# PKI Ceremony Guide

The ceremony scripts generate the root CA and intermediate CA that the entire credo PKI trust chain depends on. Run this once at initial deployment. Re-running it replaces the entire trust chain — every service certificate must be reissued afterward.

Ceremony runs on your operator machine (or an air-gapped machine for production root CA key generation). The intermediate CA key and certificate are the only artifacts that need to reach the Vigil host. The root CA key never leaves the ceremony environment.

---

## Prerequisites

**Tools required:**

- `openssl` — all four scripts depend on it

**Configuration:**

- Copy `ca-vars.env.example` to `ca-vars.env` (git-ignored) and set values for your deployment before running any script.

Key variables:

| Variable | Default | Notes |
|----------|---------|-------|
| `CA_DIR` | `./ca` | Where all CA artifacts are written |
| `ORG` | `Vigil Cert Authority` | Organization in the DN; must match across root and intermediate |
| `ROOT_ECDSA_CN` | `Vigil Root X1` | Common name for the root CA |
| `INT_ECDSA_CN` | `E1` | Common name for the intermediate CA |
| `ROOT_DAYS` | `3650` | Root cert validity (10 years recommended for production) |
| `INT_DAYS` | `730` | Intermediate cert validity (2 years recommended) |
| `PKI_BASE_URL` | `http://pki.example.com` | Embedded in AIA/CDP extensions — does not need to be served |

**Environment:**

- For the root CA key, adequate entropy is required. On an air-gapped machine, ensure `openssl` has access to `/dev/urandom` or equivalent.
- An offline environment is optional but strongly recommended for root CA key generation in production.

---

## Scripts

All four scripts live in `scripts/`. Run them from the ceremony directory root (the directory containing this file).

### 1. `generate-openssl-cnf.sh`

Writes OpenSSL CA configuration files for the root and intermediate CAs. Does not generate any keys or certificates.

**Inputs:** `--env-file ca-vars.env` (or explicit flags)

**Outputs:**
- `ca/root-ecdsa/openssl.cnf`
- `ca/int-ecdsa/openssl.cnf`

---

### 2. `bootstrap-roots.sh`

Generates the root CA ECDSA private key and self-signed root certificate. Runs interactively by default — the operator must type `GENERATE ROOT CA` to confirm before key material is written.

**Inputs:** `ca/root-ecdsa/openssl.cnf` (from step 1)

**Outputs:**
- `ca/root-ecdsa/private/root-ecdsa.key.pem` — AES-256 encrypted by default; permissions `600`
- `ca/root-ecdsa/certs/root-ecdsa.cert.pem` — self-signed root certificate
- `ca/ca-audit.log` — JSON audit entry appended

**Default key parameters:** ECDSA, `prime256v1` curve. Override with `--ec-curve secp384r1` if needed.

---

### 3. `issue-intermediary.sh`

Generates the intermediate CA private key and CSR, signs the CSR with the root CA, and assembles a certificate chain. Runs interactively by default — the operator must type `ISSUE INTERMEDIATE` to confirm.

**Inputs:**
- `ca/root-ecdsa/openssl.cnf` (root CA config)
- `ca/int-ecdsa/openssl.cnf` (intermediate CA config)
- `ca/root-ecdsa/certs/root-ecdsa.cert.pem` (appended to the chain)
- Root CA key — OpenSSL prompts for the passphrase if it is encrypted

**Outputs (artifact name defaults to `int-ecdsa-YYYYMMDD`):**
- `ca/int-ecdsa/private/<name>.key.pem` — intermediate private key, permissions `600`
- `ca/int-ecdsa/csr/<name>.csr.pem` — certificate signing request
- `ca/int-ecdsa/certs/<name>.cert.pem` — intermediate certificate
- `ca/int-ecdsa/certs/<name>.chain.pem` — intermediate cert + root cert concatenated
- Active symlinks (updated by default):
  - `ca/int-ecdsa/private/int-ecdsa.key.pem` → `<name>.key.pem`
  - `ca/int-ecdsa/certs/int-ecdsa.cert.pem` → `<name>.cert.pem`
  - `ca/int-ecdsa/certs/int-ecdsa.chain.pem` → `<name>.chain.pem`
- `ca/ca-audit.log` — JSON audit entry appended

---

### 4. `revoke-intermediary.sh`

Revokes an existing intermediate certificate in the root CA database and regenerates the CRL. Run this when rotating to a new intermediate or when intermediate key compromise is suspected. Requires the root CA key to be present.

**Inputs:**
- `--algo ecdsa` — selects the root CA family
- `--cert <path>` — path to the intermediate cert PEM to revoke (e.g., `ca/int-ecdsa/certs/int-ecdsa-20260101.cert.pem`)
- `ca/root-ecdsa/openssl.cnf`

**Outputs:**
- Root CA database updated (`ca/root-ecdsa/index.txt`)
- `ca/root-ecdsa/crl/root-ecdsa.crl.pem` — updated CRL

---

## Execution Order

For a fresh deployment, run scripts 1–3 in order. Script 4 is used only for intermediate rotation or revocation.

**Step 1 — Configure variables**

```bash
cp ca-vars.env.example ca-vars.env
$EDITOR ca-vars.env   # set ORG, ROOT_ECDSA_CN, INT_ECDSA_CN, ROOT_DAYS, INT_DAYS
```

**Step 2 — Generate OpenSSL configs**

```bash
./scripts/generate-openssl-cnf.sh --env-file ca-vars.env --force
```

**Step 3 — Generate root CA**

Interactive (production — prompts for passphrase and confirmation):

```bash
./scripts/bootstrap-roots.sh
```

Non-interactive (dev/CI — no passphrase):

```bash
./scripts/bootstrap-roots.sh --no-passphrase --non-interactive --force
```

**Step 4 — Issue intermediate CA**

Interactive:

```bash
./scripts/issue-intermediary.sh
```

Non-interactive:

```bash
./scripts/issue-intermediary.sh --non-interactive --force
```

**Step 5 — Move root key offline**

The root CA key (`ca/root-ecdsa/private/`) is no longer needed until you rotate the intermediate. Move it to offline encrypted storage (encrypted USB drive, HSM, or air-gapped machine) immediately after step 4.

---

## Outputs and What to Do with Them

### Files produced

| File | Description | Sensitivity |
|------|-------------|-------------|
| `ca/root-ecdsa/certs/root-ecdsa.cert.pem` | Root CA certificate | Public — distribute to all machines as trust anchor |
| `ca/root-ecdsa/private/root-ecdsa.key.pem` | Root CA private key | **Secret — move to offline storage; never put on Vigil host** |
| `ca/int-ecdsa/certs/int-ecdsa.cert.pem` | Intermediate CA certificate | Public — copy to Vigil host |
| `ca/int-ecdsa/certs/int-ecdsa.chain.pem` | Intermediate cert + root cert | Public — copy to Vigil host (Vigil serves this as its CA chain) |
| `ca/int-ecdsa/private/int-ecdsa.key.pem` | Intermediate CA private key | **Secret — copy to Vigil host only; restrict permissions** |
| `ca/ca-audit.log` | JSON audit log (one entry per ceremony action) | Keep with CA archive |

The active symlinks (`int-ecdsa.{key,cert,chain}.pem`) are what scripts and configs reference. Dated artifact files (`int-ecdsa-YYYYMMDD.*`) are the actual content.

### Files that feed into Shepherd bootstrap

After the ceremony, the bootstrap process (see [docs/bootstrap-guide.md](../docs/bootstrap-guide.md)) needs these files on the Vigil host:

```bash
# Intermediate CA — pushed to Vigil only
scp ca/int-ecdsa/certs/int-ecdsa.cert.pem   vigil:/var/apps/credo/ca/int-ecdsa/certs/
scp ca/int-ecdsa/certs/int-ecdsa.chain.pem  vigil:/var/apps/credo/ca/int-ecdsa/certs/
scp ca/int-ecdsa/private/int-ecdsa.key.pem  vigil:/var/apps/credo/ca/int-ecdsa/private/

# Root CA trust anchor — distributed to every machine
scp ca/root-ecdsa/certs/root-ecdsa.cert.pem vigil:/var/apps/credo/ca/root-ecdsa.cert.pem
```

The `scripts/bootstrap` orchestrator performs this transfer automatically in Phase 2. When running the manual path, copy the files above before starting Vigil.

Vigil's config points to the intermediate key at `caEcdsaIntermediateKeyPath` and the chain at `caEcdsaIntermediateCertPath`. All services use the root CA cert as their mTLS trust anchor (`caTrustPath`).

---

## Security Notes

### Root CA key

- By default, `bootstrap-roots.sh` encrypts the root key with AES-256. You are prompted for a passphrase — use a strong, randomly generated passphrase and record it in a secure credential store.
- After `issue-intermediary.sh` completes, move `ca/root-ecdsa/private/` to offline encrypted storage. The root key is only needed to issue or revoke intermediate certificates. It must never reside on the Vigil host.
- `--no-passphrase` is acceptable for dev and CI environments. Never use it for a production root CA.
- For the highest security posture, generate the root CA key on an air-gapped machine and keep it on that machine permanently. Transfer only the root certificate (`root-ecdsa.cert.pem`) off the air-gapped machine.

### Intermediate CA key

- The intermediate CA key (`int-ecdsa.key.pem`) is the key Vigil uses at runtime to sign all service certificates. It is not passphrase-protected, because Vigil must be able to load it without operator intervention on start.
- Restrict access on the Vigil host: the key should be owned by the `vigil` OS user with permissions `600`. The `scripts/bootstrap` orchestrator applies this automatically. For the manual path, set ownership and permissions explicitly after copying.
- The intermediate key is more exposed than the root key by design. Rotate it (by rerunning `issue-intermediary.sh` and running `revoke-intermediary.sh` on the old cert) if the Vigil host is compromised or the intermediate key is lost.

### Audit log

Each ceremony action appends a JSON entry to `ca/ca-audit.log`. Keep this log with your CA archive. Entries record timestamp, hostname, operator username, action type, algorithm, validity, passphrase flag, and certificate fingerprint.

### CRL and OCSP

The `PKI_BASE_URL` is embedded in AIA/CDP extensions of issued certificates. The URL does not need to be served for the CA to function within credo — Vigil does not currently enforce CRL checking. It is embedded for completeness and future use.
