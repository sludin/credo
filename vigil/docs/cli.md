# Vigil CLI Reference

```
vigil <group> <command> [options]
```

Config is loaded from `vigil.config.json` in the current directory, or from the path in `VIGIL_CONFIG_PATH`.

---

## `vigil bootstrap`

Start Vigil in bootstrap mode. Equivalent to `vigil server start --bootstrap`.

```bash
vigil bootstrap
```

In bootstrap mode:
1. Generates an ephemeral TLS certificate signed by the intermediate CA (using `commonName` from config).
2. Prints a one-time enrollment secret to stdout.
3. Starts the HTTPS server using the ephemeral certificate.
4. Accepts one call to `POST /bootstrap` — authenticated with the secret — to enroll a new service (e.g., Shepherd).

The wizard captures the printed secret automatically. Copy it before proceeding if running manually.

Requires `commonName` to be set in config; exits with an error if it is missing.

---

## `vigil server`

### `vigil server start [--bootstrap]`

Start the Vigil server. Without `--bootstrap`, loads the TLS certificate from `tls.certPath` and `tls.keyPath`. With `--bootstrap`, behaves identically to `vigil bootstrap`.

```bash
vigil server start
vigil server start --bootstrap
```

On startup:
- Ensures data directories exist (`dataDir`, `certsDir`, `usersDbPath`, `certDbPath`, `acmeAccountsDbPath`).
- Loads the intermediate CA metadata; exits if `caEcdsaIntermediateKeyPath` or `caEcdsaIntermediateCertPath` are missing.
- Restores any persisted ACME accounts.
- Emits a `WARN` log if `allowNoneValidation: true` is set.

Responds to `SIGHUP` by reloading config and TLS material without dropping active connections.

### `vigil server check-config`

Validate the config file, check that all CA material and TLS paths exist, and report whether RBAC identities are configured. Exits with code 0 if ready, 1 if any errors are found.

```bash
vigil server check-config
```

Output example:
```
Vigil config check
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

vigil.config.json
  ✓ parsed  (commonName=vigil.example.com  port=7020)

CA material
  ✓ caEcdsaIntermediateKeyPath   /etc/credo/vigil/ca/int-ecdsa/private/int-ecdsa.key.pem
  ✓ caEcdsaIntermediateCertPath  /etc/credo/vigil/ca/int-ecdsa/certs/int-ecdsa.cert.pem

TLS output paths
  ✓ tls.keyPath parent writable

Client CA
  ✓ tls.clientCaPath  /etc/credo/credo-catrust.pem  (exists)

RBAC
  ✓ rbacIdentities  1 identity(ies) configured

Issuance policy
  ✓ allowedDnsSuffixes  example.com

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Result: READY  (0 errors, 0 warnings)
```

Empty `allowedDnsSuffixes` is treated as an error, not a warning — Vigil cannot issue any certificates without at least one allowed domain suffix.

### `vigil server status`

Print a summary of the CA certificate and the issuance database. Vigil does not need to be running.

```bash
vigil server status
```

```
CA subject:      CN=Credo Intermediate CA ECDSA
CA serial:       4a:2b:...
CA valid to:     2028-01-01 00:00:00 UTC
CA fingerprint:  ab:cd:ef:...
Certificates:    total=142 active=139 revoked=3
```

---

## `vigil ca`

CA management commands read and write the data files directly. Vigil does not need to be running.

### `vigil ca add-user`

Register a service or operator in the Vigil user registry by public key. The registry maps client certificate public key fingerprints to active/inactive status. A client must have an `active: true` entry here to access Vigil's non-ACME endpoints.

```bash
vigil ca add-user \
  --id shepherd \
  --name "Shepherd service" \
  --public-key-pem-file /etc/credo/shepherd/shepherd.pubkey.pem
```

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--id` | yes | — | Unique identifier for this user |
| `--name` | yes | — | Human-readable label |
| `--public-key-pem-file` | yes | — | Path to the public key PEM file (extracted from the service's certificate) |
| `--active` | no | `true` | Set to `false` to pre-register without activating |

The fingerprint is computed from the public key and printed on success. This fingerprint must match the public key in the client certificate the service presents.

### `vigil ca export-crl`

Export the current Certificate Revocation List. The CRL is generated from the cert database and signed with the intermediate CA key.

```bash
vigil ca export-crl                          # PEM to stdout
vigil ca export-crl --out /tmp/crl.pem       # PEM to file
vigil ca export-crl --format der --out /tmp/crl.der
vigil ca export-crl --format json            # JSON to stdout
```

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--out <PATH>` | no | stdout | Write output to this file |
| `--format` | no | `pem` | Output format: `pem`, `der`, or `json` |

### `vigil ca ocsp-check`

Look up the OCSP status of a certificate by its cert database ID or serial number. Returns the OCSP response as JSON.

```bash
vigil ca ocsp-check --id <CERT_DB_ID>
vigil ca ocsp-check --serial <HEX_SERIAL>
```

One of `--id` or `--serial` is required. The cert database ID is the UUID stored in `certDbPath`; the serial is the hex-encoded certificate serial number.

---

## `vigil acme`

ACME client commands are stubs. They print a reminder but do not execute. ACME interactions are handled by Shepherd, not the Vigil CLI.

### `vigil acme directory [--url <URL>]`

Print the ACME directory URL. No network call is made.

### `vigil acme sign-csr --csr <PATH> [--url <URL>]`

Stub — not yet implemented.

---

## Environment variables

| Variable | Description |
|----------|-------------|
| `VIGIL_CONFIG_PATH` | Override the default config file path (`vigil.config.json`) |
| `VIGIL_CA_KEY_PATH` | Override `caEcdsaIntermediateKeyPath` from config |
| `VIGIL_CA_CERT_PATH` | Override `caEcdsaIntermediateCertPath` from config |
