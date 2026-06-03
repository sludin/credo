# Vigil Configuration Reference

Vigil loads its config from `vigil.config.json` in the working directory, or from the path in `VIGIL_CONFIG_PATH`.

Config files support variable interpolation (`${VAR}`) from the `vars` block and from environment variables, and `includes` arrays for splitting config across files.

## Meta Fields

| Field | Type | Description |
|-------|------|-------------|
| `vars` | object | Variable definitions, referenced as `${name}` elsewhere in the config |
| `includes` | string[] | Paths to additional JSON config files to merge in |
| `baseDir` | string | Base directory for resolving relative paths. Defaults to the config file's directory |

## Network

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `port` | number | `7020` | Port for the mTLS HTTPS server |
| `bind` | string | `"127.0.0.1"` | Interface to bind. Vigil defaults to loopback; set to `"0.0.0.0"` only when needed |

## TLS

Server certificate for Vigil's HTTPS listener. Defaults are relative to `baseDir`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `tls.keyPath` | string | `"./certs/privkey.pem"` | Server private key (PEM) |
| `tls.certPath` | string | `"./certs/fullchain.pem"` | Server certificate (PEM, full chain) |
| `tls.clientCaPath` | string | `"./certs/root-ca.cert.pem"` | CA bundle used to validate mTLS client certificates |

## CA Key Material

Paths to the intermediate CA key and certificate used for signing. Vigil does **not** generate CA key material at runtime — these must be created offline via the `ceremony/` scripts before Vigil can start.

| Field | Type | Default | Env override | Description |
|-------|------|---------|--------------|-------------|
| `caEcdsaIntermediateKeyPath` | string | `"./ca/int-ecdsa/private/int-ecdsa.key.pem"` | `VIGIL_CA_KEY_PATH` | Intermediate CA private key (ECDSA P-384) |
| `caEcdsaIntermediateCertPath` | string | `"./ca/int-ecdsa/certs/int-ecdsa.cert.pem"` | `VIGIL_CA_CERT_PATH` | Intermediate CA certificate |
| `caDir` | string | `"./ca"` | — | Root of the CA directory tree. Used for CRL storage |

The env var overrides take precedence over config file values. The startup wrapper script (`scripts/run-with-config-ca.sh`) sets these automatically from the config.

> **Security:** The intermediate CA private key is the most sensitive file in the system. Place it on a filesystem with strict permissions (`0400`, root-owned) and ensure it is not accessible to the Vigil process user beyond what is needed to read it at startup.

## CA Behavior

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ca.curve` | string | `"P-384"` | ECDSA curve for issued certificates |
| `ca.certDefaultDays` | number | `365` | Default certificate validity period in days |
| `ca.crlNextUpdateHours` | number | `24` | CRL `nextUpdate` field: hours from now |
| `ca.ocspMaxAgeSeconds` | number | `60` | `max-age` for OCSP responses |

## Identity

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `commonName` | string | `""` | Vigil's own common name. Used in service identification |

## Data Storage

All paths are relative to `dataDir` if not absolute. `dataDir` itself is relative to `baseDir`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `dataDir` | string | `"./data"` | Root directory for all runtime data |
| `usersDbPath` | string | `"<dataDir>/users.json"` | User registry — maps client cert fingerprints to active/inactive status |
| `certDbPath` | string | `"<dataDir>/certificates.json"` | Index of all issued certificates |
| `acmeAccountsDbPath` | string | `"<dataDir>/acme-accounts.json"` | ACME account key store |
| `certsDir` | string | `"<dataDir>/certs"` | Directory where issued certificate PEM files are stored |
| `ctLogPath` | string | `"./logs/ct.log"` | Append-only Certificate Transparency log |

## Issuance Policy

Controls which certificate requests Vigil will accept. These are the most important security settings to configure for production deployments.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `issuancePolicy.allowedDnsSuffixes` | string[] | `[]` | DNS suffixes Vigil will issue certificates for. **Empty list disables DNS suffix enforcement — any DNS name can be requested.** Set this to your domain(s) in production |
| `issuancePolicy.allowSubdomains` | bool | `true` | Allow subdomains of the listed suffixes |
| `issuancePolicy.allowBareSuffix` | bool | `true` | Allow the bare suffix itself (e.g. `example.com`, not just `*.example.com`) |
| `issuancePolicy.allowedIdentityUriPrefixes` | string[] | `[]` | Allowed prefixes for URI SANs in certificates. Empty list allows any URI SAN. Set to restrict (e.g. `["vigil://credo/prod/"]`) |
| `issuancePolicy.allowIpSans` | bool | `false` | Allow IP address SANs in issued certificates |

## RBAC Identities

Clients that can access Vigil's mTLS-protected endpoints (all non-ACME routes). ACME endpoints (`/acme/*`) are intentionally public.

```json
{
  "rbacIdentities": [
    {
      "uri":  "vigil://credo/dev/service/shepherd",
      "role": "admin",
      "name": "shepherd"
    }
  ]
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `uri` | yes | URI SAN that must be present in the client certificate |
| `role` | yes | `"admin"`, `"operator"`, or `"readonly"` |
| `name` | no | Human-readable label for logs |

Note: Vigil also validates all mTLS clients against `usersDbPath`. A client must have a matching `active: true` entry in the users registry regardless of `rbacIdentities`.

## Logging

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `logLevel` | string | `"info"` | One of `"fatal"`, `"warn"`, `"info"`, `"debug"` |
