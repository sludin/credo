# Corgi Configuration Reference

Corgi loads its config from `corgi.config.json` in the working directory, or from the path in `CORGI_CONFIG_PATH`.

Config files support variable interpolation (`${VAR}`) from the `vars` block and from environment variables, and `includes` arrays for splitting config across files.

## Meta Fields

| Field | Type | Description |
|-------|------|-------------|
| `vars` | object | Variable definitions, referenced as `${name}` elsewhere in the config |
| `includes` | string[] | Paths to additional JSON config files to merge in |
| `baseDir` | string | Base directory for resolving relative paths. Defaults to the config file's directory |

## Identity (required)

| Field | Type | Env override | Description |
|-------|------|--------------|-------------|
| `nodeId` | string | — | Unique identifier for this Corgi node. Used in API paths when contacting Shepherd |
| `commonName` | string | — | TLS common name for this node's certificate (e.g. `"corgi-01.example.com"`) |
| `shepherdUrl` | string | — | Base URL of the Shepherd agent port (e.g. `"https://shepherd.example.com:7000"`) |
| `identityUri` | string | — | URI SAN identity for this node (e.g. `"vigil://credo/dev/node/corgi-01"`). Optional but required for URI-based RBAC |

## Network

| Field | Type | Default | Env override | Description |
|-------|------|---------|--------------|-------------|
| `mtlsPort` | number | `7001` | `CORGI_MTLS_PORT`, `PORT` | Port for the mTLS control API |
| `bind` | string | `"127.0.0.1"` | `CORGI_BIND`, `BIND` | Interface to bind the mTLS API server |

## TLS (server cert — inbound connections)

Corgi's HTTPS server cert. If omitted, paths are derived from `certStoreDir/live/<commonName>/`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `tls.certPath` | string | `<certStoreDir>/live/<commonName>/fullchain.pem` | Server certificate (PEM, full chain) |
| `tls.keyPath` | string | `<certStoreDir>/live/<commonName>/privkey.pem` | Server private key (PEM) |

## mTLS (outbound to Shepherd)

Client certificate Corgi presents when connecting to Shepherd. Defaults to the same paths as `tls`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mtls.certPath` | string | same as `tls.certPath` | Client certificate for Shepherd connections |
| `mtls.keyPath` | string | same as `tls.keyPath` | Client private key |
| `mtls.caPath` | string | — | CA bundle for verifying Shepherd's server certificate |

## Cert Store

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `certStoreDir` | string | `"./store"` | Root directory for certificate material (`archive/` + `live/` layout) |
| `accountsPath` | string | `"corgi.fleet-accounts.json"` | Fleet RBAC accounts file |

## Node Identity Paths

Paths where Corgi's own certificate chain is written after bootstrap/renewal. Derived from `certStoreDir` if omitted.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `chainPath` | string | `<certStoreDir>/live/<commonName>/chain.pem` | Intermediate chain (without leaf) |
| `fullchainPath` | string | `<certStoreDir>/live/<commonName>/fullchain.pem` | Full chain including leaf |
| `csrPath` | string | `<certStoreDir>/live/<commonName>/csr.pem` | CSR used during issuance |

## File Policy

Default file ownership and permissions applied to all installed certificates — both Shepherd-assigned certs and flock entries. Can be overridden per-flock-entry or per-assignment.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `filePolicy.owner` | string | — | Default owner for cert and key files |
| `filePolicy.group` | string | — | Default group for cert and key files |
| `filePolicy.certMode` | string | — | Default octal permissions for cert files (e.g. `"0644"`) |
| `filePolicy.keyMode` | string | — | Default octal permissions for key files (e.g. `"0600"`) |

## Cert Hooks

Maps cert names to hook names that run when that specific cert changes. Used when different certs on the same node need to trigger different service reloads.

For the common case where all certs trigger the same reload, use `defaultHooks` instead — no per-cert configuration needed.

```json
{
  "certHooks": {
    "api.example.com":      ["nginx"],
    "payments.example.com": [{ "name": "docker-nginx", "args": { "container": "payments-proxy" } }]
  }
}
```

Hook resolution order for each cert change:
1. `certHooks[certName]` — if present, these hooks run and defaultHooks are skipped
2. `defaultHooks` — runs for any cert not listed in `certHooks`

## Flock

The `flock` array is **optional**. Without a flock entry, a Shepherd-assigned cert is installed at `certStoreDir/live/<certName>/` using `filePolicy` defaults for permissions and ownership.

Define a flock entry only when you need:
- A custom install path (e.g. `/etc/nginx/certs/`)
- Additional output files (`chainPath`, `fullchainPath`)

Hooks and file ownership are now handled by `certHooks` / `defaultHooks` and `filePolicy` — a flock entry is no longer needed just to trigger a service reload.

```json
{
  "flock": [
    {
      "name":          "api.example.com",
      "path":          "/etc/ssl/certs/api.example.com.pem",
      "keyPath":       "/etc/ssl/private/api.example.com.key",
      "fullchainPath": "/etc/ssl/certs/api.example.com.fullchain.pem"
    }
  ]
}
```

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `name` | yes | — | Must match the assignment name in Shepherd |
| `path` | no | `certStoreDir/live/<name>/fullchain.pem` | Destination path for the certificate PEM |
| `keyPath` | no | `certStoreDir/live/<name>/privkey.pem` | Destination path for the private key |
| `chainPath` | no | — | Destination path for the intermediate chain |
| `fullchainPath` | no | — | Destination path for the full chain |
| `csrPath` | no | — | Path to write the CSR |
| `domain` | no | — | Primary domain override for ACME ordering |
| `sans` | no | `[]` | Additional SANs beyond the primary domain |
| `monitor` | no | — | Endpoint monitor endpoint(s): a single object `{ "host": "...", "port": 443, "protocol": "https" }`, or an array of such objects to check several endpoints (e.g. a SAN cert served from multiple hosts). Corgi periodically TLS-handshakes each and reports `cert-mismatch` when the served leaf differs from the installed cert. Optional per-endpoint fields: `caPath` (a PEM CA bundle to additionally verify the served chain against — diagnostic only, reported as `chainTrusted`, never itself changes ok/cert-mismatch/unreachable) and `resolveIp` (pin the connection to a specific address instead of resolving `host` via DNS). Usually set on the Shepherd assignment instead; a local block is the fallback when the assignment has none. Legacy boolean values are accepted and ignored |
| `certMode` | no | from `filePolicy` | Octal file mode for cert files (e.g. `"0644"`) |
| `keyMode` | no | from `filePolicy` | Octal file mode for key files (e.g. `"0600"`) |
| `certOwner` / `certGroup` | no | from `filePolicy` | Per-cert file ownership |
| `keyOwner` / `keyGroup` | no | from `filePolicy` | Per-key file ownership |
| `identityUri` | no | — | URI SAN for CSR subject |
| `csrSubject` | no | — | CSR subject fields (`commonName`, `organization`, etc.) |

## HTTP Challenge

Controls the plain-HTTP server used for ACME HTTP-01 challenges.

| Field | Type | Default | Env override | Description |
|-------|------|---------|--------------|-------------|
| `httpChallenge.enabled` | bool | `false` | `CORGI_HTTP_CHALLENGE_ENABLED` | Enable the HTTP-01 challenge listener |
| `httpChallenge.port` | number | `7080` | `CORGI_HTTP_CHALLENGE_PORT` | Port to listen on |
| `httpChallenge.bind` | string | `"0.0.0.0"` | `CORGI_HTTP_CHALLENGE_BIND` | Interface to bind. Binds all by default since the ACME server needs to reach it |

The HTTP challenge listener is enabled automatically when the `httpChallenge` block is present in config, regardless of `enabled`.

## Shepherd Sync

Controls how Corgi pulls assignment state from Shepherd. Shepherd drives normal
reconciliation — it probes Corgi periodically and sends a data-free sync nudge
(`POST /sync/assignments`) when desired state changes — so Corgi's own periodic
pull is a slow safety net covering shepherd→corgi path breakage, not the
primary sync path. Corgi still reconciles immediately at startup.

| Field | Type | Default | Env override | Description |
|-------|------|---------|--------------|-------------|
| `shepherdSync.enabled` | bool | `true` | `CORGI_SHEPHERD_SYNC_ENABLED` | Enable periodic sync |
| `shepherdSync.intervalSeconds` | number | `1800` | `CORGI_SHEPHERD_SYNC_INTERVAL_SECONDS` | Safety-net sync interval (jittered ±10%) |
| `shepherdSync.staleWarningSeconds` | number | `3900` | `CORGI_SHEPHERD_SYNC_STALE_WARNING_SECONDS` | Emit a warning if no successful sync within this window (~2 missed pulls) |
| `shepherdSync.assignmentsCachePath` | string | `"corgi.assignments.cache.json"` | `CORGI_SHEPHERD_ASSIGNMENTS_CACHE_PATH` | Path for the persisted assignments cache. Used when Shepherd is unreachable |

## Endpoint Monitor

Corgi periodically TLS-handshakes each endpoint configured on a flock entry's
`monitor` block (from the Shepherd assignment or local config — one endpoint,
or an array of several for a SAN cert served from multiple hosts) and
compares the served leaf fingerprint against the locally installed cert.
Results (`ok`, `cert-mismatch`, `unreachable`, `pending`, `unmonitored`,
`partial-success`) ride the `/flock` response, so Shepherd picks them up on
its normal reconcile probe. With multiple endpoints, `partial-success` means
some matched and some didn't; overall `ok` requires every endpoint to match.
Each result also carries a per-endpoint breakdown (`endpoints`: the resolved
address actually dialed, the SNI sent, the fingerprint seen, the served
leaf's common name (`seenCommonName`) and SAN entries (`seenSanNames`), and —
if `caPath` was configured for that endpoint — whether the served chain
verified against it) for diagnosing a mismatch caused by DNS drift or a
misconfigured vhost versus a real fingerprint change. The checker
deliberately does not require the peer chain to verify for the handshake
itself — an expired or untrusted cert is mismatch data, not a connection
error; `caPath` verification is an additional diagnostic signal only and
never itself changes ok/cert-mismatch/unreachable. Cert installs additionally
trigger a one-shot check ~5s after hooks run.

| Field | Type | Default | Env override | Description |
|-------|------|---------|--------------|-------------|
| `monitorIntervalSeconds` | number | `900` | `CORGI_MONITOR_INTERVAL_SECONDS` | Sweep interval (jittered ±10%). Slow by design — this hunts config errors, not uptime |

## Auth

Controls how Corgi authenticates inbound connections to its mTLS API.

| Field | Type | Default | Env override | Description |
|-------|------|---------|--------------|-------------|
| `auth.mode` | string | `"mtls"` | `CORGI_AUTH_MODE` | `"mtls"` or `"proxy-headers"`. Use `"proxy-headers"` when a reverse proxy terminates TLS |
| `auth.identityOnly` | bool | `false` | `CORGI_AUTH_IDENTITY_ONLY` | When `true`, only URI SAN–matched identities in `rbacIdentities` are accepted; fingerprint and fleet fallbacks are disabled |

## RBAC Identities

List of known clients with their roles. Used when `auth.mode` is `"mtls"` or `"proxy-headers"`.

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

Roles: `"admin"`, `"operator"`, `"readonly"`.

## Proxy Auth Headers

Used only when `auth.mode` is `"proxy-headers"`. All values are lowercased on load.

| Field | Type | Default | Env override | Description |
|-------|------|---------|--------------|-------------|
| `proxyAuth.clientCertHeader` | string | `"x-corgi-client-cert"` | `CORGI_PROXY_CLIENT_CERT_HEADER` | Header carrying the PEM-encoded client cert |
| `proxyAuth.clientFingerprintHeader` | string | `"x-corgi-client-fingerprint256"` | `CORGI_PROXY_CLIENT_FINGERPRINT_HEADER` | Header carrying the SHA-256 fingerprint |
| `proxyAuth.clientSubjectHeader` | string | `"x-corgi-client-subject"` | `CORGI_PROXY_CLIENT_SUBJECT_HEADER` | Header carrying the cert subject |
| `proxyAuth.clientSanUriHeader` | string | `"x-corgi-san-uri"` | `CORGI_PROXY_CLIENT_SAN_URI_HEADER` | Header carrying the URI SAN |

## Allowed Client Fingerprints (legacy)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allowedClientFingerprints` | string[] | `[]` | SHA-256 fingerprints of clients to accept regardless of `rbacIdentities`. Legacy fallback; prefer `rbacIdentities` |

## Service Hooks

Maps hook names to shell commands or in-process signals. Hook names are referenced in flock entries and `defaultHooks`. Commands are always resolved locally on the Corgi node — Shepherd only sends names, never commands.

The array shorthand is always the simple shell-command case and needs no further tagging. Any other shape is a JSON object and **must** carry an explicit `"type"` field — `"exec"` or `"signal"` — naming which kind of hook it is. There is no shape-sniffing: an object without a recognized `type` is a config error, not a guess.

**Simple hook** (array of shell tokens — no `type` field, the array shape is unambiguous):
```json
{
  "serviceHooks": {
    "nginx":  ["systemctl", "reload", "nginx"],
    "caddy":  ["caddy", "reload", "--config", "/etc/caddy/Caddyfile"]
  }
}
```

**`"type": "exec"`** (shell command with typed runtime arguments):
```json
{
  "serviceHooks": {
    "docker-nginx": {
      "type": "exec",
      "exec": ["docker", "exec", "-t", "{container}", "nginx", "-s", "reload"],
      "args": {
        "container": { "type": "container-name" }
      }
    }
  }
}
```

Allowed `args.<name>.type` values: `"container-name"`, `"hostname"`, `"signal"`, `"service-name"`, `"identifier"`. Each has a validation regex applied before execution. (This is a different `type` field, nested inside `args` — it names an argument's validation kind, not the hook kind.)

**`"type": "signal"`** (credoSignal — PID-file signal, no subprocess):
```json
{
  "serviceHooks": {
    "corgi-self-reload": { "type": "signal", "pidFile": "corgi.pid" },
    "shepherd-reload":   { "type": "signal", "pidFile": "/opt/credo/shepherd/shepherd.pid", "signal": "TERM" }
  }
}
```
Sends a signal directly to the process recorded in `pidFile` via `nix::sys::signal::kill` — no shell, no subprocess spawn, no dependency on `kill`/`systemctl` being present. `signal` is optional and defaults to `HUP` (the reload convention every credo binary implements); it accepts either a raw signal number (`1`) or a well-known bare name (`"HUP"`, `"TERM"`, case-insensitive — the same convention as the `args.<name>.type: "signal"` arg validator above, not the `nix`/POSIX `"SIGHUP"` spelling, though that's accepted too).

Use this for credo's own binaries (shepherd, corgi, vigil, dashboard), which all write a PID file and already reload their TLS listener cert on `SIGHUP`. For corgi's own identity cert specifically, this is wired automatically: Shepherd attaches a `corgi-self-reload` hook to every corgi's self-assignment on enrollment, so a corgi just needs to define that hook name pointing at its own `corgi.pid` (relative paths resolve against the corgi process's own working directory — that's where it wrote the file). For shepherd/vigil/dashboard, the `pidFile` must be an absolute path, since it belongs to a different process than the corgi executing the hook.

**Note:** the signal above is sent via a plain POSIX `kill()` from the corgi process, which only succeeds against another user's PID if corgi runs as root or shares that user. On a host where corgi/shepherd/vigil run as separate Unix users, a `credoSignal` hook targeting `shepherd.pid`/`vigil.pid` fails with `EPERM` — see `docs/deploy/cross-user-hook-reload.md` for the sudo-scoped `exec`-hook workaround used in that case.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `defaultHooks` | string[] | `[]` | Hook names that run after any cert update, regardless of which cert changed |

## DNS Override

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `dnsOverride` | object | `{}` | Map of hostname → IP for outbound Shepherd connections. Bypasses DNS for the listed hostnames |

## Logging

| Field | Type | Default | Env override | Description |
|-------|------|---------|--------------|-------------|
| `logLevel` | string | `"info"` | `CORGI_LOG_LEVEL` | One of `"fatal"`, `"warn"`, `"info"`, `"debug"` |
| `logging.enabled` | boolean | `false` | — | Enable a size-rotated log file (in addition to stdout) with a live broadcast, so the `/logs` endpoint has historical + live-tail data to serve. Omit the whole `logging` block for current stdout-only behavior |
| `logging.dir` | string | `"logs"` | — | Directory for the rotating log file, relative to the service's working directory |
| `logging.rotateOn.sizeMb` | number | `100` | — | Rotate to a new file once the current one reaches this size |
| `logging.rotateOn.keepFiles` | number | `12` | — | Number of rotated backups to retain |
| `logging.alsoStdout` | boolean | `true` | — | Also emit to stdout when file logging is enabled (set `false` for file-only) |
| `logging.hookOutput` | boolean | `false` | — | A hook that exits non-zero (or fails to start) always logs its stdout/stderr at ERROR, regardless of this setting. Set `true` to also log a *successful* hook's stdout/stderr at INFO — off by default since successful output is usually just noise |
