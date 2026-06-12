# Corgi CLI Reference

```
corgi <group> <command> [options]
```

Config is loaded from `corgi.config.json` in the current directory, or from the path in `CORGI_CONFIG_PATH`.

---

## `corgi bootstrap`

Generate a private key and CSR, then run a temporary bootstrap server that Shepherd calls to enroll this node. The bootstrap server runs on the same port as `mtlsPort` (default 7001) and shuts down automatically when enrollment is complete.

```bash
corgi bootstrap
```

What it does:
1. Generates a new ECDSA private key and a self-signed certificate using `commonName` and `identityUri` from config.
2. Starts a plain-HTTPS listener on `mtlsPort` using the self-signed cert.
3. Prints the bootstrap token and certificate fingerprint to stdout.
4. Waits for Shepherd to call `GET /bootstrap/enroll` (authenticated with the token).
5. On successful enrollment, Shepherd calls Vigil to issue a signed certificate and writes the result back to Corgi's cert store paths.
6. Prints "Bootstrap complete. Restart Corgi: corgi server start" and exits.

The printed token and fingerprint are what `shepherd bootstrap corgi --token` and `--fingerprint` expect. The wizard captures them automatically.

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--out <PATH>` | no | stdout | Write the CSR PEM to this file instead of stdout |
| `--dry-run` | no | false | Print what would happen without starting the server or writing files |

**Dry-run example:**
```bash
corgi bootstrap --dry-run
```
```
Dry run: would start bootstrap server on 127.0.0.1:7001
  Node ID:     corgi-01
  Common name: corgi-01.example.com
  Key path:    /var/apps/corgi/store/live/corgi-01.example.com/fullchain.pem
```

---

## `corgi server`

### `corgi server start`

Start the Corgi agent. Loads config, validates hook definitions, starts the mTLS control API on `mtlsPort`, and begins the Shepherd sync loop.

If `httpChallenge.enabled` is true, also starts the plain-HTTP ACME challenge listener on `httpChallenge.port`.

Responds to `SIGHUP` by reloading config, rebuilding the TLS config, and rebuilding the Shepherd client — all without dropping existing connections.

```bash
corgi server start
```

### `corgi server check-config`

Validate the config file, check that all TLS cert and key files exist, and attempt a lightweight connectivity probe to Shepherd's `/health` endpoint.

```bash
corgi server check-config
```

Output example:
```
Config: /var/apps/corgi/corgi.config.json
  Node ID:       corgi-01
  Common name:   corgi-01.example.com
  Shepherd URL:  https://shepherd.example.com:7010
  Control port:  10.0.0.5:7001
  Challenge:     enabled (port 7080)
  Auth mode:     Mtls
  Flock entries: 3

  [ok] TLS cert: /var/apps/corgi/store/live/corgi-01.example.com/fullchain.pem
  [ok] TLS key:  /var/apps/corgi/store/live/corgi-01.example.com/fullchain.pem
  [ok] mTLS client cert: /var/apps/corgi/store/live/corgi-01.example.com/fullchain.pem
  [ok] mTLS client key:  /var/apps/corgi/store/live/corgi-01.example.com/privkey.pem
  [ok] CA: /etc/credo/credo-catrust.pem

Checking Shepherd connectivity...
  Shepherd responded: HTTP 200

Config looks good.
```

The connectivity probe uses `danger_accept_invalid_certs: true` intentionally — it is checking reachability only, not certificate validity. Certificate verification happens at runtime using the configured `mtls.caPath`.

---

## Environment variables

| Variable | Description |
|----------|-------------|
| `CORGI_CONFIG_PATH` | Override the default config file path (`corgi.config.json`) |
| `CORGI_MTLS_PORT` / `PORT` | Override `mtlsPort` from config |
| `CORGI_BIND` / `BIND` | Override `bind` from config |
| `CORGI_AUTH_MODE` | Override `auth.mode` from config |
| `CORGI_LOG_LEVEL` | Override `logLevel` from config |
| `CORGI_HTTP_CHALLENGE_ENABLED` | Override `httpChallenge.enabled` |
| `CORGI_HTTP_CHALLENGE_PORT` | Override `httpChallenge.port` |
| `CORGI_HTTP_CHALLENGE_BIND` | Override `httpChallenge.bind` |
| `CORGI_SHEPHERD_SYNC_ENABLED` | Override `shepherdSync.enabled` |
| `CORGI_SHEPHERD_SYNC_INTERVAL_SECONDS` | Override `shepherdSync.intervalSeconds` |
| `CORGI_SHEPHERD_ASSIGNMENTS_CACHE_PATH` | Override `shepherdSync.assignmentsCachePath` |
