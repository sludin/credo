# Reloading a sibling service's TLS listener from a corgi hook

## The problem

None of shepherd, vigil, or corgi hot-reload their own TLS certificate.
All three build a static `rustls::ServerConfig` at startup
(`credo-lib/src/tls.rs`) and only pick up a renewed cert on `SIGHUP`
(`shepherd/src/main.rs:378-411`, `vigil/src/cli.rs:188-218`,
`corgi/src/main.rs:178-249` all implement the identical reload path).
`corgi-self-reload` (a `credoSignal` hook, auto-attached by Shepherd to
every corgi's own identity-cert assignment) is exactly that nudge for
corgi's own cert — nothing more.

For shepherd/vigil, the equivalent doesn't exist automatically. The
`credoSignal` hook type (`corgi/docs/config.md`, "`type: signal`")
looks like it should cover this — its own documented example shows a
hook targeting an absolute `pidFile` belonging to shepherd:

```json
"shepherd-reload": { "type": "signal", "pidFile": "/opt/credo/shepherd/shepherd.pid", "signal": "TERM" }
```

**This only works if corgi and the target process share a Unix
user, or corgi runs as root.** The hook sends the signal via
`nix::sys::signal::kill` from *inside the corgi process*
(`corgi/src/hooks.rs`) — plain POSIX `kill()` semantics, which require
the same UID or a privileged caller. On any host where corgi, shepherd,
and vigil run as separate users (per `.install.json`'s distinct
`remoteUser` per component — this is the case for `corgi-01`/`home`,
which co-hosts corgi-01, shepherd, and vigil as `corgi`/`shepherd`/
`vigil` respectively), a `credoSignal` hook aimed at `shepherd.pid` or
`vigil.pid` fails with `EPERM`.

## Chosen approach: sudo-scoped exec wrapper

Use an `exec` hook to run a single-purpose, root-owned wrapper script,
permitted via a narrowly-scoped passwordless sudoers rule — the rule
grants nothing beyond running that exact script.

### 1. Wrapper scripts (root:root, mode 0755)

`/usr/local/sbin/reload-shepherd`:
```sh
#!/bin/sh
set -eu
PIDFILE=/var/apps/credo/shepherd/shepherd.pid
PID=$(cat "$PIDFILE")
case "$PID" in
  ''|*[!0-9]*) echo "reload-shepherd: invalid pid in $PIDFILE" >&2; exit 1 ;;
esac
exec kill -HUP "$PID"
```

`/usr/local/sbin/reload-vigil` — identical, pointed at
`/var/apps/credo/vigil/vigil.pid`.

### 2. Sudoers drop-in

`/etc/sudoers.d/020_corgi-hook-reload` (mode `0440`, `root:root`,
matching this host's existing numbered `sudoers.d` convention):

```
# Let the corgi hook runner send a reload signal (SIGHUP) to shepherd
# and vigil after installing a renewed cert for their own listener.
# Each entry is an exact command with no arguments and no wildcards —
# this cannot be used to run anything beyond that one signal.
corgi ALL=(root) NOPASSWD: /usr/local/sbin/reload-shepherd
corgi ALL=(root) NOPASSWD: /usr/local/sbin/reload-vigil
```

Validate before enabling: `visudo -c -f /etc/sudoers.d/020_corgi-hook-reload`.

### 3. `corgi.config.json` — hook definitions

```json
"shepherd-reload": { "type": "exec", "exec": ["sudo", "-n", "/usr/local/sbin/reload-shepherd"] },
"vigil-reload":    { "type": "exec", "exec": ["sudo", "-n", "/usr/local/sbin/reload-vigil"] }
```

`-n` makes `sudo` fail immediately instead of hanging on a password
prompt if the sudoers rule is ever missing or misconfigured.

### 4. `shepherd.assignments.json` — wire the hooks to the certs

```
shepherd.vigilcert.com   hooks: ["shepherd-reload"]
vigil.vigilcert.com      hooks: ["vigil-reload"]
```

## Alternative considered, not chosen

A Linux file capability (`setcap cap_kill+ep <corgi-binary>`) would
let corgi's native `credoSignal` hook work directly against another
user's PID, matching `corgi/docs/config.md`'s example as written, with
no sudo/wrapper involved. Not used here because it grants `corgi` the
ability to signal *any* process on the host, not just shepherd/vigil —
the sudo+wrapper approach scopes the grant to exactly two named PID
files.

## Applies to

Any corgi node that co-hosts shepherd and/or vigil under separate Unix
users. Currently only `corgi-01`/`home`.
