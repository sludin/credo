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

## Chosen approach: sudo-scoped `killall`, no wrapper script

Use an `exec` hook to run `killall -HUP <name>` under a narrowly-scoped
passwordless sudoers rule. No intermediate script is needed — and none
is used, for a specific reason: a rule that names a PID directly
(`kill -HUP 797586`) would break the moment the process restarts and
gets a new PID (sudoers matches command *and* arguments as literal
text — no way to say "whatever `shepherd.pid` currently contains").
The naive fix, wildcarding the PID (`kill -HUP [0-9]*`), removes the
staleness problem but also removes the scoping: it'd let `corgi` send
`SIGHUP` to *any* PID on the host, not just shepherd/vigil — a much
larger grant than intended, since a process with no `SIGHUP` handler
is killed by that signal by default.

`killall -HUP <name>` sidesteps this cleanly: it matches by process
name, not PID, so the sudoers rule can be an **exact, non-wildcarded
string** — no staleness, no broadened scope, no script required.
Verified on `home` (2026-09-13): `killall` is present
(`/usr/bin/killall`), and there is exactly one `shepherd` and one
`vigil` process — no ambiguity from name-based matching.

### 1. Sudoers drop-in

`/etc/sudoers.d/020_corgi-hook-reload` (mode `0440`, `root:root`,
matching this host's existing numbered `sudoers.d` convention):

```
# Let the corgi hook runner send a reload signal (SIGHUP) to shepherd
# and vigil after installing a renewed cert for their own listener.
# Exact command + arguments, no wildcards — cannot be used for
# anything beyond signaling exactly these two process names.
corgi ALL=(root) NOPASSWD: /usr/bin/killall -HUP shepherd
corgi ALL=(root) NOPASSWD: /usr/bin/killall -HUP vigil
```

Validate before enabling: `visudo -c -f /etc/sudoers.d/020_corgi-hook-reload`.

### 2. `corgi.config.json` — hook definitions

```json
"shepherd-reload": { "type": "exec", "exec": ["sudo", "-n", "/usr/bin/killall", "-HUP", "shepherd"] },
"vigil-reload":    { "type": "exec", "exec": ["sudo", "-n", "/usr/bin/killall", "-HUP", "vigil"] }
```

`-n` makes `sudo` fail immediately instead of hanging on a password
prompt if the sudoers rule is ever missing or misconfigured.

### 3. `shepherd.assignments.json` — wire the hooks to the certs

```
shepherd.vigilcert.com   hooks: ["shepherd-reload"]
vigil.vigilcert.com      hooks: ["vigil-reload"]
```

## Alternatives considered, not chosen

- **PID-file wrapper script** (`cat shepherd.pid`, then `kill -HUP` on
  that exact PID) — this was the first draft of this doc. Dropped:
  `killall` gets the same precision (signals the real running
  process) without a script to write, deploy, and keep in sync across
  hosts.
- **Linux file capability** (`setcap cap_kill+ep <corgi-binary>`) —
  would let corgi's native `credoSignal` hook work directly, matching
  `corgi/docs/config.md`'s example as written. Not used because it
  grants `corgi` the ability to signal *any* process on the host, not
  just shepherd/vigil.

## Applies to

Any corgi node that co-hosts shepherd and/or vigil under separate Unix
users. Currently only `corgi-01`/`home`.
