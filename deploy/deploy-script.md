# Deploy Script Reference

`scripts/deploy` builds and deploys credo service binaries to remote (or local) hosts.

## Quick start

```bash
./scripts/deploy                        # deploy everything (uses .deploy.json)
./scripts/deploy shepherd               # deploy shepherd only
./scripts/deploy corgi                  # deploy all corgis
./scripts/deploy corgi:corgi-01         # deploy one corgi
./scripts/deploy --dry-run all          # preview without transferring
./scripts/deploy --print-build-cmd shepherd  # print the resolved Rust build command
./scripts/deploy --parallel all         # deploy all targets concurrently
./scripts/deploy --config .deploy-local.json shepherd   # use an alternate config
```

## Config file

The script reads `.deploy.json` by default (override with `--config`). The repo includes three config files:

| File | Purpose |
|---|---|
| `.deploy.json` | Production hosts |
| `.deploy-local.json` | Local macOS development (host: `"local"`) |
| `.deploy-remote.json` | Production hosts accessed over SSH port forwarding |

### Top-level structure

```json
{
  "shepherd": { ... },
  "vigil":    { ... },
  "dashboard": { ... },
  "enroll":   { ... },
  "wizard":   { ... },
  "corgis": [
    { "name": "corgi-01", ... },
    { "name": "corgi-02", ... }
  ]
}
```

### Per-service fields

| Field | Type | Default | Description |
|---|---|---|---|
| `host` | string | — | `"user@hostname"` for SSH, or `"local"` / `"localhost"` / `"127.0.0.1"` for local copy **(required)** |
| `remoteDir` | string | — | Absolute path on the target host **(required)** |
| `files` | string[] | service default | Paths to sync, relative to the service directory |
| `sshPort` | number | `22` | SSH port |
| `sshOpts` | string | `""` | Extra flags passed to `ssh` and `rsync -e`, e.g. `"-o StrictHostKeyChecking=no"` |
| `rustTarget` | string | — | Rust cross-compile target, e.g. `"aarch64-unknown-linux-musl"`. Required for Rust services. |
| `rustProfile` | string | `"release"` | `"debug"` or `"release"` |
| `buildOverrides` | object | `{}` | Optional build-only overrides for Rust targets. Supports `env` (string map applied only to the build subprocess) and `args` (string array appended to `cargo zigbuild`). |
| `owner` | string | — | `"user:group"` — `sudo chown -R` applied after sync. Auto-set to `remoteUser:remoteGroup` when those fields are present and `owner` is omitted. |
| `dirMode` | string | — | Octal mode string — `sudo chmod` applied to `remoteDir` after chown, e.g. `"750"` |
| `rsyncOpts` | string | — | Extra rsync flags, e.g. `"-O"` for OpenWRT targets |
| `serviceName` | string | — | systemd unit name, e.g. `"credo-shepherd"`. Auto-runs `sudo systemctl restart <name>` after a successful deploy. |
| `restartMode` | string | `"restart"` | Controls the `systemctl` verb when `serviceName` is set: `"restart"`, `"reload"` (sends SIGHUP), or `"none"` (suppress auto-restart). |
| `postDeploy` | string | — | Shell command run on the remote after install. Takes precedence over `serviceName`/`restartMode` when set. |
| `sudoRsync` | boolean | `false` | Use `sudo` on the remote for `mkdir` and `rsync`. Required when the target directory is owned by a different user than the SSH login user. |
| `remoteUser` | string | — | Service user on the remote host, e.g. `"shepherd"`. Used with `sudoRsync` to run `sudo -u <user> rsync` instead of plain `sudo rsync`. |
| `remoteGroup` | string | — | Service group on the remote host, e.g. `"shepherd"`. Combined with `remoteUser` to auto-set `owner` for the post-sync chown. |

Corgi entries also require `name` (string, unique identifier used in `corgi:<name>` targets).

## Deploying to a host where binaries run as a different user

By default the script rsyncs as the SSH login user. If the target directory is owned by a service user (e.g. `shepherd`) that is different from the SSH user, rsync will fail with permission errors.

Set `sudoRsync`, `remoteUser`, and `remoteGroup` to resolve this:

```json
{
  "shepherd": {
    "host": "deploy@myhost.example.com",
    "remoteDir": "/var/apps/credo/shepherd",
    "rustTarget": "aarch64-unknown-linux-musl",
    "serviceName": "credo-shepherd",
    "sudoRsync": true,
    "remoteUser": "shepherd",
    "remoteGroup": "shepherd",
    "buildOverrides": {
      "env": {
        "RUSTFLAGS": "-C target-cpu=goldmont"
      },
      "args": ["--locked"]
    }
  }
}
```

With this config the script will:
1. Run `sudo -u shepherd mkdir -p /var/apps/credo/shepherd` to create the directory if absent
2. Pass `--rsync-path='sudo -u shepherd rsync'` so files land owned by `shepherd`
3. Run `sudo chown -R shepherd:shepherd /var/apps/credo/shepherd` after the sync (auto-derived from `remoteUser:remoteGroup`)
4. Run `sudo systemctl restart credo-shepherd` (auto-generated from `serviceName`)

### Required sudoers entry on the remote host

The SSH login user needs passwordless `sudo` for the specific executables. A minimal `/etc/sudoers.d/credo-deploy` entry:

```
# Replace "deploy" with your actual SSH login user.
# Repeat the rsync/mkdir/chmod block for each service user (shepherd, vigil, corgi, dashboard).
deploy ALL=(shepherd) NOPASSWD: /usr/bin/rsync, /usr/bin/mkdir, /usr/bin/chmod
deploy ALL=(ALL)      NOPASSWD: /usr/bin/chown
```

The `chown` line is also needed when `owner` or `dirMode` are set without `sudoRsync`.

## Systemd auto-restart

Set `serviceName` to the systemd unit name and the script will run `sudo systemctl restart <name>` after every successful deploy:

```json
{
  "shepherd": {
    "host": "home",
    "remoteDir": "/var/apps/credo/shepherd",
    "rustTarget": "aarch64-unknown-linux-musl",
    "serviceName": "credo-shepherd"
  }
}
```

For services that support graceful config reload via SIGHUP (shepherd, vigil, corgi) and you are deploying config files only, use `restartMode: "reload"` to avoid dropping connections:

```json
"restartMode": "reload"
```

To suppress the auto-restart entirely (e.g. a staging target), set `restartMode: "none"`.

If you need something more complex (a custom init system, chained commands), use `postDeploy` as a freeform shell string instead — it takes precedence over `serviceName`/`restartMode`.

## Build behaviour by service type

| Condition | Build step |
|---|---|
| `rustTarget` is set | `cargo zigbuild --target <target> --release` plus any `buildOverrides.args`; any `buildOverrides.env` entries are applied only to the build subprocess (requires [cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild)) |
| `package.json` present in service directory | `npm install && npm run build`; `npm install --omit=dev` on remote after sync |
| Neither | Files are copied directly with no build step |

### Build command printing

Use `--print-build-cmd` to print the resolved Rust build command before it runs. The printed line includes the effective working directory, any `buildOverrides.env` entries used for the build, and the final `cargo zigbuild` arguments. This is intended for troubleshooting and reproducing the exact command locally.

Example output:

```text
[deploy][corgi/corgi-02] BUILD_CMD: cd /repo/corgi && RUSTFLAGS=-C\ target-cpu=goldmont cargo zigbuild --target x86_64-unknown-linux-musl --release --locked
```

`--print-build-cmd` does not change the deployed artifact; it only surfaces the exact Rust build invocation. When combined with `--dry-run`, the script still prints the command while keeping the remote sync and restart steps non-destructive.

## Parallel deploys

`--parallel` runs all selected targets concurrently using bash background jobs. Each target builds and rsyncs independently. Failures are collected and reported at the end; a non-zero exit is returned if any target fails.

## Dry run

`--dry-run` builds the binary / runs the TypeScript build but passes `--dry-run` to rsync, so no files are transferred. It also skips `ensure_dir`, `chown`, `chmod`, and `postDeploy`. Use it to verify the rsync command and file list before a real deploy.
