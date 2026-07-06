# Manual Corgi Node Setup

`scripts/install setup` and `scripts/install corgi:<name>` are designed for Linux targets
(systemd, `useradd`/`groupadd`, standard GNU coreutils). For non-Linux targets — embedded
systems, routers, OpenWrt — these steps must be performed by hand. This document lists the
exact actions each script takes so they can be adapted to whatever init system and tooling
the target has.

The examples below use `/var/apps/credo/corgi` as `CORGI_DIR` and `/var/apps/credo` as
`CORGI_BASE` (the parent). Substitute the actual paths from the `.install.json` entry.

---

## Phase 1: Setup (`scripts/install setup corgi:<name>`)

### 1 — Create system groups and user

```sh
# Shared group for cert consumers (shepherd, vigil, and any service that reads certs)
getent group credo-cert >/dev/null 2>&1 || sudo groupadd --system credo-cert

# Corgi's own group and system user (no home dir, no shell)
getent group corgi >/dev/null 2>&1 || sudo groupadd --system corgi
id corgi >/dev/null 2>&1 || \
  sudo useradd --system --no-create-home --shell /usr/sbin/nologin -g corgi corgi
```

The `corgi` user does **not** need to be added to `credo-cert`; only services that read from the
cert store (shepherd, vigil, dashboard) need that membership.

### 2 — Create corgi working directory

```sh
sudo mkdir -p "$CORGI_DIR"
sudo chown corgi:corgi "$CORGI_DIR"
```

### 3 — Create cert store

The cert store uses setgid (`chmod 2xxx`) so files created inside it inherit the `credo-cert`
group automatically. Permissions are tighter on `store/` and `live/` (group-only traverse)
and looser on `archive/` and `pending/` (world-traversable).

```sh
sudo mkdir -p "$CORGI_DIR/store/archive" \
              "$CORGI_DIR/store/live" \
              "$CORGI_DIR/store/pending"

sudo chown corgi:credo-cert "$CORGI_DIR/store" \
                             "$CORGI_DIR/store/archive" \
                             "$CORGI_DIR/store/live" \
                             "$CORGI_DIR/store/pending"

sudo chmod 2750 "$CORGI_DIR/store" "$CORGI_DIR/store/live"
sudo chmod 2755 "$CORGI_DIR/store/archive" "$CORGI_DIR/store/pending"
```

### 4 — Deploy CA cert

The CA cert (`credo-catrust.pem`) must live at `$CORGI_BASE/credo-catrust.pem` with
`corgi:corgi 644` ownership. It must be **writable by the corgi user** because the bootstrap
sequence (`POST /bootstrap/ca`) overwrites it with the Shepherd CA cert during enrollment.

```sh
# Copy credo-catrust.pem from the management machine to the corgi host, then:
sudo chown corgi:corgi "$CORGI_BASE/credo-catrust.pem"
sudo chmod 644 "$CORGI_BASE/credo-catrust.pem"
```

The `localCaTrustPath` in `.install.json` is the path to this file on the management machine;
`scripts/install setup` rsyncs it automatically.

### 5 — Write init system unit

#### systemd (standard Linux)

Write the following to `/etc/systemd/system/credo-corgi.service`, then run
`sudo systemctl daemon-reload`:

```ini
[Unit]
Description=Credo Corgi
After=network.target
Wants=network.target

[Service]
Type=simple
User=corgi
Group=corgi
WorkingDirectory=<CORGI_DIR>
ExecStart=<CORGI_DIR>/corgi server start
ExecStop=<CORGI_DIR>/corgi server stop
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

NoNewPrivileges=yes
ProtectSystem=strict
PrivateTmp=yes
ProtectHome=yes
ReadWritePaths=<CORGI_DIR>

[Install]
WantedBy=multi-user.target
Alias=corgi.service
```

Enable and start: `sudo systemctl enable --now credo-corgi`

#### procd / OpenWrt (`/etc/init.d/`)

Write an init script appropriate for the target's init system. The binary is
`<CORGI_DIR>/corgi` and the invocation is `corgi server start`. The working directory must
be `<CORGI_DIR>` so the service finds its `corgi.config.json` there.

The `.install.json` `postDeploy` field can override the restart command for non-systemd
targets (e.g. `"/etc/init.d/corgi restart"`).

---

## Phase 2: Deploy (`scripts/install corgi:<name>`)

### 1 — Build the binary

```sh
# From the workspace root on the management machine:
cargo zigbuild --release --target <RUST_TARGET> --bin corgi
# e.g. --target armv7-unknown-linux-musleabihf for 32-bit ARM routers
```

### 2 — rsync to remote

The default file set is the `corgi` binary plus the `corgi/examples/` directory:

```sh
rsync -az --delete \
  target/<RUST_TARGET>/release/corgi \
  corgi/examples/ \
  <user>@<host>:<CORGI_DIR>/
```

If `sudoRsync: true` is set, the script uses `--rsync-path="sudo rsync"` (or
`--rsync-path="sudo -u corgi rsync"` when `remoteUser` is set). For root-login targets
(`useSudo: false`), plain rsync is used.

### 3 — Restart the service

```sh
# systemd:
sudo systemctl restart credo-corgi

# procd / OpenWrt:
/etc/init.d/corgi restart
```

Use the `postDeploy` field in `.install.json` to set a custom restart command that the
deploy script will run automatically after the rsync.

---

## Key file locations summary

| Path | Owner | Mode | Purpose |
|------|-------|------|---------|
| `<CORGI_DIR>/` | `corgi:corgi` | `755` | Working dir; binary, config, examples |
| `<CORGI_DIR>/store/` | `corgi:credo-cert` | `2750` | Cert store root (setgid) |
| `<CORGI_DIR>/store/archive/` | `corgi:credo-cert` | `2755` | Archived cert versions (setgid) |
| `<CORGI_DIR>/store/live/` | `corgi:credo-cert` | `2750` | Current live certs (setgid) |
| `<CORGI_DIR>/store/pending/` | `corgi:credo-cert` | `2755` | Pending renewal staging (setgid) |
| `<CORGI_BASE>/credo-catrust.pem` | `corgi:corgi` | `644` | CA trust bundle (corgi-writable for bootstrap) |
| `/etc/systemd/system/credo-corgi.service` | `root:root` | `644` | systemd unit |
