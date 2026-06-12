# Credo Systemd Service Installation

## Service units

| Unit file | Service | Port(s) |
|-----------|---------|---------|
| `credo-vigil.service` | Private CA | 7020 |
| `credo-shepherd.service` | Control plane | 7010, 7011 |
| `credo-corgi.service` | Certificate agent | 7001, (7080 optional) |
| `credo-dashboard.service` | Web UI / BFF | 7030 |

Shepherd and dashboard are typically co-located with vigil on a single host. Corgi is deployed on each managed node separately.

## 1. Create service users

```bash
sudo groupadd credo
sudo useradd -r -s /usr/sbin/nologin -d /var/apps/credo/vigil vigil -g credo
sudo useradd -r -s /usr/sbin/nologin -d /var/apps/credo/shepherd shepherd -g credo
sudo useradd -r -s /usr/sbin/nologin -d /var/apps/credo/corgi -G ssl-cert corgi -g credo
sudo useradd -r -s /usr/sbin/nologin -d /var/apps/credo/dashboard dashboard -g credo
```

The `ssl-cert` group must already exist (it is created by the `ssl-cert` Debian/Ubuntu package). Corgi must be in this group so its file-policy module can chown certificate files to `ssl-cert`.

## 2. Set data directory ownership

```bash
sudo chown shepherd:shepherd  /var/apps/credo/shepherd
sudo chown vigil:vigil        /var/apps/credo/vigil
sudo chown corgi:corgi        /var/apps/credo/corgi
sudo chown dashboard:dashboard /var/apps/credo/dashboard
```

## 3. Install unit files

```bash
sudo cp deploy/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
```

## 4. Enable and start

### On the host running shepherd + vigil + dashboard

```bash
sudo systemctl enable --now credo-vigil
sudo systemctl enable --now credo-shepherd
sudo systemctl enable --now credo-dashboard
```

Start vigil first; shepherd has `After=credo-vigil.service` so systemd will order them correctly when both are present on the same host.

### On each corgi host

```bash
sudo systemctl enable --now credo-corgi
```

## 5. Check status and logs

```bash
systemctl status credo-shepherd credo-vigil credo-corgi credo-dashboard
journalctl -u credo-shepherd -f
```

## 6. Reload configuration (Rust services only)

Shepherd, vigil, and corgi reload their configuration on SIGHUP without dropping connections:

```bash
sudo systemctl reload credo-shepherd
sudo systemctl reload credo-vigil
sudo systemctl reload credo-corgi
```

Dashboard does not support live reload; use `systemctl restart credo-dashboard` after a config change.

## Notes

- All units use `ProtectSystem=strict` with `ReadWritePaths` scoped to the service data directory. If the service writes to additional paths (e.g. a shared CA trust bundle), add those paths to `ReadWritePaths` in the unit file.
- Config file paths default to the `WorkingDirectory`. Override via environment variables (`SHEPHERD_CONFIG_PATH`, `VIGIL_CONFIG_PATH`, `CORGI_CONFIG_PATH`) if you prefer a separate config location such as `/etc/credo/`.
- `After=credo-vigil.service` in `credo-shepherd.service` is silently ignored on hosts where vigil is remote and the unit is absent.
