# Tier 1 — Any Operator, Any Skill Level

**Gate condition:** setup completes in under 15 minutes; nothing is silently insecure out of the box.

---

## [Setup] Restructure install / ceremony / bootstrap

Decision (final, after rejecting a Rust setup CLI — "the credo binary is a bad idea, it will be
used for setup and then never used again"): everything stays in bash, no new Rust CLI. No logic is
duplicated between bash and Rust, and none is duplicated between `bootstrap` and `ceremony` either —
bootstrap only collects inputs and orchestrates; the ceremony scripts perform the actual CA
operations.

Operator flow, end to end:

1. `git pull && cargo build`
2. `scripts/install init` (optional) — interactively generates `.install.json`
3. `scripts/install` — quizes for details not in .install.json.  Fills out .install.json with new/missing information. copies built binaries to `$TARGET_DIR`, creates service users/groups,
   optionally generates systemd units
4. `scripts/ceremony/*` — run manually, separate standalone scripts, no orchestrator; recommended on an air-gapped machine with output copied to `$TARGET_DIR/ca`
5. `scripts/bootstrap` — interactive wizard that configures and bootstraps all services. Will use bootstrap-default.json for defaults and will crate/complete bootstrap.json with entered information.
6. `systemctl enable --now credo-vigil` / `credo-shepherd` / `credo-corgi`

### Sub-tasks

- [x] **Move ceremony scripts**: `ceremony/scripts/` → `scripts/ceremony/` (the four scripts +
  `ca-vars.env.example`). `ceremony/ca/` does **not** move — existing CA material stays where it is
  as operator data, not source. Update any internal relative-path references inside the moved
  scripts. Update `docs/bootstrap-guide.md` paths.
- [x] **Rename `scripts/deploy` → `scripts/install`**. All existing functionality preserved
  (remote rsync, parallel deploy, `cargo zigbuild`, `buildOverrides.env`/`buildOverrides.args`,
  `--dry-run`, `--print-build-cmd`). Rename configs: `.deploy.json` → `.install.json`,
  `.deploy-local.json` → `.install-local.json`, `.deploy-remote.json` → `.install-remote.json`.
  Update the script's default config path.
- [x] **Add `scripts/install init` subcommand** — interactively generates `.install.json`. Asks:
  - Target directory (default `/var/apps/credo`)
  - Which services to install (shepherd, vigil, corgi; dashboard optional)
  - Rust target (auto-detected via SSH `uname -m`, offered as default, overridable)
  - Whether to create service users/groups and generate systemd unit files
- [x] **User and group model** — dedicated `vigil:vigil`, `shepherd:shepherd`, `corgi:corgi`
  users+groups, standard `useradd -r -U <name>` pattern. No shared `credo` group for internal
  secrets — that would defeat the per-service isolation (a corgi compromise must not grant group
  access to vigil's CA key or shepherd's JWT signing key). Each service's own private key material
  stays owned by that service's own user, mode `600`, no group access.
- [x] **`credo-cert` group + setgid cert store** — needed any time a non-corgi process reads cert
  material that corgi manages. On a single-host deployment this includes Shepherd and Vigil (corgi
  renews their TLS identity certs), plus external services like Caddy and nginx. Chose a dedicated
  `credo-cert` group over Debian's `ssl-cert` (portability — not Debian/Ubuntu-specific, and not
  tied to `/etc/ssl/private` semantics).

  Corgi's cert store IS the location consumers read from — there is no separate "delivery"
  directory or copy step. Corgi writes cert/key material directly to `$TARGET_DIR/corgi/certs/`
  (following the standard `live/<certname>/` layout), and all consumers read from there via the
  `credo-cert` group. In Tier 2, this path becomes the tmpfs mount — the store and the delivery
  point are the same thing; only the backing storage changes.

  - `scripts/install setup` creates `$TARGET_DIR/corgi/certs/` owned `corgi:credo-cert`, mode `2750`
    (leading `2` = setgid bit).
  - Corgi owns the directory, so it writes into it regardless of its own group membership.
  - The setgid bit makes the kernel auto-assign the `credo-cert` group to any file corgi creates
    inside that directory — no explicit `chgrp` call needed, and corgi never needs `credo-cert`
    membership itself.
  - Shepherd, Vigil, and external webserver users (`caddy`, `www-data`) are added to `credo-cert`
    by `scripts/install` (for credo services) or by the operator (for external services). Files in
    the cert store are mode `640`.
- [x] **Systemd unit file generation** — generated at `/etc/systemd/system/credo-<service>.service`
  after binaries are copied (triggered by `scripts/install init` answer or a `--systemd` flag).
  Services are **not** auto-started; operator runs `systemctl enable --now credo-vigil` etc.
  Template:

  Three slightly different unit variants:

  **Corgi** — owns the cert store, no `SupplementaryGroups` needed:
  ```ini
  [Unit]
  Description=credo corgi
  After=network-online.target
  Wants=network-online.target

  [Service]
  Type=simple
  User=corgi
  Group=corgi
  WorkingDirectory=$TARGET_DIR/corgi
  ExecStart=$TARGET_DIR/corgi/corgi server start
  Restart=on-failure
  RestartSec=5s
  TimeoutStopSec=10s
  StandardOutput=journal
  StandardError=journal
  SyslogIdentifier=corgi
  NoNewPrivileges=yes
  ProtectSystem=strict
  ReadWritePaths=$TARGET_DIR/corgi
  PrivateTmp=yes
  ProtectHome=yes

  [Install]
  WantedBy=multi-user.target
  ```

  **Shepherd and Vigil** — need `SupplementaryGroups=credo-cert` to read the TLS certs corgi
  manages for them:
  ```ini
  [Unit]
  Description=credo <service>
  After=network-online.target
  Wants=network-online.target

  [Service]
  Type=simple
  User=<service>
  Group=<service>
  SupplementaryGroups=credo-cert
  WorkingDirectory=$TARGET_DIR/<service>
  ExecStart=$TARGET_DIR/<service>/<service> server start
  Restart=on-failure
  RestartSec=5s
  TimeoutStopSec=10s
  StandardOutput=journal
  StandardError=journal
  SyslogIdentifier=<service>
  NoNewPrivileges=yes
  ProtectSystem=strict
  ReadWritePaths=$TARGET_DIR/<service>
  PrivateTmp=yes
  ProtectHome=yes

  [Install]
  WantedBy=multi-user.target
  ```

  No `ExecStop` on any unit — systemd's default `KillSignal=SIGTERM` is sufficient; the binaries
  don't have a `server stop` subcommand.
- [x] **Minimal sudo footprint** — `sudo` only for: `groupadd`/`useradd`, `chown`, writing unit
  files to `/etc/systemd/system/`, and `systemctl daemon-reload`.
- [x] **Write `scripts/bootstrap`** (run from the git source dir, after install). Phases:
  - **Phase 0** — read `.install.json` for `$TARGET_DIR`; prompt if missing.
  - **Phase 1 — Ceremony**: ask if ceremony already ran.
    - No → collect ceremony variables (table below), call `scripts/ceremony/generate-openssl-cnf.sh`
      + `bootstrap-roots.sh` + `issue-intermediary.sh` with `--ca-dir $TARGET_DIR/ca`
    - Yes → prompt for existing CA path (default `$TARGET_DIR/ca`)

  `scripts/bootstrap` supports two modes:

  - **Interactive** (default): prompts for each value, offers defaults, saves entered answers to
    `bootstrap.json` so subsequent runs or `--auto` can replay them.
  - **Unattended** (`--auto`): reads all answers from `bootstrap.json`, falling back to
    `bootstrap-default.json` for unset keys. Errors immediately on any missing required value. No
    prompts.

  `bootstrap-default.json` is committed to the repo with sensible defaults for every key except
  `ORG` and `PKI_BASE_URL`. `bootstrap.json` is gitignored — created by interactive mode and
  hand-editable for scripted deployments.

  The `ceremony` section of `bootstrap.json` answers Phase 1 in `--auto` mode:

  ```json
  {
    "ceremony": {
      "alreadyRun": true,
      "caDir": "/var/apps/credo/ca"
    }
  }
  ```

  If `alreadyRun` is `false`, bootstrap runs the ceremony scripts with values from
  `bootstrap.json`. The root CA passphrase is **never stored in JSON** — in unattended mode it is
  read from the `CREDO_ROOT_CA_PASSPHRASE` environment variable (error if unset).

  - **Phase 2 — Service config**: generate `vigil.config.json` / `shepherd.config.json` /
    `corgi.config.json` under `$TARGET_DIR/<service>/`; CA paths auto-derived from
    `$TARGET_DIR/ca`, never asked for again.
  - **Phase 3 — Bootstrap**: run existing bootstrap sequence (current phases 2–6, see
    `docs/bootstrap-guide.md`).
  - **Phase 4 — Verify**: hit health endpoints, pass/fail report.

  Ceremony variables `scripts/bootstrap` collects:

  | Question | Variable | Default |
  |---|---|---|
  | Organization name | `ORG` | *(required)* |
  | Country code | `COUNTRY` | `US` |
  | Root CA common name | `ROOT_ECDSA_CN` | `{ORG} Root` |
  | Intermediate CA common name | `INT_ECDSA_CN` | `{ORG} Intermediary` |
  | PKI base URL | `PKI_BASE_URL` | `http://pki.example.com` |
  | Root cert validity (days) | `ROOT_DAYS` | `3650` (10 yr) |
  | Intermediate cert validity (days) | `INT_DAYS` | `730` (2 yr) |
  | Root CA passphrase | *(secure prompt)* | *(required)* |

  CRL validity uses ceremony script defaults silently (`ROOT_CRL_DAYS=90`, `INT_CRL_DAYS=7`).
- [x] Confirm `ceremony/ca/` and `scripts/ceremony/ca/` are `.gitignore`d.
- [x] Update `docs/bootstrap-guide.md` to describe the new flow end to end (supersede the old
  multi-doc bootstrap description — see "Relationship to existing docs" below).
- [ ] Verification pass once implemented:
  - `scripts/install --help` shows `init` subcommand
  - `scripts/install init` produces a valid `.install.json` with `host: "local"` entries
  - `scripts/install <service>` copies the built binary to the configured local path
  - `scripts/ceremony/generate-openssl-cnf.sh --help` works from the new location
  - `scripts/bootstrap` reaches the Phase 1 prompt without errors
  - End-to-end: fresh clone → `git pull && cargo build` → `scripts/install init` → `scripts/install`
    → ceremony → `scripts/bootstrap` → `systemctl start` all three services → all health checks
    green, under 15 minutes wall-clock

---

## [Security] Vigil deny-all default

- [x] Flip `issuancePolicy.allowedDnsSuffixes: []` semantics from allow-all to deny-all. Explicit
  `"*"` opts into unrestricted issuance. A misconfigured first deployment should fail loudly, not
  silently sign anything. Secure-by-default: the safe configuration requires no action, the unsafe
  one requires explicit action.

---

## [Security] Dashboard session secret startup assertion

- [x] Shepherd/Dashboard refuses to start if the session secret matches the example/placeholder
  value or falls below a minimum entropy threshold. Currently `docs/security.md` describes this as
  an operator responsibility but the code does not enforce it — close that gap.

---

## [Docs] "What you get out of the box" security narrative

- [x] Write a short, honest doc: what credo protects by default, what requires explicit operator
  action, what it will never protect (hardware key binding, network-level isolation). Replaces the
  scattered "operator's responsibility" footnotes currently in `docs/security.md` and elsewhere.
  Written for an operator evaluating credo before installing it. → `docs/security-defaults.md`

---

## Relationship to existing docs touched by this tier

| Existing document | Status after Tier 1 |
|---|---|
| `docs/bootstrap-guide.md` | Superseded by `scripts/install` + `scripts/bootstrap` flow above |
| `docs/security.md` | "Operator's responsibility" section replaced by the new out-of-the-box narrative; deny-all default and session-secret assertion documented |
