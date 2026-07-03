# Tier 1 Item 1: Install & Bootstrap Script Restructure

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reorganize the install/ceremony/bootstrap scripts into a coherent, production-ready operator flow under `scripts/` that handles user/group isolation, systemd unit generation, and a ceremony-aware bootstrap wizard.

**Architecture:** `scripts/install` (renamed from `scripts/deploy`) gains an `init` subcommand and OS-level setup; `scripts/bootstrap` (new, derived from `wizard/bootstrap-wizard`) provides the 4-phase service bootstrap; ceremony scripts move to `scripts/ceremony/`; shared bash libs move to `scripts/lib/`.

**Tech Stack:** bash 4+, jq, shellcheck, rsync, cargo zigbuild (Rust builds), systemd

## Global Constraints

- bash 4+ required; fail early with clear message if older
- All scripts must pass `shellcheck -x` with no errors
- No `sudo` for binary copy steps; `sudo` only for: `groupadd`/`useradd`, `chmod`/`chown` of service dirs, writing `/etc/systemd/system/`, `systemctl daemon-reload`
- `chmod` runs before `chown` (while file is still owned by current user)
- `bootstrap.json` and `ceremony/ca/` must be gitignored (never committed)
- `bootstrap-default.json` is committed with sensible defaults (no `ORG` or `PKI_BASE_URL`)
- Services are **never** auto-started by any script; operator runs `systemctl enable --now`
- All internal relative path references in ceremony scripts must be updated after move
- Config file schema change: `.deploy.json` → `.install.json` (and variants)

---

## File Map

| Action | Source | Destination |
|--------|--------|-------------|
| Move | `ceremony/scripts/generate-openssl-cnf.sh` | `scripts/ceremony/generate-openssl-cnf.sh` |
| Move | `ceremony/scripts/bootstrap-roots.sh` | `scripts/ceremony/bootstrap-roots.sh` |
| Move | `ceremony/scripts/issue-intermediary.sh` | `scripts/ceremony/issue-intermediary.sh` |
| Move | `ceremony/scripts/revoke-intermediary.sh` | `scripts/ceremony/revoke-intermediary.sh` |
| Move | `ceremony/ca-vars.env.example` (if exists) | `scripts/ceremony/ca-vars.env.example` |
| Move | `wizard/lib/prompts.sh` | `scripts/lib/prompts.sh` |
| Move | `wizard/lib/runner.sh` | `scripts/lib/runner.sh` |
| Move | `wizard/lib/config-gen.sh` | `scripts/lib/config-gen.sh` |
| Rename | `scripts/deploy` | `scripts/install` |
| Create | — | `scripts/bootstrap` |
| Create | — | `bootstrap-default.json` |
| Update | `docs/bootstrap-guide.md` | same |
| Update | `.gitignore` | same |
| Update | `docs/roadmap/tier-1.md` | same (check off subtasks as done) |

**Config file renames** (operator-side, not in repo; document in `--help`):
- `.deploy.json` → `.install.json`
- `.deploy-local.json` → `.install-local.json`
- `.deploy-remote.json` → `.install-remote.json`

---

## Task 1: Move ceremony scripts and wizard libs

**Files:**
- Move: `ceremony/scripts/*` → `scripts/ceremony/`
- Move: `wizard/lib/*.sh` → `scripts/lib/`
- Modify: all four ceremony scripts (fix relative paths)
- Modify: `scripts/bootstrap` will source from `scripts/lib/` (Task 3 dependency)

**Interfaces:**
- Produces: `scripts/ceremony/generate-openssl-cnf.sh --help` works from its new location
- Produces: `scripts/lib/prompts.sh`, `scripts/lib/runner.sh`, `scripts/lib/config-gen.sh` at stable paths

- [ ] **Step 1: Create destination directories**

```bash
mkdir -p scripts/ceremony scripts/lib
```

- [ ] **Step 2: Copy ceremony scripts**

```bash
cp ceremony/scripts/generate-openssl-cnf.sh scripts/ceremony/
cp ceremony/scripts/bootstrap-roots.sh       scripts/ceremony/
cp ceremony/scripts/issue-intermediary.sh    scripts/ceremony/
cp ceremony/scripts/revoke-intermediary.sh   scripts/ceremony/
# copy ca-vars.env.example if it exists
[[ -f ceremony/ca-vars.env.example ]] && cp ceremony/ca-vars.env.example scripts/ceremony/
```

- [ ] **Step 3: Fix relative-path references inside ceremony scripts**

Each ceremony script that references sibling scripts (e.g. `source "$(dirname "$0")/generate-openssl-cnf.sh"` or `./bootstrap-roots.sh`) must still work from `scripts/ceremony/`. Verify:

```bash
grep -n 'source\|\./' scripts/ceremony/*.sh
```

For any reference like `source "$(dirname "$0")/../lib/something"` or similar, update the path. The scripts currently reference each other using `$(dirname "$0")/...` which is location-independent — confirm this is the case, otherwise update each reference.

- [ ] **Step 4: Move wizard libs**

```bash
cp wizard/lib/prompts.sh    scripts/lib/
cp wizard/lib/runner.sh     scripts/lib/
cp wizard/lib/config-gen.sh scripts/lib/
```

- [ ] **Step 5: Verify ceremony scripts work from new location**

```bash
bash scripts/ceremony/generate-openssl-cnf.sh --help
bash scripts/ceremony/bootstrap-roots.sh --help
bash scripts/ceremony/issue-intermediary.sh --help
```

Expected: each prints its usage text and exits 0.

- [ ] **Step 6: shellcheck ceremony scripts**

```bash
shellcheck -x scripts/ceremony/*.sh
```

Expected: no errors. Fix any issues found before continuing.

- [ ] **Step 7: Delete originals from ceremony/scripts/**

```bash
rm ceremony/scripts/generate-openssl-cnf.sh
rm ceremony/scripts/bootstrap-roots.sh
rm ceremony/scripts/issue-intermediary.sh
rm ceremony/scripts/revoke-intermediary.sh
```

Only delete after Step 5 passes. `ceremony/ca/` stays in place — it is operator data, not source.

- [ ] **Step 8: Update .gitignore**

```bash
grep -q 'ceremony/ca/' .gitignore || echo 'ceremony/ca/' >> .gitignore
grep -q 'bootstrap.json' .gitignore || echo 'bootstrap.json' >> .gitignore
```

Confirm `ceremony/ca/` and `bootstrap.json` are gitignored. Also ensure `.install.json`, `.install-local.json`, `.install-remote.json` are gitignored (same rule that covered `.deploy.*` files; check and add if missing):

```bash
grep '\.deploy\.' .gitignore  # check current pattern
# If pattern is literal ".deploy.json" rather than glob, add the install variants:
grep -q '\.install\.json' .gitignore || echo '.install.json' >> .gitignore
grep -q '\.install-local' .gitignore || echo '.install-local.json' >> .gitignore
grep -q '\.install-remote' .gitignore || echo '.install-remote.json' >> .gitignore
```

- [ ] **Step 9: Commit**

```bash
git add scripts/ceremony/ scripts/lib/ ceremony/scripts/ .gitignore
git commit -m "refactor(scripts): move ceremony scripts to scripts/ceremony/, wizard libs to scripts/lib/"
```

---

## Task 2: Rename scripts/deploy → scripts/install

**Files:**
- Rename: `scripts/deploy` → `scripts/install`
- Modify: `scripts/install` — update default config path, add `init` to usage/targets

**Interfaces:**
- Consumes: `.install.json` (was `.deploy.json`)
- Produces: `scripts/install --help` shows updated usage; all existing deploy functionality works unchanged

- [ ] **Step 1: Rename the script**

```bash
mv scripts/deploy scripts/install
```

- [ ] **Step 2: Update default config path inside the script**

In `scripts/install`, find and replace the config path constant:

```bash
# Old:
CONFIG_PATH="$REPO_DIR/.deploy.json"

# New:
CONFIG_PATH="$REPO_DIR/.install.json"
```

Also update the fallback message that references `.deploy.json` and `examples/.deploy.json.example`:

```bash
# Old:
echo "[deploy] Config not found: $CONFIG_PATH" >&2
echo "[deploy] Copy examples/.deploy.json.example to .deploy.json and fill in your hosts." >&2

# New:
echo "[install] Config not found: $CONFIG_PATH" >&2
echo "[install] Run: scripts/install init   — to generate .install.json interactively" >&2
echo "[install] Or copy examples/.install.json.example to .install.json manually." >&2
```

- [ ] **Step 3: Replace [deploy] log prefix with [install] throughout the script**

```bash
sed -i 's/\[deploy\]/[install]/g' scripts/install
```

Verify: `grep '\[deploy\]' scripts/install` returns nothing.

- [ ] **Step 4: Rename example config files**

```bash
# In the scripts/examples directory (or repo root examples/):
find . -name '.deploy.json.example' -not -path '*/node_modules/*' | while read -r f; do
  mv "$f" "$(dirname "$f")/.install.json.example"
done
find . -name '.deploy-local.json.example' -not -path '*/node_modules/*' | while read -r f; do
  mv "$f" "$(dirname "$f")/.install-local.json.example"
done
```

- [ ] **Step 5: Update usage text in the script**

In `print_usage()`, update references from `deploy` to `install` and from `.deploy.json` to `.install.json`. Also update the `--config` default note.

The usage block should read:

```
Usage:
  ./scripts/install [options] [target ...]
  ./scripts/install init

Subcommands:
  init           Interactively generate .install.json and set up the remote host

Targets (default: all):
  ...

Config:
  Run 'scripts/install init' to generate .install.json, or copy
  examples/.install.json.example to .install.json and fill in manually.
```

- [ ] **Step 6: shellcheck**

```bash
shellcheck -x scripts/install
```

Expected: no errors.

- [ ] **Step 7: Smoke test**

```bash
scripts/install --help         # prints usage, exits 0
scripts/install --dry-run all  # reads .install.json (or .deploy.json fallback), prints dry-run plan
```

If `.deploy.json` exists locally but `.install.json` doesn't, add a fallback at config load time:

```bash
if [[ ! -f "$CONFIG_PATH" ]] && [[ -f "$REPO_DIR/.deploy.json" ]]; then
  echo "[install] Warning: .deploy.json found but .install.json expected. Using .deploy.json (rename it)." >&2
  CONFIG_PATH="$REPO_DIR/.deploy.json"
fi
```

- [ ] **Step 8: Commit**

```bash
git add scripts/install
git commit -m "refactor(scripts): rename deploy → install, update config path to .install.json"
```

---

## Task 3: Add scripts/install init subcommand

**Files:**
- Modify: `scripts/install` — add `init` subcommand function and CLI dispatch

**Interfaces:**
- Produces: running `scripts/install init` interactively generates `.install.json` with fields: `targetDir`, `services[]`, `rustTarget`, `createUsersGroups`, `generateSystemdUnits`, plus per-service blocks with `host`, `remoteDir`, etc.

The `init` subcommand does NOT install anything — it only writes `.install.json`. User/group creation and systemd generation happen during the actual `scripts/install [target]` run.

- [ ] **Step 1: Add init detection to parse_args**

In `parse_args()`, detect `init` as the first argument and set a flag:

```bash
INIT_MODE=false

parse_args() {
  # Check for init subcommand first
  if [[ "${1:-}" == "init" ]]; then
    INIT_MODE=true
    shift
    # Remaining args after 'init' are ignored (init has no sub-options)
    return
  fi
  while [[ $# -gt 0 ]]; do
    ...
  done
  ...
}
```

- [ ] **Step 2: Dispatch init before config-file check in main()**

```bash
main() {
  parse_args "$@"

  if $INIT_MODE; then
    run_init
    exit 0
  fi

  if [[ ! -f "$CONFIG_PATH" ]]; then
    ...
  fi
  ...
}
```

- [ ] **Step 3: Write run_init() function**

Add to `scripts/install` before `main()`:

```bash
# ---------------------------------------------------------------------------
# init subcommand — interactively generates .install.json
# ---------------------------------------------------------------------------

ask_init() {
  local question="$1" default="${2:-}"
  local display
  if [[ -n "$default" ]]; then display="$question [$default]: "; else display="$question: "; fi
  printf '%s' "$display" >/dev/tty
  local input
  IFS= read -r input </dev/tty || input=""
  input="${input#"${input%%[![:space:]]*}"}"
  input="${input%"${input##*[![:space:]]}"}"
  REPLY_VAL="${input:-$default}"
}

ask_init_yn() {
  local question="$1" default="${2:-y}"
  while true; do
    ask_init "$question (y/n)" "$default"
    case "${REPLY_VAL,,}" in
      y|yes) REPLY_VAL=true;  return ;;
      n|no)  REPLY_VAL=false; return ;;
    esac
    printf '  Enter y or n.\n' >&2
  done
}

detect_rust_target() {
  # Try rustup first, fall back to uname
  local toolchain
  if command -v rustup &>/dev/null; then
    toolchain=$(rustup show active-toolchain 2>/dev/null | awk '{print $1}' || true)
    if [[ -n "$toolchain" ]]; then
      printf '%s' "${toolchain#*-}"  # strip leading "stable-" / "nightly-"
      return
    fi
  fi
  local arch os
  arch=$(uname -m)
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  case "$arch" in
    x86_64)  printf 'x86_64-unknown-linux-musl' ;;
    aarch64) printf 'aarch64-unknown-linux-musl' ;;
    *)       printf '%s-unknown-%s-musl' "$arch" "$os" ;;
  esac
}

run_init() {
  if ! command -v jq &>/dev/null; then
    echo "[install] jq is required but not installed. Install it first." >&2
    exit 1
  fi

  printf 'Credo Install Config Generator\n'
  printf '%s\n' "========================================"
  printf 'This generates .install.json for use with: scripts/install\n\n'

  local target_dir rust_target create_users gen_systemd
  local detected_target
  detected_target=$(detect_rust_target)

  ask_init 'Installation root on target machine' '/var/apps/credo'
  target_dir="$REPLY_VAL"

  ask_init 'Rust cross-compile target' "$detected_target"
  rust_target="$REPLY_VAL"

  ask_init_yn 'Create service users and groups (vigil, shepherd, corgi, dashboard, credo-cert)' 'y'
  create_users="$REPLY_VAL"

  ask_init_yn 'Generate systemd unit files' 'y'
  gen_systemd="$REPLY_VAL"

  printf '\nService hosts — enter "local" to install to this machine, or user@hostname for remote.\n\n'

  local shepherd_host shepherd_dir vigil_host vigil_dir corgi_host corgi_dir dashboard_host dashboard_dir

  ask_init 'Shepherd host' 'local'
  shepherd_host="$REPLY_VAL"
  ask_init 'Shepherd remote dir' "$target_dir/shepherd"
  shepherd_dir="$REPLY_VAL"

  ask_init 'Vigil host' "${shepherd_host}"
  vigil_host="$REPLY_VAL"
  ask_init 'Vigil remote dir' "$target_dir/vigil"
  vigil_dir="$REPLY_VAL"

  ask_init 'Corgi host' "${shepherd_host}"
  corgi_host="$REPLY_VAL"
  ask_init 'Corgi remote dir' "$target_dir/corgi"
  corgi_dir="$REPLY_VAL"

  ask_init 'Dashboard host (or "none" to skip)' "${shepherd_host}"
  dashboard_host="$REPLY_VAL"
  ask_init 'Dashboard remote dir' "$target_dir/dashboard"
  dashboard_dir="$REPLY_VAL"

  local out_path="$REPO_DIR/.install.json"

  # Build per-service blocks
  local svc_blocks
  svc_blocks=$(jq -n \
    --arg sh  "$shepherd_host"  --arg sd  "$shepherd_dir"  \
    --arg vh  "$vigil_host"     --arg vd  "$vigil_dir"     \
    --arg ch  "$corgi_host"     --arg cd  "$corgi_dir"     \
    --arg dh  "$dashboard_host" --arg dd  "$dashboard_dir" \
    --arg tgt "$rust_target" \
    '{
      shepherd: {host: $sh, remoteDir: $sd, rustTarget: $tgt,
                 remoteUser: "shepherd", remoteGroup: "credo",
                 serviceName: "credo-shepherd"},
      vigil:    {host: $vh, remoteDir: $vd, rustTarget: $tgt,
                 remoteUser: "vigil", remoteGroup: "credo",
                 serviceName: "credo-vigil"},
      corgi:    {host: $ch, remoteDir: $cd, rustTarget: $tgt,
                 remoteUser: "corgi", remoteGroup: "credo",
                 serviceName: "credo-corgi"}
    }
    | if $dh != "none" then . + {dashboard: {host: $dh, remoteDir: $dd,
        remoteUser: "dashboard", remoteGroup: "credo",
        serviceName: "credo-dashboard"}} else . end')

  jq -n \
    --arg  targetDir      "$target_dir" \
    --arg  rustTarget     "$rust_target" \
    --argjson createUsers "$create_users" \
    --argjson genSystemd  "$gen_systemd" \
    --argjson services    "$svc_blocks" \
    '$services + {
       "_targetDir":         $targetDir,
       "_rustTarget":        $rustTarget,
       "_createUsersGroups": $createUsers,
       "_generateSystemd":   $genSystemd
     }' > "$out_path"

  printf '\nWrote %s\n' "$out_path"
  printf '\nNext steps:\n'
  printf '  1. Review and edit .install.json as needed\n'
  printf '  2. cargo build --release\n'
  printf '  3. scripts/install [shepherd|vigil|corgi|dashboard|all]\n'
  printf '  4. scripts/ceremony/*   (on air-gapped machine; copy output to %s/ca)\n' "$target_dir"
  printf '  5. scripts/bootstrap\n'
}
```

- [ ] **Step 4: Add init to print_usage()**

Add a `Subcommands:` section before `Targets:` in `print_usage()`:

```
Subcommands:
  init           Interactively generate .install.json and set up the target host
```

- [ ] **Step 5: shellcheck**

```bash
shellcheck -x scripts/install
```

Expected: no errors.

- [ ] **Step 6: Smoke test**

```bash
scripts/install init  # should prompt interactively
# Answer: targetDir=/tmp/test-credo, rust_target=x86_64-unknown-linux-musl,
#         create_users=n, gen_systemd=n, all hosts=local
cat .install.json | jq .  # should be valid JSON with _targetDir, shepherd, vigil, corgi
rm .install.json
```

- [ ] **Step 7: Commit**

```bash
git add scripts/install
git commit -m "feat(scripts/install): add init subcommand for interactive .install.json generation"
```

---

## Task 4: User/group setup and systemd generation in scripts/install

**Files:**
- Modify: `scripts/install` — add `setup_host()` called after binary copy when `_createUsersGroups` or `_generateSystemd` is true in `.install.json`

**Interfaces:**
- Consumes: `.install.json` fields `_targetDir`, `_createUsersGroups`, `_generateSystemd`
- Produces: on the target host, system users `vigil`, `shepherd`, `corgi`, `dashboard` + group `credo-cert`; cert store at `$targetDir/corgi/certs/` mode `2750` setgid; systemd unit files in `/etc/systemd/system/`

The setup runs once per `scripts/install all` or can be triggered explicitly with `scripts/install setup`.

- [ ] **Step 1: Add setup target to expand_targets()**

In `expand_targets()`, add a `setup` case:

```bash
setup)
  add_job "setup" "setup" "setup"
  ;;
```

And add `setup` to the `all` expansion (runs before service deployments):

```bash
all)
  add_job "setup" "setup" "setup"  # add FIRST so it runs before service copies
  for svc in shepherd vigil dashboard enroll wizard; do
  ...
```

- [ ] **Step 2: Add run_job dispatch for setup**

```bash
run_job() {
  local i="$1"
  local type="${JOB_TYPES[$i]}" key="${JOB_KEYS[$i]}"
  case "$type" in
    service) deploy_service "$key" "${JOB_LABELS[$i]}" ;;
    corgi)   deploy_corgi_by_name "$key" ;;
    setup)   run_setup ;;
  esac
}
```

- [ ] **Step 3: Write run_setup()**

```bash
# ---------------------------------------------------------------------------
# Host setup — users, groups, cert store, systemd units
# Reads _targetDir, _createUsersGroups, _generateSystemd from .install.json
# ---------------------------------------------------------------------------

run_setup() {
  local target_dir create_users gen_systemd
  target_dir=$(jq -r '._targetDir // empty' "$CONFIG_PATH")
  create_users=$(jq -r '._createUsersGroups // false' "$CONFIG_PATH")
  gen_systemd=$(jq -r '._generateSystemd // false' "$CONFIG_PATH")

  # Determine a representative host from config (setup only makes sense for one host)
  local host port ssh_opts
  host=$(jq -r '.shepherd.host // .vigil.host // "local"' "$CONFIG_PATH")
  port=$(jq -r '.shepherd.sshPort // 22' "$CONFIG_PATH")
  ssh_opts=$(jq -r '.shepherd.sshOpts // ""' "$CONFIG_PATH")

  if [[ -z "$target_dir" ]]; then
    echo "[install] _targetDir not set in .install.json — skipping setup. Run scripts/install init first." >&2
    return 0
  fi

  if [[ "$create_users" == "true" ]]; then
    echo "[install] Setting up service users and groups on $(format_dest "$host" "$target_dir")..."
    setup_users_groups "$host" "$port" "$ssh_opts" "$target_dir"
  fi

  if [[ "$gen_systemd" == "true" ]]; then
    echo "[install] Generating systemd unit files..."
    generate_systemd_units "$host" "$port" "$ssh_opts" "$target_dir"
  fi
}

setup_users_groups() {
  local host="$1" port="$2" ssh_opts="$3" target_dir="$4"

  local services=(vigil shepherd corgi dashboard)
  local svc
  for svc in "${services[@]}"; do
    run_cmd "$host" "$port" "$ssh_opts" \
      "id '$svc' &>/dev/null || sudo useradd -r -U -s /sbin/nologin '$svc'"
    echo "[install]   user: $svc"
  done

  # credo-cert group for cert consumers
  run_cmd "$host" "$port" "$ssh_opts" \
    "getent group credo-cert &>/dev/null || sudo groupadd credo-cert"
  echo "[install]   group: credo-cert"

  # Add shepherd and vigil to credo-cert (they read certs corgi manages for them)
  for svc in shepherd vigil dashboard; do
    run_cmd "$host" "$port" "$ssh_opts" \
      "sudo usermod -aG credo-cert '$svc' 2>/dev/null || true"
    echo "[install]   added $svc to credo-cert"
  done

  # Cert store — setgid so files created by corgi auto-inherit credo-cert group
  # chmod before chown (while still owned by current user, no sudo needed for chmod)
  local cert_store="$target_dir/corgi/certs"
  run_cmd "$host" "$port" "$ssh_opts" "mkdir -p '$cert_store'"
  run_cmd "$host" "$port" "$ssh_opts" "chmod 2750 '$cert_store'"
  run_cmd "$host" "$port" "$ssh_opts" "sudo chown corgi:credo-cert '$cert_store'"
  echo "[install]   cert store: $cert_store (corgi:credo-cert, 2750)"
}

generate_systemd_units() {
  local host="$1" port="$2" ssh_opts="$3" target_dir="$4"

  local corgi_unit shepherd_unit vigil_unit dashboard_unit

  corgi_unit="[Unit]
Description=credo corgi
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=corgi
Group=corgi
WorkingDirectory=$target_dir/corgi
ExecStart=$target_dir/corgi/corgi server start
Restart=on-failure
RestartSec=5s
TimeoutStopSec=10s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=corgi
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=$target_dir/corgi
PrivateTmp=yes
ProtectHome=yes

[Install]
WantedBy=multi-user.target"

  # Shepherd and Vigil need SupplementaryGroups=credo-cert to read TLS certs corgi manages
  for svc in shepherd vigil; do
    local unit_body
    unit_body="[Unit]
Description=credo $svc
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$svc
Group=$svc
SupplementaryGroups=credo-cert
WorkingDirectory=$target_dir/$svc
ExecStart=$target_dir/$svc/$svc server start
Restart=on-failure
RestartSec=5s
TimeoutStopSec=10s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$svc
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=$target_dir/$svc
PrivateTmp=yes
ProtectHome=yes

[Install]
WantedBy=multi-user.target"

    run_cmd "$host" "$port" "$ssh_opts" \
      "printf '%s' $(printf '%q' "$unit_body") | sudo tee /etc/systemd/system/credo-$svc.service > /dev/null"
    echo "[install]   wrote /etc/systemd/system/credo-$svc.service"
  done

  # Corgi unit
  run_cmd "$host" "$port" "$ssh_opts" \
    "printf '%s' $(printf '%q' "$corgi_unit") | sudo tee /etc/systemd/system/credo-corgi.service > /dev/null"
  echo "[install]   wrote /etc/systemd/system/credo-corgi.service"

  # Dashboard unit (Node.js, different ExecStart)
  local node_exec
  node_exec=$(run_cmd "$host" "$port" "$ssh_opts" "command -v node" 2>/dev/null || echo "/usr/bin/node")
  dashboard_unit="[Unit]
Description=credo dashboard
After=network-online.target credo-shepherd.service
Wants=network-online.target

[Service]
Type=simple
User=dashboard
Group=dashboard
SupplementaryGroups=credo-cert
WorkingDirectory=$target_dir/dashboard
Environment=NODE_ENV=production
ExecStart=$node_exec dist/server/index.js
Restart=on-failure
RestartSec=5s
TimeoutStopSec=10s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=dashboard
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=$target_dir/dashboard
PrivateTmp=yes
ProtectHome=yes

[Install]
WantedBy=multi-user.target"

  run_cmd "$host" "$port" "$ssh_opts" \
    "printf '%s' $(printf '%q' "$dashboard_unit") | sudo tee /etc/systemd/system/credo-dashboard.service > /dev/null"
  echo "[install]   wrote /etc/systemd/system/credo-dashboard.service"

  run_cmd "$host" "$port" "$ssh_opts" "sudo systemctl daemon-reload"
  echo "[install]   systemctl daemon-reload complete"
  echo "[install]   Run: sudo systemctl enable --now credo-vigil credo-shepherd credo-corgi credo-dashboard"
}
```

- [ ] **Step 4: shellcheck**

```bash
shellcheck -x scripts/install
```

Expected: no errors. Pay attention to `printf '%q'` usage — shellcheck may warn; suppress with a `# shellcheck disable=SC2059` if needed only on the relevant lines.

- [ ] **Step 5: Dry-run test (setup target)**

```bash
scripts/install --dry-run setup
```

Expected: prints what it would do, no SSH connections made (dry-run skips ensure_dir and rsync but `run_setup` currently doesn't check `$DRY_RUN`). Add `$DRY_RUN` guard to `run_setup()`:

```bash
run_setup() {
  ...
  if $DRY_RUN; then
    echo "[install] DRY RUN: would set up users/groups and systemd on $host"
    return 0
  fi
  ...
}
```

- [ ] **Step 6: Commit**

```bash
git add scripts/install
git commit -m "feat(scripts/install): add setup subcommand for user/group isolation and systemd unit generation"
```

---

## Task 5: Write scripts/bootstrap

**Files:**
- Create: `scripts/bootstrap`
- Modify: `scripts/lib/config-gen.sh` — update `source` paths from `wizard/lib/` to `scripts/lib/`

**Interfaces:**
- Consumes: `.install.json` (`_targetDir`), `scripts/ceremony/*.sh`, `scripts/lib/*.sh`
- Produces: all four services bootstrapped and their TLS certs on disk; `bootstrap.json` saved; health check pass/fail report

`scripts/bootstrap` is a rewrite of `wizard/bootstrap-wizard` with four phases replacing the flat structure. The inner bootstrap sequence (starting services, capturing secrets, enrolling corgi) is carried over with minimal changes.

- [ ] **Step 1: Update source paths in scripts/lib/config-gen.sh**

`config-gen.sh` was written for `wizard/bootstrap-wizard` and may have no internal sourcing. Verify:

```bash
grep 'source\|SCRIPT_DIR' scripts/lib/config-gen.sh
```

If it sources sibling files via `$(dirname "$0")`, those references are now `scripts/lib/` and still work. No changes needed if it's self-contained.

- [ ] **Step 2: Create scripts/bootstrap with shebang and Phase 0**

```bash
#!/usr/bin/env bash
set -euo pipefail

if (( BASH_VERSINFO[0] < 4 )); then
  echo "[bootstrap] Requires bash 4+. macOS users: brew install bash" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/lib/prompts.sh"
source "$SCRIPT_DIR/lib/runner.sh"
source "$SCRIPT_DIR/lib/config-gen.sh"

INSTALL_CONFIG="$REPO_DIR/.install.json"
BOOTSTRAP_JSON="$REPO_DIR/bootstrap.json"
BOOTSTRAP_DEFAULT="$REPO_DIR/bootstrap-default.json"
AUTO=false
DRY_RUN=false

die() { printf '[bootstrap] Error: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# bootstrap.json read/write helpers
# ---------------------------------------------------------------------------

_bj() {
  # Read a key from bootstrap.json, falling back to bootstrap-default.json
  local jq_path="$1" fallback="${2:-}"
  local val=""
  if [[ -f "$BOOTSTRAP_JSON" ]]; then
    val=$(jq -r "$jq_path // empty" "$BOOTSTRAP_JSON" 2>/dev/null || true)
  fi
  if [[ -z "$val" ]] && [[ -f "$BOOTSTRAP_DEFAULT" ]]; then
    val=$(jq -r "$jq_path // empty" "$BOOTSTRAP_DEFAULT" 2>/dev/null || true)
  fi
  printf '%s' "${val:-$fallback}"
}

_require_bj() {
  local field="$1" jq_path="$2" fallback="${3:-}"
  local val
  val=$(_bj "$jq_path" "$fallback")
  if [[ -z "$val" ]]; then
    die "--auto mode requires $field to be set in bootstrap.json or bootstrap-default.json"
  fi
  printf '%s' "$val"
}

save_bootstrap() {
  # Merge current answer globals into bootstrap.json (create if absent)
  local existing="{}"
  [[ -f "$BOOTSTRAP_JSON" ]] && existing=$(cat "$BOOTSTRAP_JSON")
  printf '%s' "$existing" | jq \
    --arg  credoRoot          "$CREDO_ROOT" \
    --arg  caTrustPath        "$CA_TRUST_PATH" \
    --arg  domain             "$DOMAIN" \
    --arg  vigilHostname      "$VIGIL_HOSTNAME" \
    --argjson vigilPort       "${VIGIL_PORT:-0}" \
    --arg  vigilIntCaKeyPath  "$VIGIL_INT_CA_KEY_PATH" \
    --arg  vigilIntCaCertPath "$VIGIL_INT_CA_CERT_PATH" \
    --arg  vigilDir           "$VIGIL_DIR" \
    --arg  vigilIdentityUri   "$VIGIL_IDENTITY_URI" \
    --arg  shepherdHostname   "$SHEPHERD_HOSTNAME" \
    --argjson shepherdAgentPort     "${SHEPHERD_AGENT_PORT:-0}" \
    --argjson shepherdDashboardPort "${SHEPHERD_DASHBOARD_PORT:-0}" \
    --arg  shepherdDir        "$SHEPHERD_DIR" \
    --arg  shepherdIdentityUri "$SHEPHERD_IDENTITY_URI" \
    --arg  corgiName          "$CORGI_NAME" \
    --arg  corgiHostname      "$CORGI_HOSTNAME" \
    --argjson corgiPort       "${CORGI_PORT:-0}" \
    --argjson corgiBootstrapPort "${CORGI_BOOTSTRAP_PORT:-0}" \
    --argjson corgiHttpChallengePort "${CORGI_HTTP_CHALLENGE_PORT:-0}" \
    --arg  corgiDir           "$CORGI_DIR" \
    --arg  corgiIdentityUri   "$CORGI_IDENTITY_URI" \
    '. + {
      credoRoot:   $credoRoot,
      caTrustPath: $caTrustPath,
      domain:      $domain,
      vigil: {
        hostname:      $vigilHostname,
        port:          $vigilPort,
        intCaKeyPath:  $vigilIntCaKeyPath,
        intCaCertPath: $vigilIntCaCertPath,
        dir:           $vigilDir,
        identityUri:   $vigilIdentityUri
      },
      shepherd: {
        hostname:      $shepherdHostname,
        agentPort:     $shepherdAgentPort,
        dashboardPort: $shepherdDashboardPort,
        dir:           $shepherdDir,
        identityUri:   $shepherdIdentityUri
      },
      corgi: {
        name:              $corgiName,
        hostname:          $corgiHostname,
        port:              $corgiPort,
        bootstrapPort:     $corgiBootstrapPort,
        httpChallengePort: $corgiHttpChallengePort,
        dir:               $corgiDir,
        identityUri:       $corgiIdentityUri
      }
    }' > "$BOOTSTRAP_JSON"
}
```

- [ ] **Step 3: Add Phase 0 — read install config**

```bash
phase0_read_install_config() {
  printf '\nPhase 0: Reading install config\n'
  if [[ ! -f "$INSTALL_CONFIG" ]]; then
    if $AUTO; then
      die ".install.json not found. Run scripts/install init first."
    fi
    ask_required 'Installation root (targetDir)' '/var/apps/credo'
    CREDO_ROOT="$REPLY_VAL"
  else
    CREDO_ROOT=$(jq -r '._targetDir // empty' "$INSTALL_CONFIG")
    if [[ -z "$CREDO_ROOT" ]]; then
      ask_required 'Installation root (_targetDir missing from .install.json)' '/var/apps/credo'
      CREDO_ROOT="$REPLY_VAL"
    else
      printf '  targetDir: %s\n' "$CREDO_ROOT"
    fi
  fi
}
```

- [ ] **Step 4: Add Phase 1 — ceremony**

```bash
phase1_ceremony() {
  printf '\nPhase 1: Ceremony\n'

  local already_run ca_dir
  already_run=$(_bj '.ceremony.alreadyRun' '')
  ca_dir=$(_bj '.ceremony.caDir' "$CREDO_ROOT/ca")

  if $AUTO; then
    if [[ "$already_run" == "true" ]]; then
      printf '  ceremony.alreadyRun=true — using existing CA at %s\n' "$ca_dir"
      VIGIL_INT_CA_KEY_PATH="$ca_dir/int-ecdsa/private/int-ecdsa.key.pem"
      VIGIL_INT_CA_CERT_PATH="$ca_dir/int-ecdsa/certs/int-ecdsa.cert.pem"
      CA_TRUST_PATH="$ca_dir/credo-catrust.pem"
      return
    fi
    # Run ceremony in auto mode
    _run_ceremony_auto "$ca_dir"
    return
  fi

  ask_init_yn 'Has the PKI ceremony already been run?' "${already_run:-n}"
  if [[ "$REPLY_VAL" == "true" ]]; then
    ask_required 'Path to existing CA directory' "$ca_dir"
    ca_dir="$REPLY_VAL"
    VIGIL_INT_CA_KEY_PATH="$ca_dir/int-ecdsa/private/int-ecdsa.key.pem"
    VIGIL_INT_CA_CERT_PATH="$ca_dir/int-ecdsa/certs/int-ecdsa.cert.pem"
    CA_TRUST_PATH="$ca_dir/credo-catrust.pem"
    jq '. + {ceremony: {alreadyRun: true, caDir: "'"$ca_dir"'"}}' "$BOOTSTRAP_JSON" > "$BOOTSTRAP_JSON.tmp" \
      && mv "$BOOTSTRAP_JSON.tmp" "$BOOTSTRAP_JSON"
  else
    _run_ceremony_interactive "$ca_dir"
  fi
}

_run_ceremony_interactive() {
  local ca_dir="$1"
  local org country root_cn int_cn pki_url root_days int_days passphrase

  printf '\n  Collecting ceremony variables:\n'
  ask_required 'Organization name (ORG)' "$(_bj '.ceremony.org' '')"
  org="$REPLY_VAL"
  ask 'Country code' "$(_bj '.ceremony.country' 'US')"
  country="${REPLY_VAL:-US}"
  ask 'Root CA common name' "$(_bj '.ceremony.rootCn' "$org Root")"
  root_cn="${REPLY_VAL:-$org Root}"
  ask 'Intermediate CA common name' "$(_bj '.ceremony.intCn' "$org Intermediary")"
  int_cn="${REPLY_VAL:-$org Intermediary}"
  ask 'PKI base URL' "$(_bj '.ceremony.pkiBaseUrl' 'http://pki.example.com')"
  pki_url="${REPLY_VAL:-http://pki.example.com}"
  ask 'Root cert validity (days)' "$(_bj '.ceremony.rootDays' '3650')"
  root_days="${REPLY_VAL:-3650}"
  ask 'Intermediate cert validity (days)' "$(_bj '.ceremony.intDays' '730')"
  int_days="${REPLY_VAL:-730}"

  # Root CA passphrase: secure prompt, never saved to JSON
  printf 'Root CA passphrase: ' >/dev/tty
  IFS= read -rs passphrase </dev/tty; printf '\n' >/dev/tty

  _invoke_ceremony "$ca_dir" "$org" "$country" "$root_cn" "$int_cn" \
    "$pki_url" "$root_days" "$int_days" "$passphrase"
}

_run_ceremony_auto() {
  local ca_dir="$1"
  local org country root_cn int_cn pki_url root_days int_days passphrase

  org=$(_require_bj 'ceremony.org' '.ceremony.org')
  country=$(_bj '.ceremony.country' 'US')
  root_cn=$(_bj '.ceremony.rootCn' "$org Root")
  int_cn=$(_bj '.ceremony.intCn' "$org Intermediary")
  pki_url=$(_bj '.ceremony.pkiBaseUrl' 'http://pki.example.com')
  root_days=$(_bj '.ceremony.rootDays' '3650')
  int_days=$(_bj '.ceremony.intDays' '730')

  # Passphrase from env in auto mode — never from JSON
  passphrase="${CREDO_ROOT_CA_PASSPHRASE:-}"
  if [[ -z "$passphrase" ]]; then
    die "--auto mode requires CREDO_ROOT_CA_PASSPHRASE env var to be set"
  fi

  _invoke_ceremony "$ca_dir" "$org" "$country" "$root_cn" "$int_cn" \
    "$pki_url" "$root_days" "$int_days" "$passphrase"
}

_invoke_ceremony() {
  local ca_dir="$1" org="$2" country="$3" root_cn="$4" int_cn="$5" \
        pki_url="$6" root_days="$7" int_days="$8" passphrase="$9"
  local ceremony_dir="$SCRIPT_DIR/ceremony"

  [[ -d "$ceremony_dir" ]] || die "ceremony scripts not found at $ceremony_dir"

  printf '  Running generate-openssl-cnf.sh...\n'
  "$ceremony_dir/generate-openssl-cnf.sh" \
    --ca-dir "$ca_dir" --org "$org" --country "$country" \
    --root-ecdsa-cn "$root_cn" --int-ecdsa-cn "$int_cn" \
    --pki-base-url "$pki_url" --root-days "$root_days" --int-days "$int_days"

  printf '  Running bootstrap-roots.sh...\n'
  PASSPHRASE="$passphrase" "$ceremony_dir/bootstrap-roots.sh" --ca-dir "$ca_dir"

  printf '  Running issue-intermediary.sh...\n'
  PASSPHRASE="$passphrase" "$ceremony_dir/issue-intermediary.sh" --ca-dir "$ca_dir"

  VIGIL_INT_CA_KEY_PATH="$ca_dir/int-ecdsa/private/int-ecdsa.key.pem"
  VIGIL_INT_CA_CERT_PATH="$ca_dir/int-ecdsa/certs/int-ecdsa.cert.pem"
  CA_TRUST_PATH="$ca_dir/credo-catrust.pem"

  jq '. + {ceremony: {alreadyRun: true, caDir: "'"$ca_dir"'"}}' \
    "$BOOTSTRAP_JSON" > "$BOOTSTRAP_JSON.tmp" && mv "$BOOTSTRAP_JSON.tmp" "$BOOTSTRAP_JSON"
}
```

- [ ] **Step 5: Add Phase 2 — collect service answers and generate configs**

Port `collect_answers()` and `generate_all_configs()` from `wizard/bootstrap-wizard` and `wizard/lib/config-gen.sh`. Rename references from `_df`/`_require_df`/`ORIG_DEFAULTS` to `_bj`/`_require_bj`. The bootstrap.json file replaces the old defaults file concept.

```bash
phase2_service_config() {
  printf '\nPhase 2: Service configuration\n'
  collect_answers    # from scripts/lib/config-gen.sh (ported from wizard)
  generate_all_configs "$($DRY_RUN && echo yes || echo no)"
}
```

The `collect_answers` function in `scripts/lib/config-gen.sh` must be updated to use `_bj`/`_require_bj` instead of `_df`/`_require_df`, and to call `save_bootstrap` instead of `save_defaults`. All references to `DEFAULTS_FILE`, `DEFAULTS_SAVE_PATH`, `ORIG_DEFAULTS` are replaced by `BOOTSTRAP_JSON` and `BOOTSTRAP_DEFAULT`.

- [ ] **Step 6: Add Phase 3 — bootstrap sequence**

Port the bootstrap sequence from `wizard/bootstrap-wizard` `main()` (steps 1–5: start vigil, start shepherd, start corgi, register admin, enroll corgi, restart in server mode, smoke-check). The logic is identical; only the sourcing paths change.

```bash
phase3_bootstrap() {
  printf '\nPhase 3: Bootstrap\n'

  if $DRY_RUN; then
    printf '  (dry-run — skipping service start)\n'
    return
  fi

  # ... copy steps 1–5 verbatim from wizard/bootstrap-wizard main()
  # starting from "Step 1: Vigil" through "Starting vigil and shepherd in server mode"
}
```

- [ ] **Step 7: Add Phase 4 — health verify**

```bash
phase4_verify() {
  printf '\nPhase 4: Verify\n'
  if $DRY_RUN; then printf '  (dry-run — skipping)\n'; return; fi

  local errors=0

  _check_health() {
    local name="$1" url="$2"
    local http_code
    http_code=$(curl -sk -o /dev/null -w '%{http_code}' \
      --cacert "$CA_TRUST_PATH" "$url/health" 2>/dev/null || echo 000)
    if [[ "$http_code" == "200" ]]; then
      printf '  ✓ %s\n' "$name"
    else
      printf '  ✗ %s (HTTP %s)\n' "$name" "$http_code"
      (( errors++ )) || true
    fi
  }

  _check_health "vigil"    "https://$VIGIL_HOSTNAME:$VIGIL_PORT"
  _check_health "shepherd" "https://$SHEPHERD_HOSTNAME:$SHEPHERD_DASHBOARD_PORT"
  _check_health "corgi"    "https://$CORGI_HOSTNAME:$CORGI_PORT"

  if (( errors > 0 )); then
    printf '\n  %d health check(s) failed. Check service logs.\n' "$errors"
    return 1
  fi
  printf '\n  All health checks passed.\n'
}
```

- [ ] **Step 8: Wire phases into main()**

```bash
main() {
  parse_args "$@"

  if ! command -v jq &>/dev/null; then
    die "jq is required. Install with: apt install jq  OR  brew install jq"
  fi

  printf 'Credo Bootstrap\n'
  printf '%s\n' "========================================"
  $DRY_RUN && printf '(dry-run)\n'
  $AUTO    && printf '(auto mode)\n'

  # Initialize bootstrap.json if absent
  [[ -f "$BOOTSTRAP_JSON" ]] || printf '{}' > "$BOOTSTRAP_JSON"

  phase0_read_install_config
  phase1_ceremony
  phase2_service_config
  phase3_bootstrap
  phase4_verify

  printf '\nBootstrap complete. Start services:\n'
  printf '  sudo systemctl enable --now credo-vigil credo-shepherd credo-corgi credo-dashboard\n'
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --auto)     AUTO=true; shift ;;
      --dry-run)  DRY_RUN=true; shift ;;
      --help|-h)  print_help; exit 0 ;;
      *)          die "Unknown option: $1" ;;
    esac
  done
}

print_help() {
  cat >&2 <<'EOF'
Usage: scripts/bootstrap [options]

Options:
  --auto      Non-interactive; reads from bootstrap.json / bootstrap-default.json.
              CREDO_ROOT_CA_PASSPHRASE must be set if ceremony has not run.
  --dry-run   Generate configs only; do not start services.
  --help      Show this help.
EOF
}

trap 'kill_tracked_pids' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

main "$@"
```

- [ ] **Step 9: Make executable**

```bash
chmod +x scripts/bootstrap
```

- [ ] **Step 10: shellcheck**

```bash
shellcheck -x scripts/bootstrap
```

Expected: no errors.

- [ ] **Step 11: Dry-run smoke test**

```bash
scripts/bootstrap --dry-run
```

Expected: Phase 0 prompts for targetDir (or reads .install.json), Phase 1 asks about ceremony, Phase 2 generates configs to stdout (dry-run), Phase 3 and 4 print "(dry-run — skipping)".

- [ ] **Step 12: Commit**

```bash
git add scripts/bootstrap scripts/lib/config-gen.sh
git commit -m "feat(scripts/bootstrap): new 4-phase bootstrap wizard with ceremony integration and health verify"
```

---

## Task 6: bootstrap-default.json, docs, and tier-1 checklist

**Files:**
- Create: `bootstrap-default.json`
- Update: `docs/bootstrap-guide.md`
- Update: `docs/roadmap/tier-1.md`

- [ ] **Step 1: Create bootstrap-default.json**

```bash
cat > bootstrap-default.json <<'EOF'
{
  "_comment": "Default values for scripts/bootstrap. Copy to bootstrap.json and customize. Never commit bootstrap.json.",
  "ceremony": {
    "alreadyRun": false,
    "caDir": "/var/apps/credo/ca",
    "country": "US",
    "rootCn": "Credo Root",
    "intCn": "Credo Intermediary",
    "pkiBaseUrl": "http://pki.example.com",
    "rootDays": 3650,
    "intDays": 730
  },
  "credoRoot": "/var/apps/credo",
  "domain": "example.com",
  "vigil": {
    "port": 7020,
    "identityUri": "vigil://credo/service/vigil"
  },
  "shepherd": {
    "agentPort": 7010,
    "dashboardPort": 7011,
    "identityUri": "vigil://credo/service/shepherd"
  },
  "corgi": {
    "port": 7001,
    "bootstrapPort": 7002,
    "httpChallengePort": 8080
  },
  "admin": {
    "outCert": "~/.vigil/admin.pem",
    "outKey":  "~/.vigil/admin.key"
  }
}
EOF
```

Note: `ORG` and `PKI_BASE_URL` are intentionally absent — they must always be set explicitly. `domain` is a placeholder (`example.com`) that will always be wrong and must be changed.

- [ ] **Step 2: Rewrite docs/bootstrap-guide.md**

Replace the existing multi-step manual process with the new operator flow. The new guide should describe exactly:

```markdown
# Bootstrap Guide

## Prerequisites
- cargo build --release (or use scripts/install with rustTarget)
- jq installed on the machine running the scripts
- openssl available on the machine that runs the ceremony scripts

## Full fresh deployment

1. **Generate install config**
   scripts/install init

2. **Deploy binaries**
   scripts/install all

3. **Run PKI ceremony** (recommend air-gapped machine)
   scripts/ceremony/generate-openssl-cnf.sh --ca-dir /path/to/ca --org "My Org" ...
   scripts/ceremony/bootstrap-roots.sh --ca-dir /path/to/ca
   scripts/ceremony/issue-intermediary.sh --ca-dir /path/to/ca
   # Copy /path/to/ca to $TARGET_DIR/ca on the deployment host

4. **Bootstrap services**
   scripts/bootstrap
   # (or scripts/bootstrap --auto with CREDO_ROOT_CA_PASSPHRASE set)

5. **Enable services** (on deployment host)
   sudo systemctl enable --now credo-vigil credo-shepherd credo-corgi credo-dashboard

## Re-running bootstrap on an existing deployment
   scripts/bootstrap --dry-run   # preview without changing anything

## Unattended deployment
   cp bootstrap-default.json bootstrap.json
   # Edit bootstrap.json: set credoRoot, domain, vigil/shepherd/corgi hostnames
   # Set ceremony.alreadyRun=true if CA is already in place
   export CREDO_ROOT_CA_PASSPHRASE="..."
   scripts/bootstrap --auto
```

- [ ] **Step 3: Check off tier-1 subtasks**

In `docs/roadmap/tier-1.md`, mark complete all the sub-tasks that are now done:

```bash
# Mark each completed sub-task with [x]:
# - Move ceremony scripts
# - Rename scripts/deploy → scripts/install
# - Add scripts/install init
# - User and group model
# - credo-cert group + setgid cert store
# - Systemd unit file generation
# - Minimal sudo footprint
# - Write scripts/bootstrap
# - Confirm ceremony/ca/ gitignored
# - Update docs/bootstrap-guide.md
# - Verification pass (do the end-to-end check first)
```

- [ ] **Step 4: End-to-end verification pass**

Run through the spec gate conditions:

```bash
scripts/install --help              # shows 'init' subcommand
scripts/install init                # produces valid .install.json (answer all prompts)
cat .install.json | jq .            # valid JSON, has _targetDir
scripts/install --dry-run shepherd  # dry-run shows what would be deployed
scripts/ceremony/generate-openssl-cnf.sh --help   # works from new location
scripts/bootstrap --dry-run         # reaches Phase 4 without errors
```

- [ ] **Step 5: Commit**

```bash
git add bootstrap-default.json docs/bootstrap-guide.md docs/roadmap/tier-1.md
git commit -m "docs: bootstrap-default.json, updated bootstrap-guide, tier-1 subtasks checked off"
```

---

## Verification

End-to-end gate (from the spec): fresh clone → `cargo build` → `scripts/install init` → `scripts/install` → ceremony → `scripts/bootstrap` → `systemctl start` all three → all health checks green, under 15 minutes wall-clock.

Minimum verification before PR:
1. `shellcheck -x scripts/install scripts/bootstrap scripts/ceremony/*.sh` — no errors
2. `scripts/install --help` — shows `init` subcommand
3. `scripts/install init` — produces valid `.install.json`
4. `scripts/ceremony/generate-openssl-cnf.sh --help` — works from new location
5. `scripts/bootstrap --dry-run` — runs all 4 phases without error
6. `scripts/install --dry-run all` — dry-run plan prints without error
