#!/usr/bin/env bash
# Remove credo systemd units, service users, and service groups from this host.
# The data directory (/var/apps/credo/ or equivalent) is NOT touched.
#
# Usage:
#   sudo ./uninstall.sh [options]
#
# Options:
#   --dry-run          Print what would change; make no changes.
#   --services LIST    Comma-separated services to remove (default: corgi,shepherd,vigil,dashboard).
#   -h, --help         Show this help.

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
DRY_RUN=0
SERVICES="corgi shepherd vigil dashboard"

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage:
  $SCRIPT_NAME [options]

Options:
  --dry-run          Print what would change; make no changes.
  --services LIST    Comma-separated services (default: corgi,shepherd,vigil,dashboard).
  -h, --help         Show this help.

What is removed:
  - systemd units:  credo-<svc>.service (stopped, disabled, unit file deleted)
  - system users:   corgi, shepherd, vigil, dashboard
  - system groups:  per-service primary groups; credo-cert (if empty); credo (if exists and empty)

What is NOT removed:
  - The data directory (/var/apps/credo/ or equivalent) — left for the operator.

Examples:
  sudo $SCRIPT_NAME
  sudo $SCRIPT_NAME --dry-run
  sudo $SCRIPT_NAME --services corgi
  sudo $SCRIPT_NAME --services corgi,shepherd --dry-run
EOF
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --services)
            [[ -z "${2:-}" ]] && { echo "Error: --services requires a value" >&2; exit 1; }
            SERVICES="${2//,/ }"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Error: unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

if [[ "$DRY_RUN" -eq 0 && "$EUID" -ne 0 ]]; then
    echo "Error: must run as root (use sudo, or add --dry-run to preview)" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Dry-run-aware primitives
# ---------------------------------------------------------------------------

do_run() {
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "  $*"
    else
        "$@"
    fi
}

do_rm() {
    local path="$1"
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "  rm $path"
    else
        rm -f "$path"
    fi
}

# ---------------------------------------------------------------------------
# Helper: check if a group has any members
# Returns 0 (true) if empty or not found, 1 if it has members.
# ---------------------------------------------------------------------------

group_is_empty() {
    local grp="$1"
    getent group "$grp" >/dev/null 2>&1 || return 0
    local members
    members=$(getent group "$grp" | cut -d: -f4)
    [[ -z "$members" ]]
}

# ---------------------------------------------------------------------------
# Summary header
# ---------------------------------------------------------------------------

echo "credo uninstall"
echo "  services: ${SERVICES// /,}"
[[ "$DRY_RUN" -eq 1 ]] && echo "  [DRY RUN — no changes will be made]"
echo ""

# ---------------------------------------------------------------------------
# Phase 1: systemd
# ---------------------------------------------------------------------------

echo "--- Phase 1: systemd ---"

any_unit_found=0
for svc in $SERVICES; do
    unit="credo-${svc}.service"
    unit_file="/etc/systemd/system/${unit}"

    echo "[$svc] systemd unit: $unit"

    # Stop if active
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
        echo "  stopping $unit"
        do_run systemctl stop "$unit"
    else
        echo "  $unit is not active — skip stop"
    fi

    # Disable if enabled
    if systemctl is-enabled --quiet "$unit" 2>/dev/null; then
        echo "  disabling $unit"
        do_run systemctl disable "$unit"
    else
        echo "  $unit is not enabled — skip disable"
    fi

    # Remove unit file
    if [[ -f "$unit_file" ]]; then
        echo "  removing $unit_file"
        do_rm "$unit_file"
        any_unit_found=1
    else
        echo "  $unit_file not found — skip"
    fi

    echo ""
done

if [[ "$any_unit_found" -eq 1 || "$DRY_RUN" -eq 1 ]]; then
    echo "[systemd] daemon-reload"
    do_run systemctl daemon-reload
    echo "[systemd] reset-failed"
    do_run systemctl reset-failed
fi
echo ""

# ---------------------------------------------------------------------------
# Phase 2: users
# ---------------------------------------------------------------------------

echo "--- Phase 2: users ---"

for svc in $SERVICES; do
    if id "$svc" >/dev/null 2>&1; then
        echo "[$svc] removing user $svc"
        do_run userdel "$svc"
    else
        echo "[$svc] user $svc not found — skip"
    fi
done
echo ""

# ---------------------------------------------------------------------------
# Phase 3: groups
# ---------------------------------------------------------------------------

echo "--- Phase 3: groups ---"

# Per-service primary groups
for svc in $SERVICES; do
    if getent group "$svc" >/dev/null 2>&1; then
        if group_is_empty "$svc"; then
            echo "[$svc] removing group $svc"
            do_run groupdel "$svc"
        else
            echo "[$svc] group $svc still has members — skipping (remove manually if needed)"
        fi
    else
        echo "[$svc] group $svc not found — skip"
    fi
done

# credo-cert — shared cert-consumer group
if getent group credo-cert >/dev/null 2>&1; then
    if group_is_empty credo-cert; then
        echo "[shared] removing group credo-cert"
        do_run groupdel credo-cert
    else
        echo "[shared] group credo-cert still has members — skipping (remove manually if needed)"
    fi
else
    echo "[shared] group credo-cert not found — skip"
fi

# credo — legacy shared primary group (old INSTALL.md setup)
if getent group credo >/dev/null 2>&1; then
    if group_is_empty credo; then
        echo "[legacy] removing group credo"
        do_run groupdel credo
    else
        echo "[legacy] group credo still has members — skipping (remove manually if needed)"
    fi
else
    echo "[legacy] group credo not found — skip"
fi

echo ""

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

echo "Uninstall complete."
echo ""
echo "Note: the credo data directory was not removed."
echo "      Delete it manually when you are ready:"
echo "      sudo rm -rf /var/apps/credo   # or your configured path"
