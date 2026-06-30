#!/usr/bin/env bash
set -euo pipefail


SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CEREMONY_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

usage() {
  cat <<'EOF'
Bootstrap a root ECDSA CA key and self-signed root certificate for Vigil.

This is a ceremony script. By default it runs interactively with step-by-step
prompts and appends an entry to ca/ca-audit.log. Use --non-interactive for
dev or CI environments.

Usage:
  bootstrap-roots.sh [options]

Options:
  --ca-dir <path>                CA base dir (default: ./ca)
  --root-ecdsa-config <path>     Override root-ecdsa openssl.cnf path
                                 default: <ca-dir>/root-ecdsa/openssl.cnf
  --root-days <n>                Root cert validity override
                                 default: [CA_default].default_days from openssl.cnf
  --ec-curve <name>              EC curve (default: prime256v1)
  --no-passphrase                Generate root key without AES-256 encryption.
                                 Default is to prompt for a passphrase.
                                 Required when using --non-interactive.
  --non-interactive              Skip ceremony prompts (dev/CI mode).
                                 Implies --no-passphrase.
  --force                        Overwrite existing root key/cert outputs
  --dry-run                      Print commands without changing files
  -h, --help                     Show help

Security notes:
  By default the root key is encrypted with AES-256. Use --no-passphrase only
  for dev/CI environments. For production, an HSM is strongly recommended.

  After running issue-intermediary.sh, move the root private key to offline
  storage — it is not needed on the Vigil host.

Examples:
  ./scripts/bootstrap-roots.sh
  ./scripts/bootstrap-roots.sh --no-passphrase --non-interactive --force
  ./scripts/bootstrap-roots.sh --ec-curve secp384r1
EOF
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: required command not found: $1" >&2
    exit 1
  }
}

run() {
  if [[ "$DRY_RUN" == "true" ]]; then
    printf '+ '
    printf '%q ' "$@"
    printf '\n'
    return 0
  fi
  "$@"
}

abspath() {
  local p="$1"
  if [[ "$p" != /* ]]; then p="$(pwd)/$p"; fi
  while [[ "$p" == *"//"*  ]]; do p="${p//\/\//\/}";   done
  while [[ "$p" == *"/./"* ]]; do p="${p//\/\.\//\/}"; done
  if   [[ "$p" == */. ]];      then p="${p%/.}";        fi
  printf '%s\n' "$p"
}

config_has_section() {
  local cfg="$1" section="$2"
  grep -Eq "^[[:space:]]*\[[[:space:]]*${section//./\\.}[[:space:]]*\][[:space:]]*$" "$cfg"
}

config_default_days() {
  local cfg="$1"
  awk '
    BEGIN { in_ca = 0 }
    /^[[:space:]]*\[/ {
      in_ca = ($0 ~ /^[[:space:]]*\[[[:space:]]*CA_default[[:space:]]*\][[:space:]]*$/)
      next
    }
    in_ca && /^[[:space:]]*default_days[[:space:]]*=/ {
      val = $0
      sub(/^[[:space:]]*default_days[[:space:]]*=[[:space:]]*/, "", val)
      sub(/[[:space:]]*(#|;).*$/, "", val)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", val)
      print val; exit
    }
  ' "$cfg"
}

init_ca_db() {
  local root_dir="$1"
  run mkdir -p "${root_dir}/certs" "${root_dir}/crl" "${root_dir}/newcerts" "${root_dir}/private"
  if [[ "$DRY_RUN" == "true" ]]; then
    [[ -f "${root_dir}/index.txt" ]] || echo "+ : > ${root_dir}/index.txt"
    [[ -f "${root_dir}/serial"    ]] || echo "+ echo 1000 > ${root_dir}/serial"
    [[ -f "${root_dir}/crlnumber" ]] || echo "+ echo 1000 > ${root_dir}/crlnumber"
    return 0
  fi
  [[ -f "${root_dir}/index.txt" ]] || : > "${root_dir}/index.txt"
  [[ -f "${root_dir}/serial"    ]] || echo "1000" > "${root_dir}/serial"
  [[ -f "${root_dir}/crlnumber" ]] || echo "1000" > "${root_dir}/crlnumber"
}

append_audit() {
  local action="$1"; shift
  [[ "$DRY_RUN" == "true" ]] && return 0
  local ts host operator entry
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date +%Y-%m-%dT%H:%M:%SZ)"
  host="$(hostname 2>/dev/null || echo unknown)"
  operator="$(id -un 2>/dev/null || echo unknown)"
  entry="{\"ts\":\"${ts}\",\"host\":\"${host}\",\"operator\":\"${operator}\",\"action\":\"${action}\""
  for kv in "$@"; do
    entry="${entry},\"${kv%%=*}\":\"${kv#*=}\""
  done
  entry="${entry}}"
  printf '%s\n' "$entry" >> "${CA_DIR}/ca-audit.log"
}

# ── Argument defaults ────────────────────────────────────────────────────────

CA_DIR="${CEREMONY_DIR}/ca"
ROOT_ECDSA_CONFIG=""
ROOT_DAYS=""
EC_CURVE="prime256v1"
PASSPHRASE="true"
NON_INTERACTIVE="false"
FORCE="false"
DRY_RUN="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ca-dir)            CA_DIR="${2:-}"; shift 2 ;;
    --root-ecdsa-config) ROOT_ECDSA_CONFIG="${2:-}"; shift 2 ;;
    --root-days)         ROOT_DAYS="${2:-}"; shift 2 ;;
    --ec-curve)          EC_CURVE="${2:-}"; shift 2 ;;
    --no-passphrase)     PASSPHRASE="false"; shift ;;
    --non-interactive)   NON_INTERACTIVE="true"; PASSPHRASE="false"; shift ;;
    --force)             FORCE="true"; shift ;;
    --dry-run)           DRY_RUN="true"; shift ;;
    -h|--help)           usage; exit 0 ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage; exit 2
      ;;
  esac
done

# CREDO_ROOT_CA_PASSPHRASE env var enables non-interactive passphrase mode
if [[ -n "${CREDO_ROOT_CA_PASSPHRASE:-}" && "$PASSPHRASE" == "true" ]]; then
  NON_INTERACTIVE="true"
fi

if [[ "$PASSPHRASE" == "true" && "$NON_INTERACTIVE" == "true" && -z "${CREDO_ROOT_CA_PASSPHRASE:-}" ]]; then
  echo "ERROR: passphrase requires interactive input; use --no-passphrase with --non-interactive," >&2
  echo "       or set CREDO_ROOT_CA_PASSPHRASE env var for unattended operation" >&2
  exit 2
fi

require_cmd openssl

CA_DIR="$(abspath "$CA_DIR")"
ROOT_ECDSA_DIR="${CA_DIR}/root-ecdsa"

[[ -z "$ROOT_ECDSA_CONFIG" ]] && ROOT_ECDSA_CONFIG="${ROOT_ECDSA_DIR}/openssl.cnf"
ROOT_ECDSA_CONFIG="$(abspath "$ROOT_ECDSA_CONFIG")"

[[ -f "$ROOT_ECDSA_CONFIG" ]] || {
  echo "ERROR: missing root-ecdsa openssl.cnf: $ROOT_ECDSA_CONFIG" >&2
  echo "       run generate-openssl-cnf.sh first" >&2
  exit 1
}

for section in req dn v3_root_ca; do
  config_has_section "$ROOT_ECDSA_CONFIG" "$section" || {
    echo "ERROR: [$ROOT_ECDSA_CONFIG] missing [${section}] section" >&2
    exit 1
  }
done

KEY_PATH="${ROOT_ECDSA_DIR}/private/root-ecdsa.key.pem"
CERT_PATH="${ROOT_ECDSA_DIR}/certs/root-ecdsa.cert.pem"

if [[ "$FORCE" != "true" && "$DRY_RUN" != "true" ]]; then
  [[ ! -e "$KEY_PATH"  ]] || { echo "ERROR: output exists: $KEY_PATH (use --force)" >&2; exit 1; }
  [[ ! -e "$CERT_PATH" ]] || { echo "ERROR: output exists: $CERT_PATH (use --force)" >&2; exit 1; }
fi

DAYS_EFFECTIVE="$ROOT_DAYS"
[[ -z "$DAYS_EFFECTIVE" ]] && DAYS_EFFECTIVE="$(config_default_days "$ROOT_ECDSA_CONFIG")"
if ! [[ "$DAYS_EFFECTIVE" =~ ^[0-9]+$ ]] || [[ "$DAYS_EFFECTIVE" -le 0 ]]; then
  echo "ERROR: cannot resolve root validity days; set --root-days or define default_days in $ROOT_ECDSA_CONFIG" >&2
  exit 1
fi

# ── Ceremony ─────────────────────────────────────────────────────────────────

APPROX_EXPIRY="$(date -d "+${DAYS_EFFECTIVE} days" +%Y-%m-%d 2>/dev/null \
  || date -v "+${DAYS_EFFECTIVE}d" +%Y-%m-%d 2>/dev/null \
  || echo '(check cert after generation)')"

if [[ "$NON_INTERACTIVE" != "true" ]]; then
  echo ""
  echo "================================================================"
  echo "  VIGIL ROOT CA CEREMONY"
  echo "================================================================"
  echo ""
  echo "  Algorithm  : ECDSA (${EC_CURVE})"
  echo "  Output     : ${ROOT_ECDSA_DIR}/"
  echo "  Config     : ${ROOT_ECDSA_CONFIG}"
  echo "  Validity   : ${DAYS_EFFECTIVE} days (expires approx. ${APPROX_EXPIRY})"
  echo "  Passphrase : $([ "$PASSPHRASE" == "true" ] && echo yes || echo no)"
  echo ""

  if [[ "$PASSPHRASE" != "true" ]]; then
    echo "  ============================================================"
    echo "  WARNING: Root key will be generated WITHOUT a passphrase."
    echo "  NEVER store an unencrypted root key on a networked host."
    echo "  For production use, an HSM is strongly recommended."
    echo "  ============================================================"
    echo ""
  fi

  printf "  [1/3] Type 'GENERATE ROOT CA' to proceed (or Ctrl-C to abort): "
  read -r CONFIRM
  if [[ "$CONFIRM" != "GENERATE ROOT CA" ]]; then
    echo "Aborted." >&2
    exit 1
  fi
  echo ""
  echo "  [2/3] Generating root CA key and certificate..."
  if [[ "$PASSPHRASE" == "true" ]]; then
    echo "        OpenSSL will prompt for a passphrase (enter twice to confirm)."
    echo ""
  fi
fi

# ── Key + certificate generation ─────────────────────────────────────────────

init_ca_db "$ROOT_ECDSA_DIR"

if [[ "$PASSPHRASE" == "true" ]]; then
  if [[ -n "${CREDO_ROOT_CA_PASSPHRASE:-}" ]]; then
    run openssl genpkey \
      -algorithm EC \
      -pkeyopt "ec_paramgen_curve:${EC_CURVE}" \
      -aes256 \
      -pass env:CREDO_ROOT_CA_PASSPHRASE \
      -out "$KEY_PATH"
  else
    run openssl genpkey \
      -algorithm EC \
      -pkeyopt "ec_paramgen_curve:${EC_CURVE}" \
      -aes256 \
      -out "$KEY_PATH"
  fi
else
  run openssl ecparam -name "$EC_CURVE" -genkey -noout -out "$KEY_PATH"
fi

run chmod 600 "$KEY_PATH"

if [[ "$PASSPHRASE" == "true" && "$NON_INTERACTIVE" != "true" ]]; then
  echo ""
  echo "        OpenSSL will prompt for the passphrase to sign the certificate."
  echo ""
fi

if [[ -n "${CREDO_ROOT_CA_PASSPHRASE:-}" && "$PASSPHRASE" == "true" ]]; then
  run openssl req -new -x509 \
    -config "$ROOT_ECDSA_CONFIG" \
    -extensions v3_root_ca \
    -key "$KEY_PATH" \
    -passin env:CREDO_ROOT_CA_PASSPHRASE \
    -out "$CERT_PATH" \
    -days "$DAYS_EFFECTIVE" \
    -sha256
else
  run openssl req -new -x509 \
    -config "$ROOT_ECDSA_CONFIG" \
    -extensions v3_root_ca \
    -key "$KEY_PATH" \
    -out "$CERT_PATH" \
    -days "$DAYS_EFFECTIVE" \
    -sha256
fi

# ── Post-ceremony summary ─────────────────────────────────────────────────────

FINGERPRINT=""
NOT_AFTER=""
if [[ "$DRY_RUN" != "true" ]]; then
  FINGERPRINT="$(openssl x509 -in "$CERT_PATH" -noout -fingerprint -sha256 2>/dev/null | sed 's/^.*=//')"
  NOT_AFTER="$(openssl x509 -in "$CERT_PATH" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')"
fi

if [[ "$NON_INTERACTIVE" != "true" ]]; then
  echo ""
  echo "  [3/3] Root CA generated."
  echo "        Key         : ${KEY_PATH}"
  echo "        Cert        : ${CERT_PATH}"
  [[ -n "$FINGERPRINT" ]] && echo "        Fingerprint : ${FINGERPRINT}"
  [[ -n "$NOT_AFTER"   ]] && echo "        Expires     : ${NOT_AFTER}"
  echo ""
  echo "  ============================================================"
  echo "  NEXT STEP: Run issue-intermediary.sh to create the signing"
  echo "  intermediate, then move the root private key offline:"
  echo ""
  echo "  Root key dir: ${ROOT_ECDSA_DIR}/private/"
  echo ""
  echo "  The root key should NOT remain on the Vigil host."
  echo "  ============================================================"
  echo ""
fi

if [[ "$DRY_RUN" != "true" ]]; then
  append_audit "root-generated" \
    "algo=ecdsa" \
    "curve=${EC_CURVE}" \
    "days=${DAYS_EFFECTIVE}" \
    "passphrase=${PASSPHRASE}" \
    "fingerprint=${FINGERPRINT}"
fi

echo "Root bootstrap complete."
echo "  caDir       : ${CA_DIR}"
echo "  keyPath     : ${KEY_PATH}"
echo "  certPath    : ${CERT_PATH}"
[[ -n "$FINGERPRINT" ]] && echo "  fingerprint : ${FINGERPRINT}"
[[ -n "$NOT_AFTER"   ]] && echo "  expires     : ${NOT_AFTER}"
echo "  rootDays    : ${DAYS_EFFECTIVE}"
echo "  passphrase  : ${PASSPHRASE}"
echo "  dryRun      : ${DRY_RUN}"
[[ "$DRY_RUN" != "true" ]] && echo "  auditLog    : ${CA_DIR}/ca-audit.log"
