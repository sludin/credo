#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VIGIL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

usage() {
  cat <<'EOF'
Issue a new Vigil ECDSA intermediate certificate from the offline root CA.

This is a ceremony script. By default it runs interactively with step-by-step
prompts and appends an entry to ca/ca-audit.log. Use --non-interactive for
dev or CI environments.

Usage:
  issue-intermediary.sh [options]

Options:
  --name <name>                  Artifact base name
                                 default: auto int-ecdsa-YYYYMMDD (with -N on collision)
  --root-dir <path>              Root CA dir (default: ./ca/root-ecdsa)
  --int-dir <path>               Intermediate dir (default: ./ca/int-ecdsa)
  --root-config <path>           Root openssl.cnf (default: <root-dir>/openssl.cnf)
  --int-config <path>            Intermediate openssl.cnf (default: <int-dir>/openssl.cnf)
  --subject <dn>                 CSR subject (default: use [req]/[dn] from --int-config)
  --days <n>                     Validity days (default: 730)
  --extensions <name>            openssl.cnf extension section (default: v3_intermediate_ca)
  --ec-curve <name>              EC curve for intermediate key (default: prime256v1)
  --root-cert <path>             Root cert to append to chain
                                 default: <root-dir>/certs/root-ecdsa.cert.pem
  --no-set-active                Skip updating active symlinks after issuance
  --non-interactive              Skip ceremony prompts (dev/CI mode)
  --force                        Overwrite output files if they already exist
  --dry-run                      Print commands without changing files
  -h, --help                     Show help

Notes:
  If the root CA key is passphrase-protected, OpenSSL will prompt for it
  during signing.

  After issuance, move the root private key to offline storage — it is not
  needed on the Vigil host.

Examples:
  ./scripts/issue-intermediary.sh
  ./scripts/issue-intermediary.sh --name int-ecdsa-2026q2
  ./scripts/issue-intermediary.sh --ec-curve secp384r1 --days 365
  ./scripts/issue-intermediary.sh --non-interactive --force
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

default_intermediate_name() {
  local int_dir="$1"
  local day base candidate n
  day="$(date +%Y%m%d)"
  base="int-ecdsa-${day}"
  candidate="$base"

  if [[ ! -e "${int_dir}/private/${candidate}.key.pem"  && \
        ! -e "${int_dir}/csr/${candidate}.csr.pem"       && \
        ! -e "${int_dir}/certs/${candidate}.cert.pem"    && \
        ! -e "${int_dir}/certs/${candidate}.chain.pem" ]]; then
    printf '%s\n' "$candidate"; return 0
  fi

  n=1
  while true; do
    candidate="${base}-${n}"
    if [[ ! -e "${int_dir}/private/${candidate}.key.pem"  && \
          ! -e "${int_dir}/csr/${candidate}.csr.pem"       && \
          ! -e "${int_dir}/certs/${candidate}.cert.pem"    && \
          ! -e "${int_dir}/certs/${candidate}.chain.pem" ]]; then
      printf '%s\n' "$candidate"; return 0
    fi
    n=$((n + 1))
  done
}

append_audit() {
  local action="$1"; shift
  [[ "$DRY_RUN" == "true" ]] && return 0
  local ts host operator ca_dir entry
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date +%Y-%m-%dT%H:%M:%SZ)"
  host="$(hostname 2>/dev/null || echo unknown)"
  operator="$(id -un 2>/dev/null || echo unknown)"
  ca_dir="$(dirname "$ROOT_DIR")"
  entry="{\"ts\":\"${ts}\",\"host\":\"${host}\",\"operator\":\"${operator}\",\"action\":\"${action}\""
  for kv in "$@"; do
    entry="${entry},\"${kv%%=*}\":\"${kv#*=}\""
  done
  entry="${entry}}"
  printf '%s\n' "$entry" >> "${ca_dir}/ca-audit.log"
}

# ── Argument defaults ─────────────────────────────────────────────────────────

NAME=""
ROOT_DIR_ARG=""
INT_DIR_ARG=""
ROOT_CONFIG_ARG=""
INT_CONFIG_ARG=""
SUBJECT=""
DAYS="730"
EXTENSIONS="v3_intermediate_ca"
EC_CURVE="prime256v1"
ROOT_CERT_ARG=""
SET_ACTIVE="true"
NON_INTERACTIVE="false"
FORCE="false"
DRY_RUN="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)           NAME="${2:-}"; shift 2 ;;
    --root-dir)       ROOT_DIR_ARG="${2:-}"; shift 2 ;;
    --int-dir)        INT_DIR_ARG="${2:-}"; shift 2 ;;
    --root-config)    ROOT_CONFIG_ARG="${2:-}"; shift 2 ;;
    --int-config)     INT_CONFIG_ARG="${2:-}"; shift 2 ;;
    --subject)        SUBJECT="${2:-}"; shift 2 ;;
    --days)           DAYS="${2:-}"; shift 2 ;;
    --extensions)     EXTENSIONS="${2:-}"; shift 2 ;;
    --ec-curve)       EC_CURVE="${2:-}"; shift 2 ;;
    --root-cert)      ROOT_CERT_ARG="${2:-}"; shift 2 ;;
    --no-set-active)  SET_ACTIVE="false"; shift ;;
    --non-interactive) NON_INTERACTIVE="true"; shift ;;
    --force)          FORCE="true"; shift ;;
    --dry-run)        DRY_RUN="true"; shift ;;
    -h|--help)        usage; exit 0 ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage; exit 2
      ;;
  esac
done

require_cmd openssl

ROOT_DIR="${ROOT_DIR_ARG:-${VIGIL_DIR}/ca/root-ecdsa}"
INT_DIR="${INT_DIR_ARG:-${VIGIL_DIR}/ca/int-ecdsa}"
ROOT_CONFIG="${ROOT_CONFIG_ARG:-${ROOT_DIR}/openssl.cnf}"
INT_CONFIG="${INT_CONFIG_ARG:-${INT_DIR}/openssl.cnf}"
ROOT_CERT="${ROOT_CERT_ARG:-${ROOT_DIR}/certs/root-ecdsa.cert.pem}"

if [[ -n "$NAME" ]]; then
  EFFECTIVE_NAME="$NAME"
else
  EFFECTIVE_NAME="$(default_intermediate_name "$INT_DIR")"
fi

[[ -f "$ROOT_CONFIG" ]] || { echo "ERROR: missing root openssl.cnf: $ROOT_CONFIG" >&2; exit 1; }
[[ -f "$INT_CONFIG"  ]] || { echo "ERROR: missing intermediate openssl.cnf: $INT_CONFIG" >&2; exit 1; }
[[ -f "$ROOT_CERT"   ]] || { echo "ERROR: missing root cert: $ROOT_CERT" >&2; exit 1; }

config_has_section "$INT_CONFIG" "req" || {
  echo "ERROR: [$INT_CONFIG] missing [req] section" >&2; exit 1
}
if [[ -z "$SUBJECT" ]]; then
  config_has_section "$INT_CONFIG" "dn" || {
    echo "ERROR: no --subject provided and [$INT_CONFIG] missing [dn] section" >&2; exit 1
  }
fi
config_has_section "$INT_CONFIG" "$EXTENSIONS" || {
  echo "ERROR: [$INT_CONFIG] missing extension section [${EXTENSIONS}]" >&2; exit 1
}

KEY_PATH="${INT_DIR}/private/${EFFECTIVE_NAME}.key.pem"
CSR_PATH="${INT_DIR}/csr/${EFFECTIVE_NAME}.csr.pem"
CERT_PATH="${INT_DIR}/certs/${EFFECTIVE_NAME}.cert.pem"
CHAIN_PATH="${INT_DIR}/certs/${EFFECTIVE_NAME}.chain.pem"

if [[ "$FORCE" != "true" ]]; then
  for p in "$KEY_PATH" "$CSR_PATH" "$CERT_PATH" "$CHAIN_PATH"; do
    [[ ! -e "$p" ]] || { echo "ERROR: output exists: $p (use --force)" >&2; exit 1; }
  done
fi

# ── Ceremony ──────────────────────────────────────────────────────────────────

APPROX_EXPIRY="$(date -d "+${DAYS} days" +%Y-%m-%d 2>/dev/null \
  || date -v "+${DAYS}d" +%Y-%m-%d 2>/dev/null \
  || echo '(check cert after generation)')"

if [[ "$NON_INTERACTIVE" != "true" ]]; then
  echo ""
  echo "================================================================"
  echo "  VIGIL INTERMEDIATE CA ISSUANCE"
  echo "================================================================"
  echo ""
  echo "  Algorithm  : ECDSA (${EC_CURVE})"
  echo "  Name       : ${EFFECTIVE_NAME}"
  echo "  Output     : ${INT_DIR}/"
  echo "  Validity   : ${DAYS} days (expires approx. ${APPROX_EXPIRY})"
  echo "  Root CA    : ${ROOT_CERT}"
  echo ""

  while true; do
    printf "  [1/3] Type 'ISSUE INTERMEDIATE' to proceed (or Ctrl-C to abort): "
    read -r CONFIRM
    if [[ "$CONFIRM" == "ISSUE INTERMEDIATE" ]]; then
      break
    fi
    echo "  Input did not match. Try again (or press Ctrl-C to abort)." >&2
  done
  echo ""
  echo "  [2/3] Generating intermediate key, CSR, and certificate..."
  echo "        (If root key is passphrase-protected, OpenSSL will prompt for it.)"
  echo ""
fi

# ── Ensure CA database dirs ───────────────────────────────────────────────────

if [[ "$DRY_RUN" == "true" ]]; then
  echo "+ mkdir -p ${ROOT_DIR}/{certs,crl,newcerts,private,csr}"
  [[ -f "${ROOT_DIR}/index.txt" ]] || echo "+ : > ${ROOT_DIR}/index.txt"
  [[ -f "${ROOT_DIR}/serial"    ]] || echo "+ echo 1000 > ${ROOT_DIR}/serial"
  [[ -f "${ROOT_DIR}/crlnumber" ]] || echo "+ echo 1000 > ${ROOT_DIR}/crlnumber"
else
  mkdir -p "${ROOT_DIR}"/{certs,crl,newcerts,private,csr}
  [[ -f "${ROOT_DIR}/index.txt" ]] || : > "${ROOT_DIR}/index.txt"
  [[ -f "${ROOT_DIR}/serial"    ]] || echo "1000" > "${ROOT_DIR}/serial"
  [[ -f "${ROOT_DIR}/crlnumber" ]] || echo "1000" > "${ROOT_DIR}/crlnumber"
fi

run mkdir -p "${INT_DIR}/private" "${INT_DIR}/csr" "${INT_DIR}/certs"

# ── Key, CSR, certificate ─────────────────────────────────────────────────────

run openssl ecparam -name "$EC_CURVE" -genkey -noout -out "$KEY_PATH"
run chmod 600 "$KEY_PATH"

if [[ -n "$SUBJECT" ]]; then
  run openssl req -new -sha256 \
    -config "$INT_CONFIG" \
    -key "$KEY_PATH" \
    -out "$CSR_PATH" \
    -subj "$SUBJECT"
else
  run openssl req -new -sha256 \
    -config "$INT_CONFIG" \
    -key "$KEY_PATH" \
    -out "$CSR_PATH"
fi

if [[ -n "${CREDO_ROOT_CA_PASSPHRASE:-}" ]]; then
  run openssl ca -batch \
    -config "$ROOT_CONFIG" \
    -extfile "$INT_CONFIG" \
    -extensions "$EXTENSIONS" \
    -days "$DAYS" \
    -notext \
    -passin env:CREDO_ROOT_CA_PASSPHRASE \
    -in "$CSR_PATH" \
    -out "$CERT_PATH"
else
  run openssl ca -batch \
    -config "$ROOT_CONFIG" \
    -extfile "$INT_CONFIG" \
    -extensions "$EXTENSIONS" \
    -days "$DAYS" \
    -notext \
    -in "$CSR_PATH" \
    -out "$CERT_PATH"
fi

if [[ "$DRY_RUN" == "true" ]]; then
  echo "+ cat $CERT_PATH $ROOT_CERT > $CHAIN_PATH"
else
  cat "$CERT_PATH" "$ROOT_CERT" > "$CHAIN_PATH"
fi

# ── Active symlinks ───────────────────────────────────────────────────────────

if [[ "$SET_ACTIVE" == "true" ]]; then
  run ln -sfn "$KEY_PATH"   "${INT_DIR}/private/int-ecdsa.key.pem"
  run ln -sfn "$CERT_PATH"  "${INT_DIR}/certs/int-ecdsa.cert.pem"
  run ln -sfn "$CHAIN_PATH" "${INT_DIR}/certs/int-ecdsa.chain.pem"
fi

# ── Post-issuance summary ─────────────────────────────────────────────────────

FINGERPRINT=""
NOT_AFTER=""
if [[ "$DRY_RUN" != "true" ]]; then
  FINGERPRINT="$(openssl x509 -in "$CERT_PATH" -noout -fingerprint -sha256 2>/dev/null | sed 's/^.*=//')"
  NOT_AFTER="$(openssl x509 -in "$CERT_PATH" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')"
fi

if [[ "$NON_INTERACTIVE" != "true" ]]; then
  echo "  [3/3] Intermediate CA issued."
  echo "        Key         : ${KEY_PATH}"
  echo "        CSR         : ${CSR_PATH}"
  echo "        Cert        : ${CERT_PATH}"
  echo "        Chain       : ${CHAIN_PATH}"
  [[ -n "$FINGERPRINT" ]] && echo "        Fingerprint : ${FINGERPRINT}"
  [[ -n "$NOT_AFTER"   ]] && echo "        Expires     : ${NOT_AFTER}"
  if [[ "$SET_ACTIVE" == "true" ]]; then
    echo "        Symlinks    : int-ecdsa.{key,cert,chain}.pem → ${EFFECTIVE_NAME}"
  fi
  echo ""
  echo "  ============================================================"
  echo "  Root signing is complete. Move the root CA private key"
  echo "  to offline storage — it is not needed on the Vigil host:"
  echo ""
  echo "  Root key dir: ${ROOT_DIR}/private/"
  echo ""
  if [[ "$SET_ACTIVE" == "true" ]]; then
    echo "  Vigil can now use the active intermediate:"
    echo "    cert: ${INT_DIR}/certs/int-ecdsa.cert.pem"
    echo "    key : ${INT_DIR}/private/int-ecdsa.key.pem"
  fi
  echo "  ============================================================"
  echo ""
fi

if [[ "$DRY_RUN" != "true" ]]; then
  append_audit "intermediate-issued" \
    "algo=ecdsa" \
    "name=${EFFECTIVE_NAME}" \
    "days=${DAYS}" \
    "setActive=${SET_ACTIVE}" \
    "fingerprint=${FINGERPRINT}"
fi

echo "Issued intermediate certificate."
echo "  name        : ${EFFECTIVE_NAME}"
echo "  rootDir     : ${ROOT_DIR}"
echo "  intDir      : ${INT_DIR}"
echo "  keyPath     : ${KEY_PATH}"
echo "  certPath    : ${CERT_PATH}"
echo "  chainPath   : ${CHAIN_PATH}"
[[ -n "$FINGERPRINT" ]] && echo "  fingerprint : ${FINGERPRINT}"
[[ -n "$NOT_AFTER"   ]] && echo "  expires     : ${NOT_AFTER}"
echo "  setActive   : ${SET_ACTIVE}"
echo "  dryRun      : ${DRY_RUN}"
[[ "$DRY_RUN" != "true" ]] && echo "  auditLog    : $(dirname "$ROOT_DIR")/ca-audit.log"
