#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VIGIL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

usage() {
  cat <<'EOF'
Revoke an intermediate certificate in the offline root CA DB and regenerate CRL.

Usage:
  revoke-intermediary.sh --algo rsa|ecdsa --cert <path> [options]

Required:
  --algo <rsa|ecdsa>             Root family
  --cert <path>                  Intermediate cert PEM to revoke

Optional:
  --root-dir <path>              Root CA dir (default: ./ca/root-<algo>)
  --reason <code>                CRL reason (default: cessationOfOperation)
                                 examples: keyCompromise, superseded, cessationOfOperation
  --crl-out <path>               CRL output path (default: <root-dir>/crl/root-<algo>.crl.pem)
  --skip-verify                  Skip CRL text verification output
  --dry-run                      Print commands without changing files
  -h, --help                     Show help

Examples:
  ./scripts/revoke-intermediary.sh --algo rsa --cert ./ca/int-rsa/certs/int-rsa-2026q1.cert.pem
  ./scripts/revoke-intermediary.sh --algo ecdsa --cert ./ca/int-ecdsa/certs/int-ecdsa-2026q1.cert.pem --reason superseded
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

ALGO=""
CERT_PATH=""
ROOT_DIR=""
REASON="cessationOfOperation"
CRL_OUT=""
SKIP_VERIFY="false"
DRY_RUN="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --algo) ALGO="${2:-}"; shift 2 ;;
    --cert) CERT_PATH="${2:-}"; shift 2 ;;
    --root-dir) ROOT_DIR="${2:-}"; shift 2 ;;
    --reason) REASON="${2:-}"; shift 2 ;;
    --crl-out) CRL_OUT="${2:-}"; shift 2 ;;
    --skip-verify) SKIP_VERIFY="true"; shift ;;
    --dry-run) DRY_RUN="true"; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ "$ALGO" != "rsa" && "$ALGO" != "ecdsa" ]]; then
  echo "ERROR: --algo must be rsa or ecdsa" >&2
  exit 2
fi
if [[ -z "$CERT_PATH" ]]; then
  echo "ERROR: --cert is required" >&2
  exit 2
fi

require_cmd openssl

if [[ -z "$ROOT_DIR" ]]; then
  ROOT_DIR="${VIGIL_DIR}/ca/root-${ALGO}"
fi
if [[ -z "$CRL_OUT" ]]; then
  CRL_OUT="${ROOT_DIR}/crl/root-${ALGO}.crl.pem"
fi

if [[ ! -f "${ROOT_DIR}/openssl.cnf" ]]; then
  echo "ERROR: missing root openssl.cnf: ${ROOT_DIR}/openssl.cnf" >&2
  exit 1
fi
if [[ ! -f "$CERT_PATH" ]]; then
  echo "ERROR: cert not found: $CERT_PATH" >&2
  exit 1
fi

run mkdir -p "$(dirname "$CRL_OUT")"

run openssl ca -config "${ROOT_DIR}/openssl.cnf" \
  -revoke "$CERT_PATH" \
  -crl_reason "$REASON"

run openssl ca -config "${ROOT_DIR}/openssl.cnf" \
  -gencrl \
  -out "$CRL_OUT"

if [[ "$SKIP_VERIFY" != "true" ]]; then
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "+ openssl crl -in $CRL_OUT -noout -text | sed -n '/Revoked Certificates:/,/Signature Algorithm/p'"
  else
    openssl crl -in "$CRL_OUT" -noout -text | sed -n '/Revoked Certificates:/,/Signature Algorithm/p'
  fi
fi

echo "Revocation complete."
echo "  algo:     $ALGO"
echo "  rootDir:  $ROOT_DIR"
echo "  certPath: $CERT_PATH"
echo "  reason:   $REASON"
echo "  crlOut:   $CRL_OUT"
echo "  dryRun:   $DRY_RUN"