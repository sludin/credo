#!/usr/bin/env bash
set -euo pipefail

# Offline bootstrap helper for the very first Vigil admin identity.
#
# What this script does:
# 1) Optionally generates a new client key/cert signed by a supplied issuer cert/key.
# 2) Extracts the client public key.
# 3) Ensures Vigil data stores exist.
# 4) Registers the user in users.json via Vigil CLI add-user.
#
# Notes:
# - This is intended to be run locally on the Vigil host.
# - It does NOT call Vigil HTTP APIs.
# - For auth bootstrap, users.json is the critical store.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VIGIL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

usage() {
  cat <<'EOF'
Usage:
  bootstrap-first-admin.sh --user-id <id> --user-name <name> [options]

Required:
  --user-id <id>                  User ID to register in Vigil
  --user-name <name>              Display name for the user

Certificate input (choose one mode):
  Mode A: Provide an existing certificate
    --cert <path>                 Existing PEM client certificate

  Mode B: Generate and sign a new client certificate
    --algo <rsa|ecdsa>            Use active intermediary paths for selected algorithm
                                  issuer-cert: ./ca/int-<algo>/certs/int-<algo>.cert.pem
                                  issuer-key:  ./ca/int-<algo>/private/int-<algo>.key.pem
    --issuer-cert <path>          Issuer certificate PEM (typically active intermediate)
    --issuer-key <path>           Issuer private key PEM
    [--key-out <path>]            Output private key path (default: ./bootstrap/<id>.key.pem)
    [--cert-out <path>]           Output certificate path (default: ./bootstrap/<id>.cert.pem)
    [--days <n>]                  Certificate lifetime in days (default: 365)

Optional:
  --vigil-dir <path>              Path to Vigil project (default: script parent dir)
  --skip-build                    Skip npm build (default on deployed hosts: auto-skipped when dist/ exists)

Examples:
  # Register an existing cert
  ./scripts/bootstrap-first-admin.sh \
    --user-id admin --user-name "Bootstrap Admin" \
    --cert /secure/offline/admin-client.cert.pem

  # Generate + sign a new cert from intermediate
  ./scripts/bootstrap-first-admin.sh \
    --user-id admin --user-name "Bootstrap Admin" \
    --algo rsa

  # Generate + sign with explicit issuer paths
  ./scripts/bootstrap-first-admin.sh \
    --user-id admin --user-name "Bootstrap Admin" \
    --issuer-cert ./ca/int-rsa/certs/int-rsa.cert.pem \
    --issuer-key ./ca/int-rsa/private/int-rsa.key.pem
EOF
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: required command not found: $1" >&2
    exit 1
  }
}

abs_path() {
  local p="$1"
  if [[ "$p" = /* ]]; then
    printf '%s\n' "$p"
  else
    printf '%s\n' "$(cd "$PWD" && pwd)/$p"
  fi
}

USER_ID=""
USER_NAME=""
CERT_PATH=""
ALGO=""
ISSUER_CERT=""
ISSUER_KEY=""
KEY_OUT=""
CERT_OUT=""
DAYS="365"
SKIP_BUILD="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user-id) USER_ID="${2:-}"; shift 2 ;;
    --user-name) USER_NAME="${2:-}"; shift 2 ;;
    --cert) CERT_PATH="${2:-}"; shift 2 ;;
    --algo) ALGO="${2:-}"; shift 2 ;;
    --issuer-cert) ISSUER_CERT="${2:-}"; shift 2 ;;
    --issuer-key) ISSUER_KEY="${2:-}"; shift 2 ;;
    --key-out) KEY_OUT="${2:-}"; shift 2 ;;
    --cert-out) CERT_OUT="${2:-}"; shift 2 ;;
    --days) DAYS="${2:-}"; shift 2 ;;
    --vigil-dir) VIGIL_DIR="${2:-}"; shift 2 ;;
    --skip-build) SKIP_BUILD="true"; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$USER_ID" || -z "$USER_NAME" ]]; then
  echo "ERROR: --user-id and --user-name are required" >&2
  usage
  exit 2
fi

if [[ -n "$CERT_PATH" ]]; then
  if [[ -n "$ALGO" || -n "$ISSUER_CERT" || -n "$ISSUER_KEY" ]]; then
    echo "ERROR: do not pass --algo/--issuer-cert/--issuer-key when --cert is provided" >&2
    exit 2
  fi
else
  case "$ALGO" in
    ""|rsa|ecdsa) ;;
    *)
      echo "ERROR: --algo must be rsa or ecdsa" >&2
      exit 2
      ;;
  esac

  if [[ -n "$ALGO" ]]; then
    if [[ -z "$ISSUER_CERT" ]]; then
      ISSUER_CERT="${VIGIL_DIR}/ca/int-${ALGO}/certs/int-${ALGO}.cert.pem"
    fi
    if [[ -z "$ISSUER_KEY" ]]; then
      ISSUER_KEY="${VIGIL_DIR}/ca/int-${ALGO}/private/int-${ALGO}.key.pem"
    fi
  fi

  if [[ -z "$ISSUER_CERT" || -z "$ISSUER_KEY" ]]; then
    echo "ERROR: either --cert, or --algo, or both --issuer-cert and --issuer-key are required" >&2
    exit 2
  fi
fi

require_cmd openssl
require_cmd node
require_cmd npm

VIGIL_DIR="$(cd "$VIGIL_DIR" && pwd)"
cd "$VIGIL_DIR"

if [[ "$SKIP_BUILD" != "true" ]] && [[ -f "${VIGIL_DIR}/dist/index.js" ]]; then
  echo "Skipping build (dist/ already exists — deployed host)"
  SKIP_BUILD="true"
fi

if [[ "$SKIP_BUILD" != "true" ]]; then
  npm run build >/dev/null
fi

if [[ -n "$CERT_PATH" ]]; then
  CERT_PATH="$(abs_path "$CERT_PATH")"
  if [[ ! -f "$CERT_PATH" ]]; then
    echo "ERROR: cert file not found: $CERT_PATH" >&2
    exit 1
  fi
else
  ISSUER_CERT="$(abs_path "$ISSUER_CERT")"
  ISSUER_KEY="$(abs_path "$ISSUER_KEY")"
  if [[ ! -f "$ISSUER_CERT" ]]; then
    echo "ERROR: issuer cert not found: $ISSUER_CERT" >&2
    exit 1
  fi
  if [[ ! -f "$ISSUER_KEY" ]]; then
    echo "ERROR: issuer key not found: $ISSUER_KEY" >&2
    exit 1
  fi

  BOOTSTRAP_DIR="${VIGIL_DIR}/bootstrap"
  mkdir -p "$BOOTSTRAP_DIR"

  if [[ -z "$KEY_OUT" ]]; then
    KEY_OUT="${BOOTSTRAP_DIR}/${USER_ID}.key.pem"
  fi
  if [[ -z "$CERT_OUT" ]]; then
    CERT_OUT="${BOOTSTRAP_DIR}/${USER_ID}.cert.pem"
  fi

  KEY_OUT="$(abs_path "$KEY_OUT")"
  CERT_OUT="$(abs_path "$CERT_OUT")"

  TMP_CSR="$(mktemp -t vigil-bootstrap-csr.XXXXXX.pem)"
  TMP_EXT="$(mktemp -t vigil-bootstrap-ext.XXXXXX.cnf)"

  cat > "$TMP_EXT" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

  openssl genrsa -out "$KEY_OUT" 3072 >/dev/null 2>&1
  chmod 600 "$KEY_OUT"

  openssl req -new -sha256 \
    -key "$KEY_OUT" \
    -out "$TMP_CSR" \
    -subj "/CN=${USER_ID}" >/dev/null 2>&1

  openssl x509 -req \
    -in "$TMP_CSR" \
    -CA "$ISSUER_CERT" \
    -CAkey "$ISSUER_KEY" \
    -CAcreateserial \
    -out "$CERT_OUT" \
    -days "$DAYS" \
    -sha256 \
    -extfile "$TMP_EXT" >/dev/null 2>&1

  rm -f "$TMP_CSR" "$TMP_EXT"
  CERT_PATH="$CERT_OUT"
fi

TMP_PUB="$(mktemp -t vigil-bootstrap-pub.XXXXXX.pem)"
openssl x509 -in "$CERT_PATH" -pubkey -noout > "$TMP_PUB"

# Initialize all file stores so bootstrap has deterministic on-disk state.
node -e "const s=require('./dist/storage'); s.ensureUsersDb(); s.ensureCertificatesDb(); s.ensureAcmeAccountsDb();" >/dev/null

node ./dist/cli.js add-user \
  --id "$USER_ID" \
  --name "$USER_NAME" \
  --publicKeyPemFile "$TMP_PUB" >/dev/null

rm -f "$TMP_PUB"

FPR="$(openssl x509 -in "$CERT_PATH" -noout -fingerprint -sha256 | sed 's/^.*=//' | tr -d ':')"

echo "Bootstrap complete."
echo "  userId:     $USER_ID"
echo "  userName:   $USER_NAME"
if [[ -n "$ALGO" ]]; then
  echo "  algo:       $ALGO"
fi
echo "  certPath:   $CERT_PATH"
if [[ -n "${KEY_OUT:-}" ]]; then
  echo "  keyPath:    $KEY_OUT"
fi
echo "  certSha256: ${FPR}"
echo ""
echo "Vigil stores initialized/updated:"
echo "  - users.json (user registered)"
echo "  - certificates.json (initialized if missing)"
echo "  - acme-accounts.json (initialized if missing)"
