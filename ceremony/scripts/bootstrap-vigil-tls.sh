#!/usr/bin/env bash
set -euo pipefail

# Offline bootstrap helper for the Vigil server TLS keypair/certificate.
#
# What this script does:
# 1) Generates a server private key.
# 2) Generates a CSR with the supplied CN and SANs.
# 3) Signs the CSR with the supplied issuer cert/key.
# 4) Writes key, cert, chain, and fullchain outputs.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VIGIL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

usage() {
  cat <<'EOF'
Usage:
  bootstrap-vigil-tls.sh --cn <common-name> --algo <rsa|ecdsa> [options]

Required:
  --cn <value>                  Server certificate common name (required)
  --algo <rsa|ecdsa>            Server key algorithm and intermediary family

Optional:
  --san <dns>                   Additional DNS SAN (repeatable)
  --rsa-bits <n>                RSA key size when --algo rsa (default: 3072)
  --ecdsa-curve <name>          ECDSA curve when --algo ecdsa (default: prime256v1)
  --days <n>                    Certificate lifetime override
                                 default: [CA_default].default_days from issuer openssl.cnf
  --issuer-cert <path>          Override issuer certificate PEM
                                 default: ./ca/int-<algo>/certs/int-<algo>.cert.pem
  --issuer-key <path>           Override issuer private key PEM
                                 default: ./ca/int-<algo>/private/int-<algo>.key.pem
  --issuer-config <path>        Override issuer openssl.cnf used for default days
                                 default: <issuer-ca-dir>/openssl.cnf
  --issuer-chain <path>         Optional issuer chain PEM used for chain/fullchain output
                                 default behavior without this flag: chain contains issuer cert only
  --key-out <path>              Output key path (default: ./certs/privkey.pem)
  --cert-out <path>             Output cert path (default: ./certs/cert.pem)
  --chain-out <path>            Output chain path (default: ./certs/chain.pem)
                                 certbot-compatible intent: chain/intermediates only
  --fullchain-out <path>        Output fullchain path (default: ./certs/fullchain.pem)
                                 certbot-compatible intent: cert + chain
  --client-trust-out <path>     Output mTLS client trust bundle
                                 default: tlsClientCaPath from vigil.config.json
                                 fallback: ./certs/client-trust-all.pem
  --trust-mode <roots|intermediates|both>
                                 Trust bundle composition (default: both)
  --skip-record                 Do not record issuance in Vigil data/CT log
  --issued-by <value>           Actor string for issuance record (default: bootstrap:vigil-tls)
  --owner-user-id <value>       ownerVigilUserId for certificate record (default: system)
  --vigil-dir <path>            Path to Vigil project root (default: script parent dir)
  --skip-build                  Skip npm build before recording (expects dist/ to exist)
  --force                       Overwrite output files if they already exist
  --dry-run                     Print planned operations without writing files
  -h, --help                    Show help

Examples:
  ./scripts/bootstrap-vigil-tls.sh \
    --cn vigil.internal.example \
    --algo rsa

  ./scripts/bootstrap-vigil-tls.sh \
    --cn vigil.internal.example \
    --san vigil \
    --san vigil.svc.cluster.local \
    --algo ecdsa \
    --issuer-chain ./certs/intermediates.pem
EOF
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: required command not found: $1" >&2
    exit 1
  }
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
      print val
      exit
    }
  ' "$cfg"
}

abspath() {
  local p="$1"
  if [[ "$p" != /* ]]; then
    p="$(pwd)/$p"
  fi

  # Normalize textual path segments without requiring parent directories to exist.
  while [[ "$p" == *"//"* ]]; do
    p="${p//\/\//\/}"
  done
  while [[ "$p" == *"/./"* ]]; do
    p="${p//\/\.\//\/}"
  done
  if [[ "$p" == */. ]]; then
    p="${p%/.}"
  fi

  printf '%s\n' "$p"
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

CN=""
ISSUER_CERT=""
ISSUER_KEY=""
ISSUER_CONFIG=""
ISSUER_CHAIN=""
KEY_ALGO=""
RSA_BITS="3072"
ECDSA_CURVE="prime256v1"
DAYS=""
KEY_OUT="./certs/privkey.pem"
CERT_OUT="./certs/cert.pem"
CHAIN_OUT="./certs/chain.pem"
FULLCHAIN_OUT="./certs/fullchain.pem"
CLIENT_TRUST_OUT=""
TRUST_MODE="both"
RECORD_ISSUANCE="true"
ISSUED_BY="bootstrap:vigil-tls"
OWNER_USER_ID="system"
SKIP_BUILD="false"
FORCE="false"
DRY_RUN="false"
SANS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cn) CN="${2:-}"; shift 2 ;;
    --issuer-cert) ISSUER_CERT="${2:-}"; shift 2 ;;
    --issuer-key) ISSUER_KEY="${2:-}"; shift 2 ;;
    --issuer-config) ISSUER_CONFIG="${2:-}"; shift 2 ;;
    --issuer-chain) ISSUER_CHAIN="${2:-}"; shift 2 ;;
    --san) SANS+=("${2:-}"); shift 2 ;;
    --algo) KEY_ALGO="${2:-}"; shift 2 ;;
    --rsa-bits) RSA_BITS="${2:-}"; shift 2 ;;
    --ecdsa-curve) ECDSA_CURVE="${2:-}"; shift 2 ;;
    --days) DAYS="${2:-}"; shift 2 ;;
    --key-out) KEY_OUT="${2:-}"; shift 2 ;;
    --cert-out) CERT_OUT="${2:-}"; shift 2 ;;
    --chain-out) CHAIN_OUT="${2:-}"; shift 2 ;;
    --fullchain-out) FULLCHAIN_OUT="${2:-}"; shift 2 ;;
    --client-trust-out) CLIENT_TRUST_OUT="${2:-}"; shift 2 ;;
    --trust-mode) TRUST_MODE="${2:-}"; shift 2 ;;
    --skip-record) RECORD_ISSUANCE="false"; shift ;;
    --issued-by) ISSUED_BY="${2:-}"; shift 2 ;;
    --owner-user-id) OWNER_USER_ID="${2:-}"; shift 2 ;;
    --vigil-dir) VIGIL_DIR="${2:-}"; shift 2 ;;
    --skip-build) SKIP_BUILD="true"; shift ;;
    --force) FORCE="true"; shift ;;
    --dry-run) DRY_RUN="true"; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$CN" ]]; then
  echo "ERROR: --cn is required" >&2
  usage
  exit 2
fi

case "$KEY_ALGO" in
  rsa|ecdsa) ;;
  "")
    echo "ERROR: --algo is required" >&2
    usage
    exit 2
    ;;
  *)
    echo "ERROR: --algo must be rsa or ecdsa" >&2
    exit 2
    ;;
esac

case "$TRUST_MODE" in
  roots|intermediates|both) ;;
  *)
    echo "ERROR: --trust-mode must be roots, intermediates, or both" >&2
    exit 2
    ;;
esac

require_cmd openssl
if [[ "$RECORD_ISSUANCE" == "true" ]]; then
  require_cmd node
  if [[ "$SKIP_BUILD" != "true" ]]; then
    require_cmd npm
  fi
fi

VIGIL_DIR="$(abspath "$VIGIL_DIR")"

if [[ -z "$CLIENT_TRUST_OUT" ]]; then
  VIGIL_CONFIG_PATH="${VIGIL_DIR}/vigil.config.json"
  if [[ -f "$VIGIL_CONFIG_PATH" ]] && command -v node >/dev/null 2>&1; then
    CONFIG_TRUST_PATH="$({
      VIGIL_CONFIG_PATH="$VIGIL_CONFIG_PATH" node -e "
const fs = require('fs');
const path = process.env.VIGIL_CONFIG_PATH;
try {
  const raw = JSON.parse(fs.readFileSync(path, 'utf8'));
  const val = typeof raw.tlsClientCaPath === 'string' ? raw.tlsClientCaPath.trim() : '';
  if (val) process.stdout.write(val);
} catch (_) {
  // Ignore parsing errors and fall back to default below.
}
";
    } 2>/dev/null)"
    if [[ -n "$CONFIG_TRUST_PATH" ]]; then
      CLIENT_TRUST_OUT="$CONFIG_TRUST_PATH"
    fi
  fi
fi

if [[ -z "$CLIENT_TRUST_OUT" ]]; then
  CLIENT_TRUST_OUT="${VIGIL_DIR}/certs/client-trust-all.pem"
fi

if [[ -z "$ISSUER_CERT" ]]; then
  ISSUER_CERT="${VIGIL_DIR}/ca/int-${KEY_ALGO}/certs/int-${KEY_ALGO}.cert.pem"
fi
if [[ -z "$ISSUER_KEY" ]]; then
  ISSUER_KEY="${VIGIL_DIR}/ca/int-${KEY_ALGO}/private/int-${KEY_ALGO}.key.pem"
fi

if [[ -z "$ISSUER_CONFIG" ]]; then
  ISSUER_CA_DIR="$(dirname "$(dirname "$ISSUER_CERT")")"
  ISSUER_CONFIG="${ISSUER_CA_DIR}/openssl.cnf"
fi

ISSUER_CERT="$(abspath "$ISSUER_CERT")"
ISSUER_KEY="$(abspath "$ISSUER_KEY")"
ISSUER_CONFIG="$(abspath "$ISSUER_CONFIG")"
KEY_OUT="$(abspath "$KEY_OUT")"
CERT_OUT="$(abspath "$CERT_OUT")"
CHAIN_OUT="$(abspath "$CHAIN_OUT")"
FULLCHAIN_OUT="$(abspath "$FULLCHAIN_OUT")"
CLIENT_TRUST_OUT="$(abspath "$CLIENT_TRUST_OUT")"

if [[ -n "$ISSUER_CHAIN" ]]; then
  ISSUER_CHAIN="$(abspath "$ISSUER_CHAIN")"
fi

if [[ ! -f "$ISSUER_CERT" ]]; then
  echo "ERROR: issuer cert not found: $ISSUER_CERT" >&2
  exit 1
fi
if [[ ! -f "$ISSUER_KEY" ]]; then
  echo "ERROR: issuer key not found: $ISSUER_KEY" >&2
  exit 1
fi
if [[ ! -f "$ISSUER_CONFIG" ]]; then
  echo "ERROR: issuer config not found: $ISSUER_CONFIG" >&2
  exit 1
fi
if [[ -n "$ISSUER_CHAIN" && ! -f "$ISSUER_CHAIN" ]]; then
  echo "ERROR: issuer chain not found: $ISSUER_CHAIN" >&2
  exit 1
fi

if [[ -z "$DAYS" ]]; then
  DAYS="$(config_default_days "$ISSUER_CONFIG")"
  if [[ -z "$DAYS" ]]; then
    echo "ERROR: unable to resolve default validity from $ISSUER_CONFIG. Set --days or define [CA_default] default_days." >&2
    exit 1
  fi
fi
if ! [[ "$DAYS" =~ ^[0-9]+$ ]] || [[ "$DAYS" -le 0 ]]; then
  echo "ERROR: --days must be a positive integer" >&2
  exit 2
fi

for out in "$KEY_OUT" "$CERT_OUT" "$CHAIN_OUT" "$FULLCHAIN_OUT" "$CLIENT_TRUST_OUT"; do
  if [[ -e "$out" && "$FORCE" != "true" && "$DRY_RUN" != "true" ]]; then
    echo "ERROR: output exists: $out (use --force to overwrite)" >&2
    exit 1
  fi
done

SAN_CSV="DNS:${CN}"
for san in "${SANS[@]}"; do
  SAN_CSV+=",DNS:${san}"
done

OUT_DIR="$(dirname "$KEY_OUT")"
run mkdir -p "$OUT_DIR"
if [[ "$(dirname "$CERT_OUT")" != "$OUT_DIR" ]]; then
  run mkdir -p "$(dirname "$CERT_OUT")"
fi
if [[ "$(dirname "$CHAIN_OUT")" != "$OUT_DIR" && "$(dirname "$CHAIN_OUT")" != "$(dirname "$CERT_OUT")" ]]; then
  run mkdir -p "$(dirname "$CHAIN_OUT")"
fi
if [[ "$(dirname "$FULLCHAIN_OUT")" != "$OUT_DIR" && "$(dirname "$FULLCHAIN_OUT")" != "$(dirname "$CERT_OUT")" && "$(dirname "$FULLCHAIN_OUT")" != "$(dirname "$CHAIN_OUT")" ]]; then
  run mkdir -p "$(dirname "$FULLCHAIN_OUT")"
fi
if [[ "$(dirname "$CLIENT_TRUST_OUT")" != "$OUT_DIR" && "$(dirname "$CLIENT_TRUST_OUT")" != "$(dirname "$CERT_OUT")" && "$(dirname "$CLIENT_TRUST_OUT")" != "$(dirname "$CHAIN_OUT")" && "$(dirname "$CLIENT_TRUST_OUT")" != "$(dirname "$FULLCHAIN_OUT")" ]]; then
  run mkdir -p "$(dirname "$CLIENT_TRUST_OUT")"
fi

TMP_CSR="$(mktemp -t vigil-server-csr.XXXXXX.pem)"
TMP_EXT="$(mktemp -t vigil-server-ext.XXXXXX.cnf)"
TMP_WORKDIR="$(mktemp -d -t vigil-server-work.XXXXXX)"
TMP_SERIAL="${TMP_WORKDIR}/serial.srl"

cleanup() {
  rm -f "$TMP_CSR" "$TMP_EXT"
  rm -rf "$TMP_WORKDIR"
}
trap cleanup EXIT

cat > "$TMP_EXT" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=${SAN_CSV}
EOF

if [[ "$KEY_ALGO" == "rsa" ]]; then
  run openssl genrsa -out "$KEY_OUT" "$RSA_BITS"
else
  run openssl ecparam -name "$ECDSA_CURVE" -genkey -noout -out "$KEY_OUT"
fi

if [[ "$DRY_RUN" != "true" ]]; then
  chmod 600 "$KEY_OUT"
else
  echo "+ chmod 600 $KEY_OUT"
fi

run openssl req -new -sha256 \
  -key "$KEY_OUT" \
  -out "$TMP_CSR" \
  -subj "/CN=${CN}"

run openssl x509 -req \
  -in "$TMP_CSR" \
  -CA "$ISSUER_CERT" \
  -CAkey "$ISSUER_KEY" \
  -CAserial "$TMP_SERIAL" \
  -CAcreateserial \
  -out "$CERT_OUT" \
  -days "$DAYS" \
  -sha256 \
  -extfile "$TMP_EXT"

if [[ "$DRY_RUN" == "true" ]]; then
  if [[ -n "$ISSUER_CHAIN" ]]; then
    echo "+ cp $ISSUER_CHAIN $CHAIN_OUT"
  else
    echo "+ cp $ISSUER_CERT $CHAIN_OUT"
  fi
  echo "+ cat $CERT_OUT $CHAIN_OUT > $FULLCHAIN_OUT"
else
  if [[ -n "$ISSUER_CHAIN" ]]; then
    cp "$ISSUER_CHAIN" "$CHAIN_OUT"
  else
    cp "$ISSUER_CERT" "$CHAIN_OUT"
  fi
  cat "$CERT_OUT" "$CHAIN_OUT" > "$FULLCHAIN_OUT"
fi

ROOT_CERT_DEFAULT="${VIGIL_DIR}/ca/root-${KEY_ALGO}/certs/root-${KEY_ALGO}.cert.pem"
ROOT_CERT_DEFAULT="$(abspath "$ROOT_CERT_DEFAULT")"
if [[ "$TRUST_MODE" == "roots" || "$TRUST_MODE" == "both" ]]; then
  if [[ ! -f "$ROOT_CERT_DEFAULT" ]]; then
    echo "ERROR: trust-mode '$TRUST_MODE' requires root cert: $ROOT_CERT_DEFAULT" >&2
    exit 1
  fi
fi

if [[ "$DRY_RUN" == "true" ]]; then
  case "$TRUST_MODE" in
    roots)
      echo "+ cp $ROOT_CERT_DEFAULT $CLIENT_TRUST_OUT"
      ;;
    intermediates)
      echo "+ cp $CHAIN_OUT $CLIENT_TRUST_OUT"
      ;;
    both)
      echo "+ cat $CHAIN_OUT $ROOT_CERT_DEFAULT > $CLIENT_TRUST_OUT"
      ;;
  esac
else
  case "$TRUST_MODE" in
    roots)
      cp "$ROOT_CERT_DEFAULT" "$CLIENT_TRUST_OUT"
      ;;
    intermediates)
      cp "$CHAIN_OUT" "$CLIENT_TRUST_OUT"
      ;;
    both)
      cat "$CHAIN_OUT" "$ROOT_CERT_DEFAULT" > "$CLIENT_TRUST_OUT"
      ;;
  esac
fi

if [[ "$RECORD_ISSUANCE" == "true" ]]; then
  if [[ "$DRY_RUN" == "true" ]]; then
    if [[ "$SKIP_BUILD" != "true" ]]; then
      echo "+ (cd $VIGIL_DIR && npm run build >/dev/null)"
    fi
    echo "+ node record issuance in Vigil storage for cert: $CERT_OUT"
  else
    if [[ "$SKIP_BUILD" != "true" ]] && [[ -f "${VIGIL_DIR}/dist/index.js" ]]; then
      echo "Skipping build (dist/ already exists — deployed host)"
      SKIP_BUILD="true"
    fi
    if [[ "$SKIP_BUILD" != "true" ]]; then
      (cd "$VIGIL_DIR" && npm run build >/dev/null)
    fi

    (
      cd "$VIGIL_DIR"
      BOOT_CERT_PATH="$CERT_OUT" \
      BOOT_ISSUED_BY="$ISSUED_BY" \
      BOOT_OWNER_USER_ID="$OWNER_USER_ID" \
      node -e "
const fs = require('fs');
const { X509Certificate } = require('crypto');
const { ensureCertificatesDb, issueCertificateRecord } = require('./dist/storage');
const { appendCTLog } = require('./dist/ctlog');

const certPath = process.env.BOOT_CERT_PATH;
const issuedBy = process.env.BOOT_ISSUED_BY || 'bootstrap:vigil-tls';
const ownerUserId = process.env.BOOT_OWNER_USER_ID || 'system';

const certPem = fs.readFileSync(certPath, 'utf8');
const metadata = new X509Certificate(certPem);
const issuedAt = new Date().toISOString();

ensureCertificatesDb();
const record = issueCertificateRecord({
  id: metadata.serialNumber.toLowerCase(),
  serialNumber: metadata.serialNumber,
  subject: metadata.subject,
  fingerprint256: metadata.fingerprint256,
  validFrom: metadata.validFrom,
  validTo: metadata.validTo,
  issuedAt,
  issuedBy,
  ownerVigilUserId: ownerUserId,
  revoked: false,
}, certPem);

appendCTLog('certificate.signed', issuedBy, {
  certificateId: record.id,
  serialNumber: record.serialNumber,
  subject: record.subject,
  validTo: record.validTo,
  source: 'bootstrap-vigil-tls',
});
"
    )
  fi
fi

echo "Vigil TLS bootstrap complete."
echo "  cn:         $CN"
echo "  algo:       $KEY_ALGO"
echo "  issuerCert: $ISSUER_CERT"
echo "  issuerCfg:  $ISSUER_CONFIG"
echo "  keyOut:     $KEY_OUT"
echo "  certOut:    $CERT_OUT"
echo "  chainOut:   $CHAIN_OUT"
echo "  fullchain:  $FULLCHAIN_OUT"
echo "  trustOut:   $CLIENT_TRUST_OUT"
echo "  trustMode:  $TRUST_MODE"
echo "  days:       $DAYS"
echo "  recorded:   $RECORD_ISSUANCE"
if [[ "$RECORD_ISSUANCE" == "true" ]]; then
  echo "  issuedBy:   $ISSUED_BY"
  echo "  ownerUser:  $OWNER_USER_ID"
fi
echo "  dryRun:     $DRY_RUN"
