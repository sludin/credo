#!/usr/bin/env bash
set -euo pipefail

# Generate OpenSSL CA config files for Vigil ECDSA root and intermediate CAs.
#
# This script writes:
# - ca/root-ecdsa/openssl.cnf
# - ca/int-ecdsa/openssl.cnf
#
# It only generates config files — it does not create keys or certificates.
# Run bootstrap-roots.sh and issue-intermediary.sh after this step.

usage() {
  cat <<'EOF'
Usage:
  generate-openssl-cnf.sh [options]

Options:
  --ca-dir <path>                CA base dir (default: ./ca)
  --org <value>                  Organization in DN (required)
  --country <value>              Country in DN (default: US)
  --root-ecdsa-cn <value>        Root ECDSA CN (required when generating root-ecdsa)
  --int-ecdsa-cn <value>         Intermediate ECDSA CN (required when generating int-ecdsa)
  --root-days <n>                Root cert default days (default: 3650)
  --int-days <n>                 Intermediate cert default days (default: 730)
  --root-crl-days <n>            Root CRL default days (default: 90)
  --int-crl-days <n>             Intermediate CRL default days (default: 7)
  --pki-base-url <url>           Base URL embedded in AIA/CDP extensions
                                 (default: http://pki.example.com)
                                 Does not need to be served for the CA to function.
  --target <name>                Generate only selected config (repeatable)
                                 values: root-ecdsa, int-ecdsa
                                 default: derived from available CNs
  --env-file <path>              Optional KEY=VALUE env file for defaults
  --force                        Overwrite existing openssl.cnf files
  --dry-run                      Print planned writes without modifying files
  -h, --help                     Show help

Supported env-file keys:
  CA_DIR, ORG, COUNTRY,
  ROOT_ECDSA_CN, INT_ECDSA_CN,
  ROOT_DAYS, INT_DAYS, ROOT_CRL_DAYS, INT_CRL_DAYS,
  PKI_BASE_URL

Examples:
  ./scripts/generate-openssl-cnf.sh --env-file ./ca-vars.env --force

  ./scripts/generate-openssl-cnf.sh \
    --org "Example PKI" \
    --root-ecdsa-cn "Example Root X1" \
    --int-ecdsa-cn "Example E1" \
    --force
EOF
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

write_file() {
  local path="$1"
  local content="$2"

  if [[ "$DRY_RUN" != "true" && -e "$path" && "$FORCE" != "true" ]]; then
    echo "ERROR: file exists: $path (use --force to overwrite)" >&2
    exit 1
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    echo "+ write $path"
    return 0
  fi

  mkdir -p "$(dirname "$path")"
  printf '%s\n' "$content" > "$path"
}

abspath() {
  local p="$1"
  if [[ "$p" != /* ]]; then
    p="$(pwd)/$p"
  fi
  printf '%s\n' "$(cd -P -- "$(dirname -- "$p")" 2>/dev/null && pwd -P)/$(basename -- "$p")"
}

CA_DIR="./ca"
ORG=""
COUNTRY="US"
ROOT_ECDSA_CN=""
INT_ECDSA_CN=""
ROOT_DAYS="3650"
INT_DAYS="730"
ROOT_CRL_DAYS="90"
INT_CRL_DAYS="7"
PKI_BASE_URL="http://pki.example.com"
ENV_FILE=""
FORCE="false"
DRY_RUN="false"
TARGETS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ca-dir)         CA_DIR="${2:-}"; shift 2 ;;
    --org)            ORG="${2:-}"; shift 2 ;;
    --country)        COUNTRY="${2:-}"; shift 2 ;;
    --root-ecdsa-cn)  ROOT_ECDSA_CN="${2:-}"; shift 2 ;;
    --int-ecdsa-cn)   INT_ECDSA_CN="${2:-}"; shift 2 ;;
    --root-days)      ROOT_DAYS="${2:-}"; shift 2 ;;
    --int-days)       INT_DAYS="${2:-}"; shift 2 ;;
    --root-crl-days)  ROOT_CRL_DAYS="${2:-}"; shift 2 ;;
    --int-crl-days)   INT_CRL_DAYS="${2:-}"; shift 2 ;;
    --pki-base-url)   PKI_BASE_URL="${2:-}"; shift 2 ;;
    --target)         TARGETS+=("${2:-}"); shift 2 ;;
    --env-file)       ENV_FILE="${2:-}"; shift 2 ;;
    --force)          FORCE="true"; shift ;;
    --dry-run)        DRY_RUN="true"; shift ;;
    -h|--help)        usage; exit 0 ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -n "$ENV_FILE" ]]; then
  if [[ ! -f "$ENV_FILE" ]]; then
    echo "ERROR: env file not found: $ENV_FILE" >&2
    exit 1
  fi
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

if [[ ${#TARGETS[@]} -eq 0 ]]; then
  if [[ -n "$ROOT_ECDSA_CN" ]]; then
    TARGETS+=("root-ecdsa")
    [[ -n "$INT_ECDSA_CN" ]] && TARGETS+=("int-ecdsa")
  fi
  if [[ ${#TARGETS[@]} -eq 0 ]]; then
    echo "ERROR: no --target specified and no CNs found to derive targets from" >&2
    echo "       provide --root-ecdsa-cn (and optionally --int-ecdsa-cn), or use --target explicitly" >&2
    exit 2
  fi
fi

for target in "${TARGETS[@]}"; do
  case "$target" in
    root-ecdsa|int-ecdsa) ;;
    *)
      echo "ERROR: invalid --target '$target' (expected root-ecdsa or int-ecdsa)" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$ORG" ]]; then
  echo "ERROR: --org is required (or set ORG in --env-file)" >&2
  exit 2
fi

for target in "${TARGETS[@]}"; do
  case "$target" in
    root-ecdsa)
      [[ -n "$ROOT_ECDSA_CN" ]] || { echo "ERROR: --root-ecdsa-cn is required for target root-ecdsa" >&2; exit 2; }
      ;;
    int-ecdsa)
      [[ -n "$INT_ECDSA_CN" ]] || { echo "ERROR: --int-ecdsa-cn is required for target int-ecdsa" >&2; exit 2; }
      ;;
  esac
done

CA_DIR="$(abspath "$CA_DIR")"

ROOT_ECDSA_DIR="${CA_DIR}/root-ecdsa"
INT_ECDSA_DIR="${CA_DIR}/int-ecdsa"
ROOT_ECDSA_CFG="${ROOT_ECDSA_DIR}/openssl.cnf"
INT_ECDSA_CFG="${INT_ECDSA_DIR}/openssl.cnf"

root_ecdsa_content="[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = ${ROOT_ECDSA_DIR}
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial
crlnumber         = \$dir/crlnumber

certificate       = \$dir/certs/root-ecdsa.cert.pem
private_key       = \$dir/private/root-ecdsa.key.pem

default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
default_days      = ${ROOT_DAYS}
preserve          = no
policy            = policy_strict
email_in_dn       = no
copy_extensions   = none
unique_subject    = no

crl               = \$dir/crl/root-ecdsa.crl.pem
default_crl_days  = ${ROOT_CRL_DAYS}

[ policy_strict ]
countryName             = optional
stateOrProvinceName     = optional
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied

[ req ]
default_md          = sha384
prompt              = no
distinguished_name  = dn
x509_extensions     = v3_root_ca
string_mask         = utf8only
utf8                = yes

[ dn ]
C  = ${COUNTRY}
O  = ${ORG}
CN = ${ROOT_ECDSA_CN}

[ v3_root_ca ]
basicConstraints       = critical, CA:true, pathlen:1
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always"

int_ecdsa_content="[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = ${INT_ECDSA_DIR}
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial
crlnumber         = \$dir/crlnumber

certificate       = \$dir/certs/int-ecdsa.cert.pem
private_key       = \$dir/private/int-ecdsa.key.pem

default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
default_days      = ${INT_DAYS}
preserve          = no
policy            = policy_loose
email_in_dn       = no
copy_extensions   = none
unique_subject    = no

crl               = \$dir/crl/int-ecdsa.crl.pem
default_crl_days  = ${INT_CRL_DAYS}

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied

[ req ]
default_md          = sha384
prompt              = no
distinguished_name  = dn
string_mask         = utf8only
utf8                = yes

[ dn ]
C  = ${COUNTRY}
O  = ${ORG}
CN = ${INT_ECDSA_CN}

[ v3_intermediate_ca ]
basicConstraints       = critical, CA:true, pathlen:0
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer

[ server_cert ]
basicConstraints       = critical, CA:false
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
crlDistributionPoints  = URI:${PKI_BASE_URL}/crl/int-ecdsa.crl.pem
authorityInfoAccess    = caIssuers;URI:${PKI_BASE_URL}/certs/int-ecdsa.cert.pem

[ client_cert ]
basicConstraints       = critical, CA:false
keyUsage               = critical, digitalSignature
extendedKeyUsage       = clientAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
crlDistributionPoints  = URI:${PKI_BASE_URL}/crl/int-ecdsa.crl.pem
authorityInfoAccess    = caIssuers;URI:${PKI_BASE_URL}/certs/int-ecdsa.cert.pem"

for target in "${TARGETS[@]}"; do
  case "$target" in
    root-ecdsa) write_file "$ROOT_ECDSA_CFG" "$root_ecdsa_content" ;;
    int-ecdsa)  write_file "$INT_ECDSA_CFG"  "$int_ecdsa_content"  ;;
  esac
done

echo "OpenSSL config generation complete."
echo "  caDir:           $CA_DIR"
echo "  targets:         ${TARGETS[*]}"
for target in "${TARGETS[@]}"; do
  case "$target" in
    root-ecdsa) echo "  rootEcdsaConfig: $ROOT_ECDSA_CFG" ;;
    int-ecdsa)  echo "  intEcdsaConfig:  $INT_ECDSA_CFG"  ;;
  esac
done
echo "  dryRun:          $DRY_RUN"
