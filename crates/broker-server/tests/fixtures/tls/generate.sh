#!/usr/bin/env bash
# Regenerates the test certificates and keys in this directory (see
# README.md). Needs OpenSSL 3.4 or newer for -not_before / -not_after.
set -euo pipefail
cd "$(dirname "$0")"

start=20260101000000Z
end=21260101000000Z

key() {
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1.key"
}

# ca <name> <common name>
ca() {
  key "$1"
  openssl req -x509 -new -key "$1.key" -subj "/CN=$2" -sha256 \
    -not_before "$start" -not_after "$end" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$1.pem"
}

# leaf <name> <issuer> <common name> <not after> <extension>...
leaf() {
  local name=$1 issuer=$2 cn=$3 not_after=$4
  shift 4
  key "$name"
  openssl req -new -key "$name.key" -subj "/CN=$cn" -out "$name.csr"
  openssl x509 -req -in "$name.csr" -CA "$issuer.pem" -CAkey "$issuer.key" -sha256 \
    -not_before "$start" -not_after "$not_after" \
    -extfile <(printf '%s\n' "basicConstraints=critical,CA:FALSE" "keyUsage=critical,digitalSignature" "$@") \
    -out "$name.pem"
  rm "$name.csr"
}

ca ca "Test upstream CA"
ca other-ca "Other test CA"
leaf server ca localhost "$end" "extendedKeyUsage=serverAuth" "subjectAltName=DNS:localhost,IP:127.0.0.1"
leaf other-server other-ca localhost "$end" "extendedKeyUsage=serverAuth" "subjectAltName=DNS:localhost,IP:127.0.0.1"
leaf client-a ca broker-a 21250601000000Z "extendedKeyUsage=clientAuth"
leaf client-b ca broker-b 21250901000000Z "extendedKeyUsage=clientAuth"

# The CA keys are only needed to sign the certificates above.
rm ca.key other-ca.key
