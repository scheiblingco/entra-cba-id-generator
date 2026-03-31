#!/usr/bin/env bash
# One-time script to generate:
#   certs/ca.crt / ca.key       — self-signed CA
#   certs/server.crt / server.key — server cert signed by CA (localhost)
#   certs/client.crt / client.key — sample client cert signed by CA
#
# Run once: bash gen-certs.sh
# The Go server reads: certs/ca.crt, certs/server.crt, certs/server.key

set -euo pipefail

CERTS_DIR="certs"
mkdir -p "$CERTS_DIR"

echo "==> Generating CA key and self-signed certificate..."
openssl genrsa -out "$CERTS_DIR/ca.key" 4096 2>/dev/null
openssl req -new -x509 \
  -key "$CERTS_DIR/ca.key" \
  -out "$CERTS_DIR/ca.crt" \
  -days 3650 \
  -subj "/CN=Entra CBA Test CA/O=Test/C=SE"

echo "==> Generating server key and certificate (localhost)..."
openssl genrsa -out "$CERTS_DIR/server.key" 2048 2>/dev/null
openssl req -new \
  -key "$CERTS_DIR/server.key" \
  -out "$CERTS_DIR/server.csr" \
  -subj "/CN=localhost"
openssl x509 -req \
  -in "$CERTS_DIR/server.csr" \
  -CA "$CERTS_DIR/ca.crt" \
  -CAkey "$CERTS_DIR/ca.key" \
  -CAcreateserial \
  -out "$CERTS_DIR/server.crt" \
  -days 825 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")
rm "$CERTS_DIR/server.csr"

echo "==> Generating sample client key and certificate..."
openssl genrsa -out "$CERTS_DIR/client.key" 2048 2>/dev/null
openssl req -new \
  -key "$CERTS_DIR/client.key" \
  -out "$CERTS_DIR/client.csr" \
  -subj "/CN=Test User/emailAddress=testuser@example.com/O=Test Org/C=SE"
openssl x509 -req \
  -in "$CERTS_DIR/client.csr" \
  -CA "$CERTS_DIR/ca.crt" \
  -CAkey "$CERTS_DIR/ca.key" \
  -CAcreateserial \
  -out "$CERTS_DIR/client.crt" \
  -days 365 \
  -extfile <(printf "subjectAltName=email:testuser@example.com,otherName:1.3.6.1.4.1.311.20.2.3;UTF8:testuser@example.com\nextendedKeyUsage=clientAuth\nsubjectKeyIdentifier=hash")
rm "$CERTS_DIR/client.csr"

echo ""
echo "Done. Files written to $CERTS_DIR/:"
ls -1 "$CERTS_DIR/"
echo ""
echo "To test with curl:"
echo "  curl -k --cert $CERTS_DIR/client.crt --key $CERTS_DIR/client.key https://localhost:8443"
