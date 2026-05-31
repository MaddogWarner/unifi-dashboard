#!/bin/sh
set -e

CERT_DIR=/etc/nginx/certs

mkdir -p "$CERT_DIR"

if [ ! -f "$CERT_DIR/server.crt" ] || [ ! -f "$CERT_DIR/server.key" ]; then
    echo "[nginx-entrypoint] No TLS certificate found - generating self-signed cert..."
    openssl req -x509 -newkey rsa:2048 \
        -keyout "$CERT_DIR/server.key" \
        -out "$CERT_DIR/server.crt" \
        -days 3650 \
        -nodes \
        -subj "/CN=unifi-dashboard/O=UniFi Dashboard/C=AU"
    chmod 600 "$CERT_DIR/server.key"
    echo "[nginx-entrypoint] Self-signed certificate written to $CERT_DIR/server.crt"
    echo "[nginx-entrypoint] To use a custom cert: place server.crt and server.key in ./certs/ and restart nginx."
fi

exec nginx -g "daemon off;"
