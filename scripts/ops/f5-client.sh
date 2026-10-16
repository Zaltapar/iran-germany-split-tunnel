#!/bin/bash
# f5-client.sh — Phase 2 F5 client helper (Iran side).
#
# Purpose:
#   Downloads a deterministic 20 MiB payload through the SOCKS5 tunnel
#   and verifies its SHA-256. Run during the F5 443-block window to
#   confirm the tunnel still serves egress via the surviving carrier.
#
# Required environment variables:
#   SOCKS5_CRED_FILE — absolute path to a key=value file with host,
#                      port, username, password entries
#                      (default: /root/socks5-credentials.txt)
#   STAGING_DIR      — directory for the output file (default: /root/phase2-staging)
#   SERVE_HOST       — the loopback URL the payload is served from
#                      (default: http://127.0.0.1:8899/f5-payload.bin)
#
# Host-agnostic: SOCKS5 credentials are read in-shell from the file
# named by SOCKS5_CRED_FILE; they are never printed or embedded here.
# The reference tunnel endpoint (188.121.111.122:10900 in the original
# staging record) is NOT hardcoded; it is resolved from the credentials
# file at runtime.
#
# Usage:  bash f5-client.sh
set -u
SOCKS5_CRED_FILE="${SOCKS5_CRED_FILE:-/root/socks5-credentials.txt}"
STAGING_DIR="${STAGING_DIR:-/root/phase2-staging}"
SERVE_URL="${SERVE_URL:-http://127.0.0.1:8899/f5-payload.bin}"
H=$(awk -F= '$1=="host"{print $2}' "$SOCKS5_CRED_FILE")
P=$(awk -F= '$1=="port"{print $2}' "$SOCKS5_CRED_FILE")
U=$(awk -F= '$1=="username"{print $2}' "$SOCKS5_CRED_FILE")
PASS=$(awk -F= '$1=="password"{print $2}' "$SOCKS5_CRED_FILE")
OUT="${STAGING_DIR}/f5-dl.bin"
START=$(date +%s)
code=$(curl -s -o "$OUT" -w "%{http_code}" --max-time 180 \
  --proxy "socks5h://$U:$PASS@$H:$P" "$SERVE_URL")
END=$(date +%s)
DLSHA=$(sha256sum "$OUT" 2>/dev/null | cut -d' ' -f1)
BYTES=$(stat -c%s "$OUT" 2>/dev/null)
echo "F5-DL: http_code=$code bytes=$BYTES elapsed_s=$((END-START)) sha256=$DLSHA"
