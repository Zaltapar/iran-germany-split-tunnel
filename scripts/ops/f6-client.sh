#!/bin/bash
# f6-client.sh — Phase 2 F6 client helper (Iran side).
#
# Purpose:
#   During the 20 s double-carrier block, opens one TCP stream through the
#   SOCKS5 tunnel and observes that it is refused/closed cleanly when both
#   down carriers are down (no hang past the grace window). Also verifies
#   the 20 MiB download still completes (bounded; a clean failure is the
#   expected/allowed outcome when both carriers are down).
#
# Required environment variables:
#   SOCKS5_CRED_FILE — absolute path to a key=value file with host,
#                      port, username, password entries
#                      (default: /root/socks5-credentials.txt)
#   STAGING_DIR      — directory for the output file (default: /root/phase2-staging)
#   SERVE_URL        — the loopback URL the payload is served from
#                      (default: http://127.0.0.1:8899/f5-payload.bin)
#
# Host-agnostic: SOCKS5 credentials are read in-shell from the file
# named by SOCKS5_CRED_FILE; they are never printed or embedded here.
#
# Usage:  bash f6-client.sh
set -u
SOCKS5_CRED_FILE="${SOCKS5_CRED_FILE:-/root/socks5-credentials.txt}"
STAGING_DIR="${STAGING_DIR:-/root/phase2-staging}"
SERVE_URL="${SERVE_URL:-http://127.0.0.1:8899/f5-payload.bin}"
H=$(awk -F= '$1=="host"{print $2}' "$SOCKS5_CRED_FILE")
P=$(awk -F= '$1=="port"{print $2}' "$SOCKS5_CRED_FILE")
U=$(awk -F= '$1=="username"{print $2}' "$SOCKS5_CRED_FILE")
PASS=$(awk -F= '$1=="password"{print $2}' "$SOCKS5_CRED_FILE")

START=$(date +%s.%N)
OUT="${STAGING_DIR}/f6-dl.bin"
code=$(curl -s -o "$OUT" -w "%{http_code}" --max-time 25 \
  --proxy "socks5h://$U:$PASS@$H:$P" "$SERVE_URL")
END=$(date +%s.%N)
ELAPSED=$(python3 -c "print(f\"{float('$END')-float('$START'):.2f}\")")
BYTES=$(stat -c%s "$OUT" 2>/dev/null || echo 0)
echo "F6-DL: http_code=$code bytes=$BYTES elapsed_s=$ELAPSED"
