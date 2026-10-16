#!/bin/bash
# f5-serve.sh — Phase 2 F5 setup helper (Germany side).
#
# Purpose:
#   Creates a deterministic 20 MiB payload and serves it on 0.0.0.0:8899
#   so the Iran side can download it THROUGH the tunnel. The F5 443-block
#   does not touch port 8899, so the source stays up during the test.
#
# Required environment variables:
#   STAGING_DIR — directory for the payload and server state
#                 (default: /root/phase2-staging)
#
# Host-agnostic: no credentials or keys are used; only a local HTTP server
# on port 8899.
#
# Usage:  bash f5-serve.sh
set -u
STAGING_DIR="${STAGING_DIR:-/root/phase2-staging}"
cd "$STAGING_DIR"
# Exactly 20971520 bytes: 16-char pattern repeated 1165084 times + first 8 bytes.
python3 -c "p=b'PHASE2-F5-PAYLOAD1'; open('f5-payload.bin','wb').write(p*1165084 + p[:8])"
# Idempotent: kill any stale 8899 server first.
pkill -f "http.server 8899" 2>/dev/null; sleep 1
nohup python3 -m http.server 8899 --bind 0.0.0.0 >/dev/null 2>&1 &
sleep 1
echo "F5-SERVE: bytes=$(stat -c%s f5-payload.bin) server-8899=$(pgrep -f 'http.server 8899' | tr '\n' ' ')"
