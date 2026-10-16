#!/bin/bash
# f6-block.sh — Phase 2 F6 bounded fault-injection helper (Germany side).
#
# Purpose:
#   Blocks BOTH down-carrier ports (443 = instance A, 2053 = instance B)
#   for a bounded ~30 s window with a self-restoring iptables rule.
#   Used to test multi-carrier failover when both carriers are down.
#
# Required environment variables:
#   STAGING_DIR — directory for the restore log (default: /root/phase2-staging)
#
# Host-agnostic: uses only iptables INPUT rules; no credentials or keys.
#
# Usage:  bash f6-block.sh
set -u
STAGING_DIR="${STAGING_DIR:-/root/phase2-staging}"
T0=$(date +%s)
nohup sh -c "sleep 30; iptables -D INPUT -p tcp --dport 443 -j DROP; iptables -D INPUT -p tcp --dport 2053 -j DROP; echo \"F6-restore ok\" > ${STAGING_DIR}/f6-restore.log" >/dev/null 2>&1 &
iptables -I INPUT -p tcp --dport 443 -j DROP
iptables -I INPUT -p tcp --dport 2053 -j DROP
echo "F6-BLOCK: 443+2053 blocked at epoch=$T0 (self-restore at T+30s)"
iptables -L INPUT -n | grep -E "443|2053" | head -n 4
echo "F6-BLOCK-EXIT=0"
