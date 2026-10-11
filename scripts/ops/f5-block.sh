#!/bin/bash
# f5-block.sh — Phase 2 F5 bounded fault-injection helper (Germany side).
#
# Purpose:
#   Blocks TCP port 443 (instance A down-carrier) for a bounded window
#   with a self-restoring iptables rule. The restore fires automatically
#   at T+90 s so an operator interruption cannot leave the firewall
#   broken permanently.
#
# Required environment variables (all have safe defaults):
#   STAGING_DIR   — directory for the restore log (default: /root/phase2-staging)
#
# Host-agnostic: uses only iptables INPUT rules and a log file; no
# credentials, keys, or host-specific secrets are embedded.
#
# Usage:  bash f5-block.sh
set -u
STAGING_DIR="${STAGING_DIR:-/root/phase2-staging}"
T0=$(date +%s)
nohup sh -c "sleep 90; iptables -D INPUT -p tcp --dport 443 -j DROP; echo \"F5-restore-443 ok\" > ${STAGING_DIR}/f5-restore.log" >/dev/null 2>&1 &
iptables -I INPUT -p tcp --dport 443 -j DROP
echo "F5-BLOCK: 443 blocked at epoch=$T0 (self-restore at T+90s)"
iptables -L INPUT -n | grep -E "443" | head -n 3
echo "F5-BLOCK-EXIT=0"
