#!/usr/bin/env bash
# Functional test harness for install.sh (dev tool, needs bash + git-bash or
# Linux; python is optional and only used for the Xray-merge tests).
# Usage: bash test-install.sh
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
PASS=0
FAIL=0

fail() { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n' "$*"; }
ok()   { PASS=$((PASS+1)); printf '  [ ok ] %s\n' "$*"; }
assert_contains() { # file pattern desc
  if grep -qF -- "$2" "$1" 2>/dev/null; then ok "$3"; else fail "$3 (missing: $2)"; fi
}
assert_not_contains() { # file pattern desc
  if grep -qF -- "$2" "$1" 2>/dev/null; then fail "$3 (found: $2)"; else ok "$3"; fi
}

# --- fake system tools -------------------------------------------------
mkdir -p "$WORK/fakebin" "$WORK/etc/systemd/system" "$WORK/installbin"
cat > "$WORK/fakebin/systemctl" <<'EOF'
#!/bin/bash
case "$1" in
  list-unit-files) exit 0 ;;   # pretend no xray/3x-ui service exists
  is-active) exit 0 ;;
  *) exit 0 ;;
esac
EOF
cat > "$WORK/fakebin/journalctl" <<'EOF'
#!/bin/bash
exit 0
EOF
chmod +x "$WORK/fakebin/systemctl" "$WORK/fakebin/journalctl"
export PATH="$WORK/fakebin:$PATH"

# --- source the installer (main is guarded by BASH_SOURCE) -------------
# shellcheck source=/dev/null
source "$REPO/install.sh"

# --- overrides for testing --------------------------------------------
INSTALL_DIR="$WORK/installbin"
SYSTEMD_DIR="$WORK/etc/systemd/system"
check_root()   { :; }
check_system() { :; }
ensure_go()    { echo "[stub] ensure_go"; }
build_binary() { echo "[stub] build_binary $ROLE"; printf 'fake' > "$INSTALL_DIR/${ROLE}-splitter"; chmod 755 "$INSTALL_DIR/${ROLE}-splitter"; }
# read answers from piped stdin (instead of /dev/tty), echo the question to stderr
read_line() {
  local l=""
  printf '%s' "$PROMPT_LABEL" >&2
  IFS= read -r l || l=""
  printf '%s' "$l"
}

reset_state() {
  ROLE="" SECRET="" SOCKS_LISTEN="" WS_LISTEN="" DOWN_CARRIER_ADDR=""
  CDN_DOMAIN="" NGINX_CONFIG="ask" NGINX_PORT="" XRAY_CONFIG=""
  XRAY_INBOUND_TAG="" XRAY_SERVICE="" DOWN_LISTEN="" UP_WS_URL=""
  METRICS_PORT="" RELAY_BUF="" ASSUME_YES=0 UNINSTALL=0
}

UNIT_IRAN="$SYSTEMD_DIR/iran-splitter.service"
UNIT_GERMANY="$SYSTEMD_DIR/germany-splitter.service"

# ======================================================================
echo ""
echo "=== Test 1: interactive 'iran' wizard (custom + default answers) ==="
# role passed as arg -> 11 questions in order: secret, socks, ws, down,
# cdn-domain, nginx?, nginx-port, xray-config, xray-service, metrics, relay
reset_state
cat > "$WORK/ans1" <<'EOF'
test-secret-123



cdn.test.com
y

skip
3x-ui


EOF
if ( main iran ) < "$WORK/ans1" > "$WORK/out1" 2>&1; then ok "exit code 0"; else fail "exit code 0 (see out1)"; fi
if [ -f "$UNIT_IRAN" ]; then ok "unit file created"; else fail "unit file created"; fi
assert_contains "$UNIT_IRAN" "Environment=SPLIT_SECRET=test-secret-123"          "unit: secret"
assert_contains "$UNIT_IRAN" "Environment=SPLIT_SOCKS_LISTEN=127.0.0.1:10900"    "unit: socks default"
assert_contains "$UNIT_IRAN" "Environment=SPLIT_WS_LISTEN=127.0.0.1:9001"        "unit: ws default"
assert_contains "$UNIT_IRAN" "Environment=SPLIT_DOWN_CARRIER_ADDR=127.0.0.1:10802" "unit: down-carrier default"
assert_contains "$UNIT_IRAN" "Environment=SPLIT_METRICS_PORT=0"                  "unit: metrics default"
assert_contains "$UNIT_IRAN" "Environment=SPLIT_RELAY_BUF=32768"                 "unit: relay default"
assert_contains "$UNIT_IRAN" "After=network-online.target 3x-ui.service"         "unit: xray ordering"
assert_contains "$UNIT_IRAN" "ExecStart=$INSTALL_DIR/iran-splitter"              "unit: execstart"
assert_contains "$WORK/out1" "wss://cdn.test.com/upload"                         "summary: CDN URL for Germany"
assert_contains "$WORK/out1" "systemctl status iran-splitter"                    "summary: status hint"

# ======================================================================
echo ""
echo "=== Test 2: interactive 'germany' wizard (validation + defaults) ==="
# questions: secret, down-listen (invalid then valid), up-ws-url,
# xray-service, metrics, relay
reset_state
# 7 answers: 1 secret(gen), 2 down-listen invalid, 3 down-listen ok,
# 4 up-ws-url, 5 xray-service, 6 metrics, 7 relay
printf '%s\n' \
  "" \
  "9002" \
  "127.0.0.1:9002" \
  "wss://cdn.test.com/upload" \
  "" \
  "9101" \
  "16384" > "$WORK/ans2"
if ( main germany ) < "$WORK/ans2" > "$WORK/out2" 2>&1; then ok "exit code 0"; else fail "exit code 0 (see out2)"; fi
if [ -f "$UNIT_GERMANY" ]; then ok "unit file created"; else fail "unit file created"; fi
assert_contains "$WORK/out2" "Invalid value"                                     "re-prompted on invalid port"
assert_contains "$UNIT_GERMANY" "Environment=SPLIT_DOWN_LISTEN=127.0.0.1:9002"   "unit: down listen (2nd try)"
assert_contains "$UNIT_GERMANY" "Environment=SPLIT_UP_WS_URL=wss://cdn.test.com/upload" "unit: up ws url"
assert_contains "$UNIT_GERMANY" "Environment=SPLIT_METRICS_PORT=9101"            "unit: metrics custom"
assert_contains "$UNIT_GERMANY" "Environment=SPLIT_RELAY_BUF=16384"              "unit: relay custom"
assert_contains "$UNIT_GERMANY" "After=network-online.target"                    "unit: after line"
assert_not_contains "$UNIT_GERMANY" "xray.service"                               "unit: no xray ordering"
if grep -qE 'Environment=SPLIT_SECRET=[0-9a-f]{48}' "$UNIT_GERMANY"; then ok "unit: generated 48-hex secret"; else fail "unit: generated 48-hex secret"; fi

# ======================================================================
echo ""
echo "=== Test 3: non-interactive 'germany --yes' (flags + defaults) ==="
reset_state
if ( main germany --yes --down-listen 0.0.0.0:9003 --up-ws-url wss://cdn2.example.org/upload --secret abcdefgh1234567890 ) < /dev/null > "$WORK/out3" 2>&1
then ok "exit code 0"; else fail "exit code 0 (see out3)"; fi
assert_contains "$UNIT_GERMANY" "Environment=SPLIT_DOWN_LISTEN=0.0.0.0:9003"     "unit: flag down listen"
assert_contains "$UNIT_GERMANY" "Environment=SPLIT_UP_WS_URL=wss://cdn2.example.org/upload" "unit: flag up ws url"
assert_contains "$UNIT_GERMANY" "Environment=SPLIT_SECRET=abcdefgh1234567890"    "unit: flag secret"

# ======================================================================
echo ""
echo "=== Test 4: --yes with invalid flag value fails cleanly ==="
reset_state
if ( main iran --yes --socks-listen "not-a-port" ) < /dev/null > "$WORK/out4" 2>&1
then fail "should have failed on invalid flag"; else ok "non-zero exit on invalid flag"; fi
assert_contains "$WORK/out4" "is invalid"                                        "clear error message"

# ======================================================================
echo ""
echo "=== Test 5: uninstall removes unit + binary ==="
reset_state
printf 'fake' > "$INSTALL_DIR/iran-splitter"
if ( main uninstall iran ) < /dev/null > "$WORK/out5" 2>&1
then ok "exit code 0"; else fail "exit code 0 (see $WORK/out5)"; fi
if [ ! -f "$UNIT_IRAN" ]; then ok "unit removed"; else fail "unit removed"; fi
if [ ! -f "$INSTALL_DIR/iran-splitter" ]; then ok "binary removed"; else fail "binary removed"; fi

# ======================================================================
echo ""
echo "=== Test 6: unknown flag shows usage and fails ==="
if bash "$REPO/install.sh" --bogus > "$WORK/out6" 2>&1
then fail "should have failed on unknown flag"; else ok "non-zero exit"; fi
assert_contains "$WORK/out6" "Unknown option"                                    "unknown option message"
assert_contains "$WORK/out6" "Usage:"                                            "usage shown"

# ======================================================================
echo ""
echo "=== Test 7: --help works without root ==="
if bash "$REPO/install.sh" --help > "$WORK/out7" 2>&1
then ok "exit code 0"; else fail "exit code 0"; fi
assert_contains "$WORK/out7" "Split-Tunnel installer"                            "help text"
assert_contains "$WORK/out7" "--cdn-domain"                                      "help lists flags"

# ======================================================================
echo ""
echo "=== Test 8: Xray config merge (python3) + idempotency ==="
# find a real python interpreter (not the shim we are about to create,
# not broken Windows Store aliases)
PY=""
while IFS= read -r cand; do
  [ -n "$cand" ] || continue
  case "$cand" in *"$WORK/fakebin"*) continue ;; esac
  if [ -x "$cand" ] && "$cand" -c 'import sys' >/dev/null 2>&1; then PY="$cand"; break; fi
done < <(type -ap python3 2>/dev/null; type -ap python 2>/dev/null)
if [ -n "$PY" ]; then
  cat > "$WORK/fakebin/python3" <<EOF
#!/bin/bash
exec "$PY" "\$@"
EOF
  chmod +x "$WORK/fakebin/python3"
  mkdir -p "$WORK/xray"
  cp "$REPO/config/iran-xray-config.json" "$WORK/xray/config.json"
  reset_state
  if ( main iran --yes --xray-config "$WORK/xray/config.json" --xray-service xray \
        --xray-inbound user-vless-reality ) < /dev/null > "$WORK/out8" 2>&1
  then ok "exit code 0"; else fail "exit code 0 (see out8)"; fi
  assert_contains "$WORK/out8" "Backed up Xray config"                             "backup created"
  ls "$WORK/xray"/config.json.bak.* >/dev/null 2>&1 && ok "backup file exists" || fail "backup file exists"
  python_out="$("$PY" - "$WORK/xray/config.json" <<'PYEOF'
import json, sys
cfg = json.load(open(sys.argv[1]))
outs = sum(1 for o in cfg.get("outbounds", []) if o.get("tag") == "to-splitter")
rules = cfg.get("routing", {}).get("rules", [])
rules_match = sum(1 for r in rules if r.get("outboundTag") == "to-splitter"
                  and r.get("inboundTag") == ["user-vless-reality"])
socks = [o for o in cfg.get("outbounds", []) if o.get("tag") == "to-splitter"]
port_ok = bool(socks) and socks[0]["settings"]["servers"][0]["port"] == 10900
first_ok = bool(rules) and rules[0].get("outboundTag") == "to-splitter"
print(f"{outs} {rules_match} {int(port_ok)} {int(first_ok)}")
PYEOF
)"
  if [ "$python_out" = "1 1 1 1" ]; then ok "merge result: 1 outbound, 1 rule, port 10900, rule first"; else fail "merge result (got: $python_out)"; fi
  # idempotency: run again, must not duplicate
  if ( main iran --yes --xray-config "$WORK/xray/config.json" --xray-service xray \
        --xray-inbound user-vless-reality ) < /dev/null > "$WORK/out8b" 2>&1
  then ok "second run exit 0"; else fail "second run exit 0"; fi
  python_out2="$("$PY" - "$WORK/xray/config.json" <<'PYEOF'
import json, sys
cfg = json.load(open(sys.argv[1]))
outs = sum(1 for o in cfg.get("outbounds", []) if o.get("tag") == "to-splitter")
rules = cfg.get("routing", {}).get("rules", [])
rules_match = sum(1 for r in rules if r.get("outboundTag") == "to-splitter"
                  and r.get("inboundTag") == ["user-vless-reality"])
print(f"{outs} {rules_match}")
PYEOF
)"
  if [ "$python_out2" = "1 1" ]; then ok "idempotent: no duplicates"; else fail "idempotent (got: $python_out2)"; fi
else
  ok "no python interpreter found - Xray merge assertions skipped"
fi

# ======================================================================
echo ""
echo "=== Test 9: nginx config generation ==="
cat > "$WORK/fakebin/nginx" <<'EOF'
#!/bin/bash
echo "nginx: configuration file test is successful"
exit 0
EOF
chmod +x "$WORK/fakebin/nginx"
mkdir -p "$WORK/nginxroot/conf.d"
NGINX_ROOT="$WORK/nginxroot"
reset_state
if ( main iran --yes --nginx --cdn-domain cdn.test.com --nginx-port 8443 \
      --ws-listen 127.0.0.1:9050 --xray-config skip ) < /dev/null > "$WORK/out9" 2>&1
then ok "exit code 0"; else fail "exit code 0 (see out9)"; fi
NGXCONF="$WORK/nginxroot/conf.d/split-tunnel.conf"
if [ -f "$NGXCONF" ]; then ok "nginx conf created"; else fail "nginx conf created"; fi
assert_contains "$NGXCONF" "listen 8443;"                                        "public port 8443"
assert_contains "$NGXCONF" "default_server"                                      "claims default_server (none existing)"
assert_contains "$NGXCONF" "server_name cdn.test.com;"                           "server_name from CDN domain"
assert_contains "$NGXCONF" "proxy_pass http://127.0.0.1:9050;"                   "internal WS port from --ws-listen"
assert_contains "$NGXCONF" "location /upload"                                    "upload location"
assert_contains "$NGXCONF" "Managed by split-tunnel installer"                   "management marker"
# 9b: existing default_server elsewhere -> must NOT claim default_server
cat > "$WORK/nginxroot/conf.d/default.conf" <<'EOF'
server {
    listen 80 default_server;
    server_name _;
}
EOF
reset_state
if ( main iran --yes --nginx --nginx-port 8443 --ws-listen 127.0.0.1:9050 \
      --xray-config skip ) < /dev/null > "$WORK/out9b" 2>&1
then ok "9b exit 0"; else fail "9b exit 0"; fi
assert_not_contains "$NGXCONF" "default_server"                                  "does not steal existing default_server"

echo ""
echo "=============================================="
echo "PASS: $PASS   FAIL: $FAIL"
rm -rf "$WORK"
[ "$FAIL" -eq 0 ]