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
SECRET_STORE="$WORK/secret-store"
check_root()   { :; }
check_system() { :; }
ensure_go()    { echo "[stub] ensure_go"; }
# Fake binary: answers --validate-config with exit 0 unless the
# FAKE_GATE_FAIL env var is set (then it simulates a config rejection).
build_binary() { echo "[stub] build_binary $ROLE"
  cat > "$INSTALL_DIR/${ROLE}-splitter" <<'EOF'
#!/bin/bash
if [ "${1:-}" = "--validate-config" ]; then
  if [ -n "${FAKE_GATE_FAIL:-}" ]; then
    echo "configuration validation failed:" >&2
    echo "  - SPLIT_UP_WS_URL: still the placeholder; set the real CDN up-carrier URL" >&2
    exit 1
  fi
  echo "${0##*/}: configuration OK (role: ${ROLE:-fake})"
fi
exit 0
EOF
  chmod 755 "$INSTALL_DIR/${ROLE}-splitter"; }
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
  SECRET_FROM_STORE=0 SHOW_SECRET=0
}

UNIT_IRAN="$SYSTEMD_DIR/iran-splitter.service"
UNIT_GERMANY="$SYSTEMD_DIR/germany-splitter.service"

# A valid (>=32 char) literal secret for the flag-based tests.
LONG_SECRET="aaaaaaaa-bbbbbbbb-cccccccc-dddddddd-eeeeeeee"

# ======================================================================
echo ""
echo "=== Test 1: interactive 'iran' wizard (custom + default answers) ==="
# role passed as arg -> questions in order: secret, socks, ws, down,
# cdn-domain, nginx?, nginx-port, xray-config, xray-service, metrics, relay
# (printf: heredocs strip TRAILING blank lines, which would shift the answers)
reset_state
printf '%s\n' \
  "$LONG_SECRET" \
  "" \
  "" \
  "" \
  "cdn.test.com" \
  "y" \
  "" \
  "skip" \
  "3x-ui" \
  "" \
  "" \
  "__sentinel__" > "$WORK/ans1"
if ( main iran ) < "$WORK/ans1" > "$WORK/out1" 2>&1; then ok "exit code 0"; else fail "exit code 0 (see out1)"; fi
if [ -f "$UNIT_IRAN" ]; then ok "unit file created"; else fail "unit file created"; fi
assert_contains "$UNIT_IRAN" "Environment=SPLIT_SECRET=${LONG_SECRET}"          "unit: secret"
assert_contains "$UNIT_IRAN" "Environment=SPLIT_SOCKS_LISTEN=127.0.0.1:10900"    "unit: socks default"
assert_contains "$UNIT_IRAN" "Environment=SPLIT_WS_LISTEN=127.0.0.1:9001"        "unit: ws default"
assert_contains "$UNIT_IRAN" "Environment=SPLIT_DOWN_CARRIER_ADDR=127.0.0.1:10802" "unit: down-carrier default"
assert_contains "$UNIT_IRAN" "Environment=SPLIT_METRICS_PORT=0"                  "unit: metrics default"
assert_contains "$UNIT_IRAN" "Environment=SPLIT_RELAY_BUF=32768"                 "unit: relay default"
assert_contains "$UNIT_IRAN" "After=network-online.target 3x-ui.service"         "unit: xray ordering"
assert_contains "$UNIT_IRAN" "ExecStart=$INSTALL_DIR/iran-splitter"              "unit: execstart"
assert_contains "$WORK/out1" "wss://cdn.test.com/upload"                         "summary: CDN URL for Germany"
assert_contains "$WORK/out1" "systemctl status iran-splitter"                    "summary: status hint"
# Phase 8: the secret is masked in the summary by default
assert_not_contains "$WORK/out1" "Secret:        ${LONG_SECRET}"                 "summary: secret masked"
assert_contains "$WORK/out1" "**** (hidden"                                      "summary: masked marker"
# Phase 8: the cross-node command uses the secret FILE, not the value
assert_contains "$WORK/out1" "--secret-file"                                     "summary: file-based hand-off"
assert_not_contains "$WORK/out1" "--secret ${LONG_SECRET}"                       "summary: no secret on command line"
# Phase 8: unit is root-readable-only (640) — GNU stat first, BSD/macOS
# fallback. On git-bash/Windows chmod is emulated and the mode bits are
# not observable, so the assertion is skipped there (it holds on Linux).
case "$(uname -s 2>/dev/null || echo unknown)" in
  MINGW*|MSYS*|CYGWIN*)
    ok "unit mode 640 (skipped on Windows: chmod not observable)"
    ;;
  *)
    UNIT_MODE="$(stat -c '%a' "$UNIT_IRAN" 2>/dev/null || stat -f '%Lp' "$UNIT_IRAN" 2>/dev/null || true)"
    if [ "$UNIT_MODE" = "640" ]; then ok "unit mode 640"; else fail "unit mode 640 (got: ${UNIT_MODE:-unknown})"; fi
    ;;
esac

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
# Phase 8: auto-generated secret is 64 hex chars (256 bits)
if grep -qE 'Environment=SPLIT_SECRET=[0-9a-f]{64}' "$UNIT_GERMANY"; then ok "unit: generated 64-hex secret"; else fail "unit: generated 64-hex secret"; fi

# ======================================================================
echo ""
echo "=== Test 3: non-interactive 'germany --yes' (flags + defaults) ==="
reset_state
if ( main germany --yes --down-listen 0.0.0.0:9003 --up-ws-url wss://cdn2.example.org/upload \
      --secret "$LONG_SECRET" ) < /dev/null > "$WORK/out3" 2>&1
then ok "exit code 0"; else fail "exit code 0 (see out3)"; fi
assert_contains "$UNIT_GERMANY" "Environment=SPLIT_DOWN_LISTEN=0.0.0.0:9003"     "unit: flag down listen"
assert_contains "$UNIT_GERMANY" "Environment=SPLIT_UP_WS_URL=wss://cdn2.example.org/upload" "unit: flag up ws url"
assert_contains "$UNIT_GERMANY" "Environment=SPLIT_SECRET=${LONG_SECRET}"        "unit: flag secret"

# ======================================================================
echo ""
echo "=== Test 4: --yes with invalid flag value fails cleanly ==="
reset_state
if ( main iran --yes --socks-listen "not-a-port" ) < /dev/null > "$WORK/out4" 2>&1
then fail "should have failed on invalid flag"; else ok "non-zero exit on invalid flag"; fi
assert_contains "$WORK/out4" "is invalid"                                        "clear error message"

# ======================================================================
echo ""
echo "=== Test 4b: Phase 6 secret policy enforced by the installer ==="
# short secret (pre-Phase 8 bug: 8-127 chars were accepted)
reset_state
if ( main germany --yes --up-ws-url wss://cdn.test.com/upload \
      --secret abcdefgh1234567890 ) < /dev/null > "$WORK/out4b" 2>&1
then fail "short secret must be rejected"; else ok "short secret rejected"; fi
assert_contains "$WORK/out4b" "minimum 32 characters"                            "short secret error"
# blocklisted placeholder
reset_state
if ( main iran --yes --secret "change-me-please" ) < /dev/null > "$WORK/out4b2" 2>&1
then fail "blocklisted secret must be rejected"; else ok "blocklisted secret rejected"; fi
assert_contains "$WORK/out4b2" "minimum 32 characters"                           "blocklist error"

# ======================================================================
echo ""
echo "=== Test 4c: placeholder up-carrier URL rejected ==="
reset_state
if ( main germany --yes --up-ws-url wss://cdn.example.com/upload \
      --secret "$LONG_SECRET" ) < /dev/null > "$WORK/out4c" 2>&1
then fail "placeholder URL must be rejected"; else ok "placeholder URL rejected"; fi
assert_contains "$WORK/out4c" "placeholder"                                      "placeholder URL error"
# wrong path
reset_state
if ( main germany --yes --up-ws-url wss://cdn.test.com/wrongpath \
      --secret "$LONG_SECRET" ) < /dev/null > "$WORK/out4c2" 2>&1
then fail "wrong path must be rejected"; else ok "wrong path rejected"; fi
assert_contains "$WORK/out4c2" "/upload"                                         "path error message"

# ======================================================================
echo ""
echo "=== Test 4d: bare :port and bracketed IPv6 are accepted ==="
reset_state
if ( main germany --yes --down-listen :9005 --up-ws-url wss://cdn.test.com/upload \
      --secret "$LONG_SECRET" ) < /dev/null > "$WORK/out4d" 2>&1
then ok "bare :port accepted"; else fail "bare :port accepted (see out4d)"; fi
assert_contains "$UNIT_GERMANY" "Environment=SPLIT_DOWN_LISTEN=:9005"            "unit: bare :port"
reset_state
if ( main iran --yes --socks-listen '[::1]:10910' \
      --secret "$LONG_SECRET" ) < /dev/null > "$WORK/out4d2" 2>&1
then ok "bracketed IPv6 accepted"; else fail "bracketed IPv6 accepted (see out4d2)"; fi
assert_contains "$UNIT_IRAN" "Environment=SPLIT_SOCKS_LISTEN=[::1]:10910"        "unit: IPv6"

# ======================================================================
echo ""
echo "=== Test 4e: configuration gate failure aborts BEFORE install ==="
rm -f "$UNIT_GERMANY"
reset_state
if ( FAKE_GATE_FAIL=1 main germany --yes --up-ws-url wss://cdn.test.com/upload \
      --secret "$LONG_SECRET" ) < /dev/null > "$WORK/out4e" 2>&1
then fail "gate failure must abort the install"; else ok "gate failure aborts install"; fi
assert_contains "$WORK/out4e" "REJECTED this configuration"                      "gate error shown"
assert_contains "$WORK/out4e" "nothing was installed"                            "nothing installed message"
if [ ! -f "$UNIT_GERMANY" ]; then ok "unit NOT written on gate failure"; else fail "unit NOT written on gate failure"; fi

# ======================================================================
echo ""
echo "=== Test 4f: --secret-file is used and never echoed back ==="
printf '%s\n' "$LONG_SECRET" > "$WORK/secret-file"
chmod 600 "$WORK/secret-file" 2>/dev/null || true
reset_state
if ( main germany --yes --up-ws-url wss://cdn.test.com/upload \
      --secret-file "$WORK/secret-file" ) < /dev/null > "$WORK/out4f" 2>&1
then ok "exit code 0"; else fail "exit code 0 (see out4f)"; fi
assert_contains "$UNIT_GERMANY" "Environment=SPLIT_SECRET=${LONG_SECRET}"        "unit: secret from file"
assert_not_contains "$WORK/out4f" "Secret:        ${LONG_SECRET}"                "summary: file secret masked"

# ======================================================================
echo ""
echo "=== Test 4g: --show-secret reveals the value ==="
reset_state
if ( main germany --yes --up-ws-url wss://cdn.test.com/upload \
      --secret "$LONG_SECRET" --show-secret ) < /dev/null > "$WORK/out4g" 2>&1
then ok "exit code 0"; else fail "exit code 0 (see out4g)"; fi
assert_contains "$WORK/out4g" "Secret:        ${LONG_SECRET}"                    "summary: secret shown"

# ======================================================================
echo ""
echo "=== Test 4h: upgrade pre-fills + keeps the existing secret ==="
cat > "$UNIT_IRAN" <<EOF
[Unit]
Description=old

[Service]
Type=simple
ExecStart=/usr/local/bin/iran-splitter
Environment=SPLIT_SOCKS_LISTEN=127.0.0.1:10999
Environment=SPLIT_WS_LISTEN=127.0.0.1:9011
Environment=SPLIT_DOWN_CARRIER_ADDR=127.0.0.1:10899
Environment=SPLIT_SECRET=${LONG_SECRET}
Environment=SPLIT_METRICS_PORT=9150
Environment=SPLIT_RELAY_BUF=16384

[Install]
WantedBy=multi-user.target
EOF
reset_state
if ( main iran --yes --xray-config skip ) < /dev/null > "$WORK/out4h" 2>&1
then ok "exit code 0"; else fail "exit code 0 (see out4h)"; fi
assert_contains "$UNIT_IRAN" "Environment=SPLIT_SOCKS_LISTEN=127.0.0.1:10999"    "upgrade: kept socks"
assert_contains "$UNIT_IRAN" "Environment=SPLIT_WS_LISTEN=127.0.0.1:9011"        "upgrade: kept ws"
assert_contains "$UNIT_IRAN" "Environment=SPLIT_DOWN_CARRIER_ADDR=127.0.0.1:10899" "upgrade: kept down"
assert_contains "$UNIT_IRAN" "Environment=SPLIT_SECRET=${LONG_SECRET}"           "upgrade: kept secret"
assert_contains "$UNIT_IRAN" "Environment=SPLIT_METRICS_PORT=9150"               "upgrade: kept metrics"
assert_contains "$UNIT_IRAN" "Environment=SPLIT_RELAY_BUF=16384"                 "upgrade: kept relay"
if ls "$SYSTEMD_DIR"/iran-splitter.service.bak.* >/dev/null 2>&1; then ok "old unit backed up"; else fail "old unit backed up"; fi
assert_contains "$WORK/out4h" "Existing installation detected"                   "upgrade: detection message"

# ======================================================================
echo ""
echo "=== Test 5: uninstall removes unit + binary ==="
reset_state
printf 'fake' > "$INSTALL_DIR/iran-splitter"
if ( main uninstall iran ) < /dev/null > "$WORK/out5" 2>&1
then ok "exit code 0"; else fail "exit code 0 (see $WORK/out5)"; fi
if [ ! -f "$UNIT_IRAN" ]; then ok "unit removed"; else fail "unit removed"; fi
if [ ! -f "$INSTALL_DIR/iran-splitter" ]; then ok "binary removed"; else fail "binary removed"; fi
assert_contains "$WORK/out5" "Rollback: previous binary"                         "uninstall: rollback hint"

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
assert_contains "$WORK/out7" "--secret-file"                                     "help lists secret-file"

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
        --xray-inbound user-vless-reality --secret "$LONG_SECRET" ) < /dev/null > "$WORK/out8" 2>&1
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
        --xray-inbound user-vless-reality --secret "$LONG_SECRET" ) < /dev/null > "$WORK/out8b" 2>&1
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
      --ws-listen 127.0.0.1:9050 --xray-config skip --secret "$LONG_SECRET" ) < /dev/null > "$WORK/out9" 2>&1
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
      --xray-config skip --secret "$LONG_SECRET" ) < /dev/null > "$WORK/out9b" 2>&1
then ok "9b exit 0"; else fail "9b exit 0 (see out9b)"; fi
assert_not_contains "$NGXCONF" "default_server"                                  "does not steal existing default_server"

echo ""
echo "=============================================="
echo "PASS: $PASS   FAIL: $FAIL"
rm -rf "$WORK"
[ "$FAIL" -eq 0 ]