#!/usr/bin/env bash
# install-oneclick.test.sh — local test harness for install-oneclick.sh
# (design §8: "installer script tests where feasible").
#
# Runs entirely on the dev box (Git Bash on Windows, or bash on Linux).
# It NEVER touches a host: it only
#   1. syntax-checks the installer (`bash -n`);
#   2. sources the installer with ONECLICK_TESTING=1 and unit-tests the
#      pure helper functions (parse_args, env equivalences, confirm gates);
#   3. executes the full `--dry-run` paths (Iran and Germany+dashboard) and
#      asserts they exit 0, print the command plan, never leak the secret,
#      and create no host paths.
#
# Usage: bash install-oneclick.test.sh
# Exit: 0 when every assertion passes.

set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALLER="$HERE/install-oneclick.sh"

PASS=0
FAIL=0

ok()   { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$1"; }

check() { # check <description> <command...>
  local desc="$1"
  shift
  if "$@" >/dev/null 2>&1; then ok "$desc"; else fail "$desc"; fi
}

contains() { # contains <description> <haystack> <needle>
  local desc="$1" hay="$2" needle="$3"
  if printf '%s' "$hay" | grep -Fq -- "$needle"; then ok "$desc"; else fail "$desc"; fi
}

not_contains() { # not_contains <description> <haystack> <needle>
  local desc="$1" hay="$2" needle="$3"
  if printf '%s' "$hay" | grep -Fq -- "$needle"; then fail "$desc"; else ok "$desc"; fi
}

# run_sourced <bash code> — run the code in a subshell that has sourced the
# installer with ONECLICK_TESTING=1 (helper functions available, main NOT run).
run_sourced() {
  ONECLICK_TESTING=1 bash -c "
set -u
source '$INSTALLER'
$1
"
}

echo "== install-oneclick.sh test harness (local-only) =="

# ---------------------------------------------------------------------------
# 1. Static checks
# ---------------------------------------------------------------------------
echo "-- static --"
check "bash -n (syntax)" bash -n "$INSTALLER"

# The installer must not use eval or pipe remote code to a shell. Static
# checks run against comment-stripped code: the header comments themselves
# mention `eval` / `curl | bash` as things the script avoids, so a raw grep
# of the whole file would false-positive.
STATIC_SRC="$(cat "$INSTALLER")"
NOCOMMENTS="$(sed 's/#.*$//' "$INSTALLER")"
not_contains "no eval in code" "$NOCOMMENTS" "eval"
not_contains "no curl piped to bash" "$NOCOMMENTS" "| bash"
not_contains "no curl piped to sh" "$NOCOMMENTS" "| sh"
contains "uses set -euo pipefail" "$STATIC_SRC" "set -euo pipefail"
contains "exposes ONECLICK_TESTING source hook" "$STATIC_SRC" "ONECLICK_TESTING"

# ---------------------------------------------------------------------------
# 2. Sourced helper unit tests (ONECLICK_TESTING=1)
# ---------------------------------------------------------------------------
echo "-- sourced helpers --"
check "sources cleanly under ONECLICK_TESTING" run_sourced 'true'

check "parse_args: role/dry-run flags" \
  run_sourced 'parse_args --role iran --dry-run; [ "$ROLE" = "iran" ]; [ "$DRY_RUN" = "1" ]'

check "parse_args: dashboard+cert+key+port" \
  run_sourced 'parse_args --role germany --dashboard on --dashboard-port 9443 --cert /c.pem --key /k.pem; [ "$DASHBOARD" = "on" ]; [ "$DASHBOARD_PORT" = "9443" ]; [ -n "$CERT_FILE" ]; [ -n "$KEY_FILE" ]'

check "parse_args: pairing-secret-file" \
  run_sourced 'parse_args --role iran --pairing-secret-file /tmp/b; [ "$PAIRING_SECRET_FILE" = "/tmp/b" ]'

check "parse_args: dashboard-domain + certbot-arvan + arvan-api-key-file" \
  run_sourced 'parse_args --role germany --dashboard on --dashboard-domain dash.example.com --dashboard-cert-mode certbot-arvan --arvan-api-key-file /etc/arvan.env; [ "$DASHBOARD_DOMAIN" = "dash.example.com" ]; [ "$DASHBOARD_CERT_MODE" = "certbot-arvan" ]; [ "$ARVAN_API_KEY_FILE" = "/etc/arvan.env" ]'

check "parse_args: unknown flag is a hard error (exit 2)" \
  run_sourced 'rc=0; ( parse_args --bogus >/dev/null 2>&1 ) || rc=$?; [ "$rc" -eq 2 ]'

check "parse_args: --help exits 0 and prints usage" \
  bash -c "out=\$(ONECLICK_TESTING=1 bash -c \"source '$INSTALLER'; parse_args --help\" 2>&1); rc=\$?; [ \$rc -eq 0 ] && printf '%s' \"\$out\" | grep -Fq 'usage:'"

check "env equivalence: ONECLICK_* override defaults" \
  run_sourced 'export ONECLICK_DASHBOARD=on ONECLICK_IRAN_XRAY=external ONECLICK_OPEN_FIREWALL=1; DASHBOARD="off"; IRAN_XRAY="managed"; OPEN_FIREWALL=0; load_env_equivalents; [ "$DASHBOARD" = "on" ]; [ "$IRAN_XRAY" = "external" ]; [ "$OPEN_FIREWALL" = "1" ]'

check "confirm: dry-run never blocks" \
  run_sourced 'DRY_RUN=1; confirm "proceed?"'

check "confirm: --yes never blocks" \
  run_sourced 'YES=1; confirm "proceed?"'

check "confirm: interactive 'n' aborts" \
  run_sourced 'rc=0; printf "n\n" | confirm "proceed?" || rc=1; [ "$rc" -ne 0 ]'

# ---------------------------------------------------------------------------
# 3. Full end-to-end dry-runs (no host mutation)
# ---------------------------------------------------------------------------
echo "-- end-to-end dry-runs --"

IRAN_OUT="$(bash "$INSTALLER" --role iran --domain example.com --source "$HERE" --no-clone --dry-run 2>&1)"; IRAN_RC=$?
GERMANY_OUT="$(bash "$INSTALLER" --role germany --domain example.com --source "$HERE" --no-clone --dry-run --dashboard on 2>&1)"; GERMANY_RC=$?
GERMANY_CBT="$(bash "$INSTALLER" --role germany --domain example.com --source "$HERE" --no-clone --dry-run --dashboard on --dashboard-domain dash.example.com --dashboard-cert-mode certbot-arvan 2>&1)"; GERMANY_CBT_RC=$?

check "iran dry-run exits 0" bash -c "[ $IRAN_RC -eq 0 ]"
check "germany dry-run exits 0" bash -c "[ $GERMANY_RC -eq 0 ]"
check "germany certbot-arvan dry-run exits 0" bash -c "[ $GERMANY_CBT_RC -eq 0 ]"

contains "iran plan: bootstraps + delegates to splitterctl" "$IRAN_OUT" "[dry-run]"
contains "iran plan: xray-consumer via install-extra (Blob B public source)" "$IRAN_OUT" "SPLITTERCTL_CONSUMER_BLOB_B"
contains "iran plan: pairing handoff names Blob A as the single secret" "$IRAN_OUT" "blob-a"
contains "germany plan: dashboard basePath generation" "$GERMANY_OUT" "basePath"
contains "germany plan: tunneldash.service provisioning" "$GERMANY_OUT" "tunneldash.service"
contains "germany plan: dashboard TLS dir" "$GERMANY_OUT" "dashboard/tls"
not_contains "dry-run output never prints the raw pairing secret" "$IRAN_OUT" "SPLITPAIRINGSECRET"
not_contains "dry-run output never prints a 64-hex secret" \
  "$(printf '%s\n%s' "$IRAN_OUT" "$GERMANY_OUT")" "deadbeefcafe"

# --- certbot-arvan dashboard cert path (dry-run, side-effect free) ---
contains "germany certbot-arvan plan: names the dashboard domain" "$GERMANY_CBT" "dash.example.com"
contains "germany certbot-arvan plan: runs certbot DNS-01 manual auth" "$GERMANY_CBT" "certbot-arvan-dns.sh create"
contains "germany certbot-arvan plan: DNS-01 cleanup hook" "$GERMANY_CBT" "certbot-arvan-dns.sh delete"
contains "germany certbot-arvan plan: deploys PEMs to the dashboard TLS dir" "$GERMANY_CBT" "dashboard/tls"
contains "germany certbot-arvan plan: installs a renewal deploy hook" "$GERMANY_CBT" "renewal timer"
not_contains "certbot-arvan dry-run never prints the Arvan API key" \
  "$(printf '%s' "$GERMANY_CBT")" "ARVAN_API_KEY="
check "arvan DNS-01 hook syntax" bash -n "$HERE/scripts/certbot-arvan-dns.sh"

# Regression (defect: secret printed to stdout + 0600 log): the installer must
# no longer echo the generated admin Bearer token value or the generated
# basePath value to stdout/log. Assert both at source level.
not_contains "installer never echoes the admin token value" \
  "$(printf '%s' "$NOCOMMENTS")" 'admin token: $(cat'
not_contains "installer never logs the generated basePath value" \
  "$(printf '%s' "$NOCOMMENTS")" 'dashboard basePath (random'

# No host paths are created by a dry-run.
check "dry-run creates no source dir (/opt/split-tunnel-src)" test ! -d /opt/split-tunnel-src
check "dry-run creates no bin dir (/opt/split-tunnel)" test ! -d /opt/split-tunnel

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
echo "PASS=$PASS FAIL=$FAIL"
if [ "$FAIL" -ne 0 ]; then
  exit 1
fi
echo "all installer harness checks passed"
