#!/usr/bin/env bash
# certbot-arvan-dns.sh — ArvanCloud DNS-01 helper for certbot (manual authenticator).
#
# certbot owns the ACME account/key; this script manages the
# _acme-challenge TXT record on an Arvan-managed zone via the Arvan CDN API
# (https://napi.arvancloud.ir/cdn/4.0/domains/<zone>/dns-records) and waits
# for public DNS propagation.
#
# Security:
#   - The API key is read from a 0600 env file and passed to curl via a
#     0600 -K config file, so it NEVER appears on any process command line
#     or in logs.
#   - The ACME TXT value is public (a digest); it is safe to log.
#   - The key itself is never printed.
#
# Subcommands:
#   create <domain-or-fqdn> <txt-value>   create _acme-challenge TXT + wait for propagation
#   delete <domain-or-fqdn>               delete _acme-challenge TXT (idempotent)
#   help
#
# <domain-or-fqdn> may be the bare leaf certbot passes ($CERTBOT_DOMAIN,
# e.g. "dash.ctoplace.ir") or the full FQDN "_acme-challenge.dash.ctoplace.ir".
# The zone-relative record name is derived from ARVAN_DOMAIN.
#
# Env vars (all optional):
#   ARVAN_API_KEY_FILE       0600 shell env file with "ARVAN_API_KEY=<token>"
#                            (default /etc/split-tunnel/arvan/env)
#   ARVAN_API_KEY            used directly when set (CRLF-safe)
#   ARVAN_DOMAIN             Arvan-managed zone (default ctoplace.ir)
#   ARVAN_API_BASE           API base (default https://napi.arvancloud.ir/cdn/4.0)
#   ARVAN_PROPAGATION_TRIES  default 12
#   ARVAN_PROPAGATION_SLEEP  default 5 (seconds)
#
# certbot invocation (xray keeps :443; DNS-01 via --manual needs no HTTP
# verifier on the host):
#
#   certbot certificate issue \
#     --manual --preferred-challenges dns \
#     -d dash.ctoplace.ir \
#     --manual-auth-hook "ARVAN_DOMAIN=ctoplace.ir ARVAN_API_KEY_FILE=/etc/split-tunnel/arvan/env /opt/split-tunnel/scripts/certbot-arvan-dns.sh create \$CERTBOT_DOMAIN \$CERTBOT_VALIDATION" \
#     --manual-cleanup-hook "ARVAN_DOMAIN=ctoplace.ir ARVAN_API_KEY_FILE=/etc/split-tunnel/arvan/env /opt/split-tunnel/scripts/certbot-arvan-dns.sh delete \$CERTBOT_DOMAIN" \
#     --key-type ecdsa --no-verify-ssl
#
# Renewal: `certbot renew` re-runs both hooks. Add a deploy hook
# (systemctl restart tunneldash) via /etc/letsencrypt/renewal-hooks/deploy/.
#
# Exit codes: 0 ok, 1 API/propagation failure, 2 usage error, 3 key missing.

set -euo pipefail
IFS=$'\n\t'

readonly ARVAN_DOMAIN_DEFAULT="ctoplace.ir"
readonly ARVAN_API_BASE_DEFAULT="https://napi.arvancloud.ir/cdn/4.0"
readonly ARVAN_API_KEY_FILE_DEFAULT="/etc/split-tunnel/arvan/env"
readonly ARVAN_PROPAGATION_TRIES_DEFAULT=12
readonly ARVAN_PROPAGATION_SLEEP_DEFAULT=5

_log() { printf '  [i] %s\n' "$*" >&2; }
_err() { printf '  [x] %s\n' "$*" >&2; }

# ---------------------------------------------------------------------------
# resolve_api_key: populate ARVAN_API_KEY without ever printing it.
# CRLF-safe: strips \r\n from the sourced value.
# ---------------------------------------------------------------------------
resolve_api_key() {
  local keyfile="${ARVAN_API_KEY_FILE:-$ARVAN_API_KEY_FILE_DEFAULT}"
  if [ -z "${ARVAN_API_KEY:-}" ]; then
    if [ ! -r "$keyfile" ]; then
      _err "cannot read Arvan API key file: ${keyfile} (expected a 0600 file: ARVAN_API_KEY=<token>)"
      exit 3
    fi
    # shellcheck disable=SC1090
    . "$keyfile"
  fi
  # Strip CRLF artifacts (the env file is often CRLF on Windows); key has no
  # spaces, so also drop any stray whitespace.
  ARVAN_API_KEY="$(printf '%s' "${ARVAN_API_KEY:-}" | tr -d '\r\n ')"
  if [ -z "${ARVAN_API_KEY:-}" ]; then
    _err "ARVAN_API_KEY is empty after reading ${keyfile}."
    exit 3
  fi
}

# ---------------------------------------------------------------------------
# _api <METHOD> <relpath> [json-body]
# Prints the raw response body; returns 1 on transport/HTTP failure.
# The auth header goes into a 0600 curl -K config file that is unlinked
# before the function returns, so the key value is never in argv.
# ---------------------------------------------------------------------------
_api() {
  local method="$1" rel="${2:-}" body="${3:-}"
  local domain="${ARVAN_DOMAIN:-$ARVAN_DOMAIN_DEFAULT}"
  local base="${ARVAN_API_BASE:-$ARVAN_API_BASE_DEFAULT}"
  local url="${base}/domains/${domain}${rel:+/${rel}}"
  local key="${ARVAN_API_KEY}"
  local cfg rc out

  cfg="$(mktemp /tmp/.arvan-cfg.XXXXXX)"
  {
    printf 'header = "Authorization: apikey %s"\n' "$key"
    printf 'header = "Accept: application/json"\n'
    if [ -n "$body" ]; then
      printf 'header = "Content-Type: application/json"\n'
    fi
  } > "$cfg"
  chmod 0600 "$cfg"

  local -a args=( curl -sS --fail-with-body --retry 3 --max-time 30 \
                  -X "$method" "$url" -K "$cfg" )
  if [ -n "$body" ]; then
    args+=( --data "$body" )
  fi

  out="$( "${args[@]}" 2>/dev/null )"
  rc=$?
  rm -f "$cfg"
  if [ $rc -ne 0 ]; then
    _err "Arvan API ${method} /domains/${domain}${rel:+/${rel}} failed (curl rc=${rc}): ${out}"
    return 1
  fi
  printf '%s' "$out"
}

# ---------------------------------------------------------------------------
# find_txt_record_id <zone-relative-name> -> echoes record id (empty if absent)
# ---------------------------------------------------------------------------
find_txt_record_id() {
  local rec_name="$1" resp
  if ! resp="$( _api GET "dns-records?per_page=200" )"; then
    return 0
  fi
  printf '%s' "$resp" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for r in (d.get("data") or []):
    if r.get("name") == sys.argv[1] and str(r.get("type","")).lower() == "txt":
        print(r.get("id"))
        break
' "$rec_name" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Zone-relative name helpers
# ---------------------------------------------------------------------------
_zone_rel() {
  local fqdn="$1" domain="${ARVAN_DOMAIN:-$ARVAN_DOMAIN_DEFAULT}"
  case "$fqdn" in
    *".${domain}") printf '%s' "${fqdn%.$domain}" ;;
    *)            printf '%s' "$fqdn" ;;
  esac
}

# challenge_rel -> _acme-challenge.<zone-relative-leaf>  (record name in zone)
challenge_rel() {
  local z
  z="$(_zone_rel "$1")"
  case "$z" in
    _acme-challenge.*) printf '%s' "$z" ;;
    *)                printf '_acme-challenge.%s' "$z" ;;
  esac
}

# full_challenge_fqdn -> _acme-challenge.<leaf>.<zone>  (public name for dig)
full_challenge_fqdn() {
  local z
  z="$(_zone_rel "$1")"
  case "$z" in
    _acme-challenge.*) printf '%s.%s' "$z" "${ARVAN_DOMAIN:-$ARVAN_DOMAIN_DEFAULT}" ;;
    *)                printf '_acme-challenge.%s.%s' "$z" "${ARVAN_DOMAIN:-$ARVAN_DOMAIN_DEFAULT}" ;;
  esac
}

# ---------------------------------------------------------------------------
# create <domain-or-fqdn> <txt-value>
# ArvanCloud TXT value shape: [{ "text": { "value": "<txt>" } }]
# ---------------------------------------------------------------------------
create_challenge() {
  local fqdn="$1" value="$2"
  local rec_name body resp new_id old_id

  rec_name="$(challenge_rel "$fqdn")"

  # ArvanCloud TXT record value shape (confirmed via API probe): a singular
  # object { "text": { "value": "<txt>" } } (not an array), TTL 300.
  body="$(python3 -c '
import json, sys
print(json.dumps({
    "name":  sys.argv[1],
    "type":  "txt",
    "value": {"text": {"value": sys.argv[2]}},
    "ttl":   300,
    "cloud": False
}))
' "$rec_name" "$value")"

  # Idempotent: delete any pre-existing TXT with the same record name.
  old_id="$(find_txt_record_id "$rec_name" || true)"
  if [ -n "$old_id" ]; then
    _log "removing pre-existing TXT ${rec_name} (id ${old_id})"
    if ! _api DELETE "dns-records/${old_id}" > /dev/null; then
      _err "failed to delete pre-existing TXT record ${old_id}; aborting."
      return 1
    fi
  fi

  if ! resp="$( _api POST "dns-records" "$body" )"; then
    _err "Arvan API POST for TXT ${rec_name} failed; aborting."
    return 1
  fi

  new_id="$(printf '%s' "$resp" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    print((d.get("data") or {}).get("id") or "")
except Exception:
    pass
' 2>/dev/null || true)"
  _log "created TXT ${rec_name}${new_id:+ (record id ${new_id})}."

  wait_for_propagation "$(full_challenge_fqdn "$fqdn")" "$value"
}

# ---------------------------------------------------------------------------
# delete <domain-or-fqdn>
# ---------------------------------------------------------------------------
delete_challenge() {
  local fqdn="$1" rec_name id
  rec_name="$(challenge_rel "$fqdn")"
  id="$(find_txt_record_id "$rec_name" || true)"
  if [ -z "$id" ]; then
    _log "no TXT ${rec_name} on the zone; nothing to delete."
    return 0
  fi
  if _api DELETE "dns-records/${id}" > /dev/null; then
    _log "deleted TXT ${rec_name} (id ${id})."
  else
    _err "failed to delete TXT ${rec_name} (id ${id})."
    return 1
  fi
}

# ---------------------------------------------------------------------------
# Public DNS TXT lookup: dig -> host -> python3 raw-UDP fallback.
# ---------------------------------------------------------------------------
_lookup_txt() {
  local fqdn="$1"
  if command -v dig >/dev/null 2>&1; then
    dig +short +time=5 +tries=2 TXT "${fqdn}." 2>/dev/null | tr -d '"' || true
  elif command -v host >/dev/null 2>&1; then
    host -t TXT "${fqdn}" 2>/dev/null | sed -n 's/.*has TXT record "\(.*\)".*$/\1/p' || true
  else
    python3 - "$fqdn" <<'PYEOF'
import socket, struct, sys, random
def q(name):
    tid = random.randint(0, 0xFFFF)
    hdr = struct.pack('>HHHHHH', tid, 0x0000, 1, 0, 0, 0)
    qn = b''.join(bytes([len(l)]) + l.encode() for l in name.split('.') if l) + b'\x00'
    return tid, hdr + qn + struct.pack('>HH', 16, 1)
def parse(payload):
    out, idx = [], 12
    while payload[idx] != 0: idx += payload[idx] + 1
    idx += 5
    n = int.from_bytes(payload[6:8], 'big')
    for _ in range(n):
        b0 = payload[idx]
        if b0 & 0xC0: idx += 2
        else:
            while payload[idx] != 0: idx += payload[idx] + 1
            idx += 1
        idx += 2 + 2 + 4
        rdlen = int.from_bytes(payload[idx:idx+2], 'big'); idx += 2
        rdata = payload[idx:idx+rdlen]
        i = 0
        while i < len(rdata):
            l = rdata[i]
            out.append(rdata[i+1:i+1+l].decode('ascii', 'replace'))
            i += 1 + l
        idx += rdlen
    return out
name = sys.argv[1]
for server in ('8.8.8.8', '1.1.1.1'):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        tid, payload = q(name)
        s.sendto(payload, (server, 53))
        data, _ = s.recvfrom(4096)
        s.close()
        if int.from_bytes(data[:2], 'big') == tid:
            for t in parse(data[2:]): print(t)
            break
    except Exception:
        continue
PYEOF
  fi
}

wait_for_propagation() {
  local fqdn="$1" value="$2"
  local tries="${ARVAN_PROPAGATION_TRIES:-$ARVAN_PROPAGATION_TRIES_DEFAULT}"
  local sleep_s="${ARVAN_PROPAGATION_SLEEP:-$ARVAN_PROPAGATION_SLEEP_DEFAULT}"
  local i got
  for ((i = 0; i < tries; i++)); do
    got="$( _lookup_txt "$fqdn" || true )"
    if printf '%s\n' "$got" | grep -Fxq "$value"; then
      _log "public DNS serves ${fqdn} = ${value} (try $i)."
      return 0
    fi
    _log "propagation pending for ${fqdn} (try $((i + 1))/${tries})."
    sleep "$sleep_s"
  done
  _err "public DNS did not serve ${fqdn} within $((tries * sleep_s))s; failing closed."
  return 1
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
main() {
  local sub="${1:-}"
  case "$sub" in
    help|-h|--help)
      sed -n '1,45p' "$0"
      ;;
    create)
      local fqdn="${2:-}" value="${3:-}"
      if [ -z "$fqdn" ] || [ -z "$value" ]; then
        _err "usage: $0 create <domain-or-fqdn> <txt-value>"
        exit 2
      fi
      resolve_api_key
      create_challenge "$fqdn" "$value"
      ;;
    delete)
      local fqdn="${2:-}"
      if [ -z "$fqdn" ]; then
        _err "usage: $0 delete <domain-or-fqdn>"
        exit 2
      fi
      resolve_api_key
      delete_challenge "$fqdn"
      ;;
    *)
      _err "unknown subcommand: ${sub:-<none>} (use create | delete | help)"
      exit 2
      ;;
  esac
}

main "$@"
