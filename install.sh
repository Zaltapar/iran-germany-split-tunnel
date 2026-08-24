#!/usr/bin/env bash
# ============================================================
# Iran-Germany Split-Tunnel - Interactive Installer
#
# Guides you through every setting (secret, ports, CDN domain,
# Xray inbound tag, nginx, ...) with sensible defaults, then:
#   1. installs the Go toolchain if missing/too old (official tarball)
#   2. builds the requested role binary (local checkout or GitHub tarball)
#   3. installs + starts the systemd service
#   4. merges the Xray config (Iran role, JSON config, python3)
#   5. configures nginx for the CDN up-carrier (Iran role)
#   6. offers ufw firewall rules
#   7. prints a summary + exact next steps for the other node
#
# Usage:
#   Interactive (recommended):
#     sudo bash install.sh
#     curl -fsSL https://raw.githubusercontent.com/Zaltapar/iran-germany-split-tunnel/main/install.sh | sudo bash -s
#
#   Non-interactive (values via flags):
#     sudo bash install.sh iran --yes --secret <SECRET>
#     sudo bash install.sh germany --yes --secret <SECRET> --up-ws-url wss://cdn.example.com/upload
#
#   Uninstall:
#     sudo bash install.sh uninstall [iran|germany]     # no role = both
#
# Run with --help for all flags.
# ============================================================
set -euo pipefail

VERSION="1.0.0"
REPO_OWNER="Zaltapar"
REPO_NAME="iran-germany-split-tunnel"
TARBALL_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/archive/refs/heads/main.tar.gz"
RAW_INSTALL_SH="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/main/install.sh"
INSTALL_DIR="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"
MIN_GO_MINOR=21
GO_FALLBACK_VERSION="go1.23.4"

XRAY_CONFIG_CANDIDATES=(
  "/usr/local/etc/xray/config.json"
  "/etc/xray/config.json"
  "/usr/local/etc/3x-ui/xray/config.json"
)

# ------------------------------------------------------------
# Colors / logging
# ------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { printf "${GREEN}[INFO]${NC} %s\n" "$*"; }
warn()  { printf "${YELLOW}[WARN]${NC} %s\n" "$*"; }
error() { printf "${RED}[ERROR]${NC} %s\n" "$*" >&2; }
step()  { printf "\n${CYAN}==> %s${NC}\n" "$*"; }

# ------------------------------------------------------------
# State (flags -> defaults -> interactive answers)
# ------------------------------------------------------------
ROLE=""
SECRET=""
SOCKS_LISTEN=""
WS_LISTEN=""
DOWN_CARRIER_ADDR=""
CDN_DOMAIN=""
NGINX_CONFIG="ask"     # ask|y|n
NGINX_PORT=""
XRAY_CONFIG=""
XRAY_INBOUND_TAG=""
XRAY_SERVICE=""
DOWN_LISTEN=""
UP_WS_URL=""
METRICS_PORT=""
RELAY_BUF=""
ASSUME_YES=0
UNINSTALL=0
INTERACTIVE=1
TMP_WORK=""

# ------------------------------------------------------------
# Usage
# ------------------------------------------------------------
usage() {
  cat <<EOF
Split-Tunnel installer v${VERSION}

Usage:
  $0 [iran|germany] [options]       guided interactive install (press Enter = default)
  $0 uninstall [iran|germany]       remove the splitter (no role = both)
  $0 --help

Role options:
  (iran)    --socks-listen ADDR      SOCKS5 listener (default 127.0.0.1:10900)
  (iran)    --ws-listen ADDR         up-carrier WS server (default 127.0.0.1:9001)
  (iran)    --down-carrier-addr ADDR down-carrier dial target (default 127.0.0.1:10802)
  (iran)    --cdn-domain DOMAIN      your CDN domain (optional, summary + nginx server_name)
  (iran)    --nginx / --no-nginx     configure nginx for the CDN (default: ask)
  (iran)    --nginx-port PORT        public port nginx listens on (default 80)
  (iran)    --xray-config PATH       Xray config JSON to merge (default: auto-detect, 'skip' = skip)
  (iran)    --xray-inbound TAG       Xray user inbound tag (default user-vless-reality)
  (germany) --up-ws-url URL          up-carrier WS URL (default wss://cdn.example.com/upload)
  (germany) --down-listen ADDR       down-carrier TCP listener (default 0.0.0.0:9002)

Common options:
  --secret SECRET        shared secret, must match on both nodes (empty = generate)
  --metrics-port PORT    local metrics HTTP port, 0 = off (default 0)
  --relay-buf BYTES      relay buffer size in bytes (default 32768)
  --xray-service NAME    xray/3x-ui systemd service for ordering (default: auto-detect)
  --yes, -y              non-interactive: never prompt, use flags/defaults
  --help                 show this help
EOF
}

# ------------------------------------------------------------
# Validators
# ------------------------------------------------------------
is_port() {
  [[ "$1" =~ ^[0-9]{1,5}$ ]] && (( 10#$1 <= 65535 ))
}
is_hostport() {
  [[ "$1" =~ ^[0-9A-Za-z.]*:[0-9]{1,5}$ ]] && (( 10#${1##*:} <= 65535 ))
}
is_wss_url() {
  [[ "$1" =~ ^wss://[0-9A-Za-z.-]+(:[0-9]{1,5})?(/[0-9A-Za-z._~%/&=?-]+)?$ ]]
}
is_uint() {
  [[ "$1" =~ ^[0-9]{1,9}$ ]] && (( 10#$1 >= 1024 ))
}
is_secret() {
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$ ]]
}

# ------------------------------------------------------------
# Interactive prompt helpers
# Results land in $REPLY_VALUE. Prompts are read from /dev/tty
# when available so `curl ... | sudo bash -s` still works;
# otherwise they fall back to stdin.
# ------------------------------------------------------------
REPLY_VALUE=""
PROMPT_LABEL=""

# read_line: prints the pending prompt (PROMPT_LABEL) and returns one
# answer line. Chooses the best input source: the terminal on stdin,
# then /dev/tty (so `curl ... | sudo bash -s` still asks interactively),
# then plain stdin (EOF-safe).
read_line() {
  local line=""
  if [ -t 0 ]; then
    printf "${YELLOW}%s${NC} " "$PROMPT_LABEL"
    IFS= read -r line || line=""
  elif [ -r /dev/tty ] && [ -w /dev/tty ]; then
    printf "${YELLOW}%s${NC} " "$PROMPT_LABEL" >/dev/tty
    IFS= read -r line </dev/tty || line=""
  else
    printf "${YELLOW}%s${NC} " "$PROMPT_LABEL"
    IFS= read -r line || line=""
  fi
  printf '%s' "$line"
}

ask() {
  local text="$1" default="${2:-}"
  if [ "$INTERACTIVE" -ne 1 ]; then
    REPLY_VALUE="$default"
    return 0
  fi
  PROMPT_LABEL="$text"
  if [ -n "$default" ]; then
    PROMPT_LABEL="${text} [${default}]"
  fi
  REPLY_VALUE="$(read_line)"
  REPLY_VALUE="${REPLY_VALUE:-$default}"
}

ask_valid() {
  local text="$1" default="$2" validator="$3" hint="$4"
  while :; do
    ask "$text" "$default"
    if [ -n "$REPLY_VALUE" ] && "$validator" "$REPLY_VALUE"; then
      return 0
    fi
    if [ "$INTERACTIVE" -ne 1 ]; then
      error "Invalid value for '${text}': '${REPLY_VALUE}' (${hint})"
      exit 1
    fi
    warn "Invalid value: '${REPLY_VALUE}'. ${hint}"
  done
}

ask_yesno() {
  local text="$1" default="${2:-y}" ans
  while :; do
    ask "$text" "$default"
    ans="$(printf '%s' "${REPLY_VALUE}" | tr '[:upper:]' '[:lower:]')"
    case "$ans" in
      y|yes) REPLY_VALUE="y"; return 0 ;;
      n|no)  REPLY_VALUE="n"; return 0 ;;
      *)
        if [ "$INTERACTIVE" -ne 1 ]; then
          REPLY_VALUE="$default"
          return 0
        fi
        warn "Please answer 'y' or 'n'."
        ;;
    esac
  done
}

# ------------------------------------------------------------
# Small helpers
# ------------------------------------------------------------
generate_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 24
  else
    head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'
  fi
}

detect_xray_service() {
  local cand
  for cand in 3x-ui x-ui xray; do
    if systemctl list-unit-files "${cand}.service" 2>/dev/null | grep -q "^${cand}\.service[[:space:]]"; then
      echo "$cand"
      return 0
    fi
  done
  return 0
}

detect_xray_config() {
  local p
  for p in "${XRAY_CONFIG_CANDIDATES[@]}"; do
    if [ -f "$p" ]; then
      echo "$p"
      return 0
    fi
  done
  return 0
}

native_goarch() {
  case "$(uname -m)" in
    x86_64|amd64)  echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    armv7l|armv6l) echo "arm" ;;
    i386|i686)     echo "386" ;;
    *)             echo "amd64" ;;
  esac
}

go_version_ok() {
  command -v go >/dev/null 2>&1 || return 1
  local v major minor
  v="$(go env GOVERSION 2>/dev/null | sed 's/^go//')" || return 1
  major="${v%%.*}"
  minor="${v#*.}"
  minor="${minor%%.*}"
  [[ "$major" =~ ^[0-9]+$ ]] || return 1
  [[ "$minor" =~ ^[0-9]+$ ]] || return 1
  (( major > 1 || (major == 1 && 10#$minor >= MIN_GO_MINOR) ))
}

require_arg() {
  if [ -z "${2:-}" ]; then
    error "Option '$1' requires a value."
    exit 1
  fi
}

cleanup() {
  if [ -n "${TMP_WORK:-}" ] && [ -d "${TMP_WORK:-}" ]; then
    rm -rf "$TMP_WORK" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# ------------------------------------------------------------
# Argument parsing
# ------------------------------------------------------------
parse_args() {
  while [ $# -gt 0 ]; do
    if [[ "$1" == --*=* ]]; then
      local k="${1%%=*}" v="${1#*=}"
      set -- "$k" "$v" "${@:2}"
      continue
    fi
    case "$1" in
      -h|--help)
        usage
        exit 0
        ;;
      uninstall|--uninstall)
        UNINSTALL=1
        shift
        ;;
      -y|--yes)
        ASSUME_YES=1
        shift
        ;;
      iran|germany)
        if [ -n "$ROLE" ] && [ "$ROLE" != "$1" ]; then
          error "Role already set to '$ROLE'."
          exit 1
        fi
        ROLE="$1"
        shift
        ;;
      --secret)
        require_arg "$@"; SECRET="$2"; shift 2 ;;
      --socks-listen)
        require_arg "$@"; SOCKS_LISTEN="$2"; shift 2 ;;
      --ws-listen)
        require_arg "$@"; WS_LISTEN="$2"; shift 2 ;;
      --down-carrier-addr)
        require_arg "$@"; DOWN_CARRIER_ADDR="$2"; shift 2 ;;
      --cdn-domain)
        require_arg "$@"; CDN_DOMAIN="$2"; shift 2 ;;
      --nginx)
        NGINX_CONFIG="y"; shift ;;
      --no-nginx)
        NGINX_CONFIG="n"; shift ;;
      --nginx-port)
        require_arg "$@"; NGINX_PORT="$2"; shift 2 ;;
      --xray-config)
        require_arg "$@"; XRAY_CONFIG="$2"; shift 2 ;;
      --xray-inbound)
        require_arg "$@"; XRAY_INBOUND_TAG="$2"; shift 2 ;;
      --xray-service)
        require_arg "$@"; XRAY_SERVICE="$2"; shift 2 ;;
      --down-listen)
        require_arg "$@"; DOWN_LISTEN="$2"; shift 2 ;;
      --up-ws-url)
        require_arg "$@"; UP_WS_URL="$2"; shift 2 ;;
      --metrics-port)
        require_arg "$@"; METRICS_PORT="$2"; shift 2 ;;
      --relay-buf)
        require_arg "$@"; RELAY_BUF="$2"; shift 2 ;;
      *)
        error "Unknown option: $1"
        usage
        exit 1
        ;;
    esac
  done
}

# ------------------------------------------------------------
# Pre-flight checks
# ------------------------------------------------------------
check_root() {
  if [ "$(id -u)" -ne 0 ]; then
    error "This installer must run as root:  sudo bash install.sh"
    exit 1
  fi
}

check_system() {
  if ! command -v curl >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
    info "curl not found - installing it via apt-get..."
    apt-get update -qq >/dev/null 2>&1 || true
    apt-get install -y -qq curl >/dev/null 2>&1 || true
  fi
  command -v curl >/dev/null 2>&1 || { error "curl is required but not installed."; exit 1; }
  command -v tar  >/dev/null 2>&1 || { error "tar is required but not installed."; exit 1; }
  if ! command -v systemctl >/dev/null 2>&1; then
    error "systemd (systemctl) not found - this installer needs a systemd-based distro."
    exit 1
  fi
}

# ------------------------------------------------------------
# Interactive wizard - asks for every setting with defaults
# ------------------------------------------------------------
gather_params() {
  step "Configuration"
  info "Press Enter to accept the [default] for each question."

  # ---- Role ----
  if [ -z "$ROLE" ]; then
    if [ "$INTERACTIVE" -ne 1 ]; then
      error "No role specified. Run with 'iran' or 'germany' (or run interactively)."
      exit 1
    fi
    while :; do
      ask "Which role is this server? (iran / germany)" ""
      case "${REPLY_VALUE}" in
        iran|germany) ROLE="${REPLY_VALUE}"; break ;;
        *) warn "Please type exactly 'iran' or 'germany'." ;;
      esac
    done
  fi
  info "Role: ${ROLE}"

  # ---- Shared secret ----
  if [ -z "$SECRET" ] && [ "$INTERACTIVE" -eq 1 ]; then
    ask "Shared secret (must match on both nodes; empty = auto-generate)" ""
    SECRET="${REPLY_VALUE}"
  fi
  if [ -z "$SECRET" ]; then
    SECRET="$(generate_secret)"
    info "Generated random shared secret: ${SECRET}"
  elif ! is_secret "$SECRET"; then
    error "Invalid secret: use 8-128 characters of letters, digits, dot, dash or underscore."
    exit 1
  fi

  case "${ROLE}" in
    iran)
      if [ -z "$SOCKS_LISTEN" ]; then
        ask_valid "SOCKS5 listen addr (local Xray connects here)" \
          "127.0.0.1:10900" is_hostport "expected host:port, e.g. 127.0.0.1:10900"
        SOCKS_LISTEN="${REPLY_VALUE}"
      fi
      if [ -z "$WS_LISTEN" ]; then
        ask_valid "Up-carrier WS listen addr (fronted by nginx/CDN, path /upload)" \
          "127.0.0.1:9001" is_hostport "expected host:port, e.g. 127.0.0.1:9001"
        WS_LISTEN="${REPLY_VALUE}"
      fi
      if [ -z "$DOWN_CARRIER_ADDR" ]; then
        ask_valid "Down-carrier dial addr (local Xray tunnel entry point)" \
          "127.0.0.1:10802" is_hostport "expected host:port, e.g. 127.0.0.1:10802"
        DOWN_CARRIER_ADDR="${REPLY_VALUE}"
      fi
      if [ -z "$CDN_DOMAIN" ]; then
        ask "CDN domain (e.g. cdn.example.com - optional, used for nginx + summary)" ""
        CDN_DOMAIN="${REPLY_VALUE}"
      fi
      if [ "$NGINX_CONFIG" = "ask" ]; then
        ask_yesno "Configure Nginx to front the up-carrier for the CDN? (y/n)" "y"
        NGINX_CONFIG="${REPLY_VALUE}"
      fi
      if [ "$NGINX_CONFIG" = "y" ] && [ -z "$NGINX_PORT" ]; then
        ask_valid "Public port Nginx listens on for /upload (CDN origin port)" \
          "80" is_port "expected a TCP port, 1-65535"
        NGINX_PORT="${REPLY_VALUE}"
      fi
      if [ -z "$XRAY_CONFIG" ]; then
        local detected_conf
        detected_conf="$(detect_xray_config)"
        ask "Xray config JSON path (type 'skip' to skip the auto-merge)" \
          "${detected_conf:-/usr/local/etc/xray/config.json}"
        XRAY_CONFIG="${REPLY_VALUE}"
      fi
      if [ "$XRAY_CONFIG" != "skip" ] && [ -f "$XRAY_CONFIG" ] && [ -z "$XRAY_INBOUND_TAG" ]; then
        ask "Xray user inbound tag (client traffic will be routed to the splitter)" \
          "user-vless-reality"
        XRAY_INBOUND_TAG="${REPLY_VALUE}"
      fi
      ;;
    germany)
      if [ -z "$DOWN_LISTEN" ]; then
        ask_valid "Down-carrier TCP listen (Iran reaches it via the VLESS+Reality tunnel)" \
          "0.0.0.0:9002" is_hostport "expected host:port, e.g. 127.0.0.1:9002 (private) or 0.0.0.0:9002"
        DOWN_LISTEN="${REPLY_VALUE}"
      fi
      if [ -z "$UP_WS_URL" ]; then
        ask_valid "Up-carrier WebSocket URL (your CDN domain, path /upload)" \
          "wss://cdn.example.com/upload" is_wss_url "expected wss://domain[:port]/path"
        UP_WS_URL="${REPLY_VALUE}"
      fi
      ;;
  esac

  # ---- Xray service (ordering only) ----
  if [ -z "$XRAY_SERVICE" ]; then
    local detected_svc
    detected_svc="$(detect_xray_service)"
    if [ -n "$detected_svc" ]; then
      ask "Xray/panel systemd service name (for startup ordering)" "${detected_svc}"
    else
      ask "Xray/panel systemd service name (empty = not installed here)" ""
    fi
    XRAY_SERVICE="${REPLY_VALUE}"
  fi

  # ---- Metrics & buffer ----
  if [ -z "$METRICS_PORT" ]; then
    ask_valid "Metrics HTTP port (0 = disabled)" "0" is_port "expected a TCP port or 0"
    METRICS_PORT="${REPLY_VALUE}"
  fi
  if [ -z "$RELAY_BUF" ]; then
    ask_valid "Relay buffer size in bytes" "32768" is_uint "expected a positive integer >= 1024"
    RELAY_BUF="${REPLY_VALUE}"
  fi

  # Final safety net: also validate values that came from flags.
  local bad=0
  case "${ROLE}" in
    iran)
      if ! is_hostport "$SOCKS_LISTEN"; then error "SOCKS5 listen '${SOCKS_LISTEN}' is invalid (expected host:port)"; bad=1; fi
      if ! is_hostport "$WS_LISTEN"; then error "WS listen '${WS_LISTEN}' is invalid (expected host:port)"; bad=1; fi
      if ! is_hostport "$DOWN_CARRIER_ADDR"; then error "Down-carrier addr '${DOWN_CARRIER_ADDR}' is invalid (expected host:port)"; bad=1; fi
      if [ "$NGINX_CONFIG" = "y" ] && ! is_port "$NGINX_PORT"; then error "Nginx port '${NGINX_PORT}' is invalid (expected 1-65535)"; bad=1; fi
      ;;
    germany)
      if ! is_hostport "$DOWN_LISTEN"; then error "Down listen '${DOWN_LISTEN}' is invalid (expected host:port)"; bad=1; fi
      if ! is_wss_url "$UP_WS_URL"; then error "Up WS URL '${UP_WS_URL}' is invalid (expected wss://domain/path)"; bad=1; fi
      ;;
  esac
  if ! is_port "$METRICS_PORT"; then error "Metrics port '${METRICS_PORT}' is invalid (expected 0-65535)"; bad=1; fi
  if ! is_uint "$RELAY_BUF"; then error "Relay buffer '${RELAY_BUF}' is invalid (expected integer >= 1024)"; bad=1; fi
  if [ -n "$XRAY_INBOUND_TAG" ] && [[ "$XRAY_INBOUND_TAG" =~ [[:space:]] ]]; then
    error "Xray inbound tag '${XRAY_INBOUND_TAG}' must not contain spaces"
    bad=1
  fi
  if [ "$bad" -ne 0 ]; then
    exit 1
  fi
  return 0
}

# ------------------------------------------------------------
# Go toolchain (official tarball, right arch, >= go1.21)
# ------------------------------------------------------------
install_go_official() {
  local go_ver go_arch machine url tgz
  machine="$(uname -m)"
  case "$machine" in
    x86_64|amd64)  go_arch="amd64" ;;
    aarch64|arm64) go_arch="arm64" ;;
    armv7l|armv6l) go_arch="arm" ;;
    *) error "Unsupported CPU architecture: $machine (need amd64 or arm64)."; exit 1 ;;
  esac
  go_ver="$(curl -fsSL --max-time 10 'https://go.dev/VERSION?m=text' | head -n1 || true)"
  if [[ ! "$go_ver" =~ ^go1\.[0-9]+\.[0-9]+$ ]]; then
    go_ver="$GO_FALLBACK_VERSION"
    warn "Could not query the latest Go version - falling back to ${go_ver}."
  fi
  url="https://go.dev/dl/${go_ver}.linux-${go_arch}.tar.gz"
  info "Installing Go ${go_ver} (linux/${go_arch}) from ${url}"
  tgz="${TMP_WORK}/go.tar.gz"
  curl -fL --retry 3 -o "$tgz" "$url" || { error "Go download failed."; exit 1; }
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "$tgz" || { error "Go tarball extraction failed."; exit 1; }
  rm -f "$tgz"
  export PATH="/usr/local/go/bin:${PATH}"
  printf 'export PATH="/usr/local/go/bin:$PATH"\n' > /etc/profile.d/go.sh
  hash -r
  if ! go_version_ok; then
    error "Go installation failed."
    exit 1
  fi
  info "Go installed: $(go version)"
}

ensure_go() {
  if go_version_ok; then
    info "Go toolchain: $(go version)"
    return 0
  fi
  if command -v go >/dev/null 2>&1; then
    warn "Found Go $(go env GOVERSION 2>/dev/null), but go1.${MIN_GO_MINOR}+ is required."
  else
    info "Go toolchain not found."
  fi
  install_go_official
  return 0
}

# ------------------------------------------------------------
# Build & install the role binary
# Uses the local checkout when the script is run from the repo,
# otherwise downloads the GitHub source tarball.
# ------------------------------------------------------------
build_binary() {
  local script_dir src_dir go_arch
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
  if [ -n "${script_dir:-}" ] && [ -f "${script_dir}/go.mod" ] && [ -d "${script_dir}/cmd/${ROLE}-splitter" ]; then
    src_dir="$script_dir"
    info "Building from local source: ${src_dir}"
  else
    info "Downloading source tarball: ${TARBALL_URL}"
    local tgz="${TMP_WORK}/src.tar.gz"
    curl -fsSL --retry 3 -o "$tgz" "$TARBALL_URL" || { error "Source download failed."; exit 1; }
    tar -xzf "$tgz" -C "$TMP_WORK"
    src_dir="$(find "$TMP_WORK" -maxdepth 3 -name go.mod | head -n1 | xargs -r dirname)"
    if [ -z "${src_dir:-}" ] || [ ! -d "${src_dir}/cmd/${ROLE}-splitter" ]; then
      error "Unexpected tarball layout (missing cmd/${ROLE}-splitter)."
      exit 1
    fi
  fi

  go_arch="$(native_goarch)"
  info "go build: GOOS=linux GOARCH=${go_arch} ./cmd/${ROLE}-splitter"
  (
    cd "$src_dir"
    export GOOS=linux GOARCH="$go_arch"
    export GOTOOLCHAIN=local
    export CGO_ENABLED=0
    go build -ldflags "-s -w" -o "${INSTALL_DIR}/${ROLE}-splitter" "./cmd/${ROLE}-splitter"
  )
  chmod 755 "${INSTALL_DIR}/${ROLE}-splitter"
  info "Installed: ${INSTALL_DIR}/${ROLE}-splitter"
}

# ------------------------------------------------------------
# Systemd service
# ------------------------------------------------------------
install_systemd_service() {
  local svc="${ROLE}-splitter"
  local unit="${SYSTEMD_DIR}/${svc}.service"
  local role_name="${ROLE^}"
  local after="After=network-online.target"
  if [ -n "$XRAY_SERVICE" ]; then
    after="${after} ${XRAY_SERVICE}.service"
  fi

  local env_lines=""
  case "$ROLE" in
    iran)
      env_lines="Environment=SPLIT_SOCKS_LISTEN=${SOCKS_LISTEN}
Environment=SPLIT_WS_LISTEN=${WS_LISTEN}
Environment=SPLIT_DOWN_CARRIER_ADDR=${DOWN_CARRIER_ADDR}"
      ;;
    germany)
      env_lines="Environment=SPLIT_DOWN_LISTEN=${DOWN_LISTEN}
Environment=SPLIT_UP_WS_URL=${UP_WS_URL}"
      ;;
  esac

  info "Writing systemd unit: ${unit}"
  cat > "$unit" <<EOF
[Unit]
Description=${role_name} Splitter Daemon (Asymmetric Split-Tunnel v${VERSION})
${after}
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/${ROLE}-splitter
${env_lines}
Environment=SPLIT_SECRET=${SECRET}
Environment=SPLIT_METRICS_PORT=${METRICS_PORT}
Environment=SPLIT_RELAY_BUF=${RELAY_BUF}
Restart=always
RestartSec=5
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${ROLE}-splitter

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "$svc" >/dev/null
  systemctl restart "$svc"
  sleep 2
  if systemctl is-active --quiet "$svc"; then
    info "${svc} is running."
    journalctl -u "$svc" --no-pager -n 5 2>/dev/null || true
  else
    warn "${svc} is not active yet - recent logs:"
    journalctl -u "$svc" --no-pager -n 20 2>/dev/null || true
  fi
}

# ------------------------------------------------------------
# Xray config merge (Iran role, JSON configs only)
# ------------------------------------------------------------
show_xray_snippets() {
  local socks_port="${SOCKS_LISTEN##*:}"
  cat <<EOF
--- Add to "outbounds" in your Xray config ---
{
  "tag": "to-splitter",
  "protocol": "socks",
  "settings": { "servers": [ { "address": "127.0.0.1", "port": ${socks_port} } ] }
}

--- Add to "routing.rules" (put it first) ---
{
  "type": "field",
  "inboundTag": [ "${XRAY_INBOUND_TAG:-user-vless-reality}" ],
  "outboundTag": "to-splitter"
}
EOF
}

merge_xray_config() {
  if [ "$ROLE" != "iran" ]; then
    info "Xray config merge only applies to the Iran role - skipping."
    return 0
  fi
  if [ -z "$XRAY_CONFIG" ] || [ "$XRAY_CONFIG" = "skip" ]; then
    info "Xray config merge skipped."
    return 0
  fi
  if [ ! -f "$XRAY_CONFIG" ]; then
    warn "Xray config not found at ${XRAY_CONFIG} - apply these snippets manually:"
    show_xray_snippets
    return 0
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    warn "python3 not found - cannot merge the JSON automatically. Manual snippets:"
    show_xray_snippets
    return 0
  fi

  local socks_port="${SOCKS_LISTEN##*:}"
  local inbound_tag="${XRAY_INBOUND_TAG:-user-vless-reality}"
  local bak="${XRAY_CONFIG}.bak.$(date +%s)"
  cp "$XRAY_CONFIG" "$bak"
  info "Backed up Xray config to: ${bak}"

  if XRAY_CONF="$XRAY_CONFIG" XRAY_INBOUND_TAG="$inbound_tag" XRAY_SOCKS_PORT="$socks_port" python3 - <<'PYEOF'
import json, os

path = os.environ["XRAY_CONF"]
tag  = os.environ["XRAY_INBOUND_TAG"]
port = int(os.environ["XRAY_SOCKS_PORT"])

with open(path) as f:
    cfg = json.load(f)

# 1) ensure the socks outbound to the splitter exists
outs = cfg.setdefault("outbounds", [])
if not any(o.get("tag") == "to-splitter" for o in outs):
    outs.append({
        "tag": "to-splitter",
        "protocol": "socks",
        "settings": {"servers": [{"address": "127.0.0.1", "port": port}]},
    })

# 2) route the user inbound to the splitter (rule inserted first)
routing = cfg.setdefault("routing", {})
rules = [
    r for r in routing.get("rules", [])
    if not (r.get("type") == "field"
            and list(r.get("inboundTag") or []) == [tag]
            and r.get("outboundTag") == "to-splitter")
]
rules.insert(0, {"type": "field", "inboundTag": [tag], "outboundTag": "to-splitter"})
routing["rules"] = rules

with open(path, "w") as f:
    json.dump(cfg, f, indent=2)

print("Xray config updated: outbound 'to-splitter' (socks 127.0.0.1:%d) + routing rule for inbound '%s'." % (port, tag))
PYEOF
  then
    info "Xray config merged."
    if [ -n "$XRAY_SERVICE" ]; then
      local ans
      ask_yesno "Restart the Xray service (${XRAY_SERVICE}) now to apply? (y/n)" "y"
      ans="${REPLY_VALUE}"
      if [ "$ans" = "y" ]; then
        if systemctl restart "$XRAY_SERVICE" 2>/dev/null; then
          info "${XRAY_SERVICE} restarted."
        else
          warn "Could not restart ${XRAY_SERVICE} - please restart it manually."
        fi
      fi
    fi
  else
    warn "Xray merge failed - your config was not modified (backup kept at ${bak})."
  fi
  return 0
}

# ------------------------------------------------------------
# Nginx (Iran role): fronts the up-carrier WS for the CDN
# ------------------------------------------------------------
show_nginx_snippet() {
  local internal_port="${WS_LISTEN##*:}"
  cat <<EOF
--- Add to an nginx server block listening on your CDN origin port ---
location /upload {
    proxy_pass http://127.0.0.1:${internal_port};
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
}
EOF
}

configure_nginx() {
  if [ "$ROLE" != "iran" ]; then
    return 0
  fi
  if [ "$NGINX_CONFIG" != "y" ]; then
    info "Nginx configuration skipped."
    return 0
  fi
  if ! command -v nginx >/dev/null 2>&1; then
    warn "Nginx is not installed - skipping. Install it with: apt-get install -y nginx"
    return 0
  fi

  local internal_port="${WS_LISTEN##*:}"
  local nginx_root="${NGINX_ROOT:-/etc/nginx}"
  local conf_dir=""
  if [ -d "${nginx_root}/conf.d" ]; then
    conf_dir="${nginx_root}/conf.d"
  elif [ -d "${nginx_root}/sites-enabled" ]; then
    conf_dir="${nginx_root}/sites-enabled"
  else
    warn "Neither ${nginx_root}/conf.d nor ${nginx_root}/sites-enabled exists - add the location block manually."
    show_nginx_snippet
    return 0
  fi
  local conf="${conf_dir}/split-tunnel.conf"

  # only claim default_server if no other vhost already uses it
  local is_default=""
  local existing_default
  existing_default="$(grep -rhE "^[[:space:]]*listen[[:space:]].*default_server" "$nginx_root" 2>/dev/null | grep -vE "^[[:space:]]*#" | head -n1 || true)"
  if [ -z "$existing_default" ]; then
    is_default=" default_server"
  fi

  local server_name="_"
  if [ -n "$CDN_DOMAIN" ]; then
    server_name="$CDN_DOMAIN"
  else
    if [ -n "$existing_default" ]; then
      warn "Another nginx vhost is already the default server. Re-run with --cdn-domain so this vhost matches your CDN's Host header."
    fi
  fi

  local listen6=""
  if [ -r /proc/net/if_inet6 ]; then
    listen6="    listen [::]:${NGINX_PORT};${is_default}"
  fi

  if [ -f "$conf" ]; then
    cp "$conf" "${conf}.bak.$(date +%s)"
  fi

  info "Writing nginx config: ${conf}"
  cat > "$conf" <<EOF
# Managed by split-tunnel installer v${VERSION}
server {
    listen ${NGINX_PORT};${is_default}
${listen6}
    server_name ${server_name};

    location /upload {
        proxy_pass http://127.0.0.1:${internal_port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
EOF

  if nginx -t >/dev/null 2>&1; then
    systemctl reload nginx 2>/dev/null \
      || systemctl restart nginx 2>/dev/null \
      || service nginx reload 2>/dev/null \
      || warn "Nginx config is valid but could not be reloaded - run: nginx -s reload"
    info "Nginx configured: port ${NGINX_PORT}/upload -> 127.0.0.1:${internal_port}"
  else
    nginx -t
    error "Nginx config test failed - fix ${conf} and run: nginx -t && nginx -s reload"
  fi
  return 0
}

# ------------------------------------------------------------
# Firewall (ufw)
# ------------------------------------------------------------
configure_firewall() {
  if ! command -v ufw >/dev/null 2>&1; then
    return 0
  fi
  if ! ufw status 2>/dev/null | head -n1 | grep -qi "status:.*active"; then
    return 0
  fi
  local ports=""
  case "$ROLE" in
    iran)
      ports="443"
      if [ "$NGINX_CONFIG" = "y" ]; then
        ports="${NGINX_PORT} 443"
      fi
      ;;
    germany)
      ports="443"
      ;;
  esac
  local ans
  ask_yesno "ufw is active - allow TCP port(s) ${ports} (needed for the tunnel)? (y/n)" "y"
  ans="${REPLY_VALUE}"
  if [ "$ans" = "y" ]; then
    local p
    for p in $ports; do
      if ufw allow "${p}/tcp" >/dev/null 2>&1; then
        info "ufw: allowed ${p}/tcp"
      else
        warn "ufw: could not allow ${p}/tcp"
      fi
    done
  fi
  return 0
}

# ------------------------------------------------------------
# Uninstall
# ------------------------------------------------------------
uninstall_role() {
  local role="$1"
  local svc="${role}-splitter"
  warn "Uninstalling ${svc}..."
  systemctl stop "$svc" 2>/dev/null || true
  systemctl disable "$svc" 2>/dev/null || true
  rm -f "${SYSTEMD_DIR}/${svc}.service"
  rm -f "${INSTALL_DIR}/${svc}"
  local nginx_conf_dir="${NGINX_ROOT:-/etc/nginx}/conf.d"
  if [ -f "${nginx_conf_dir}/split-tunnel.conf" ] \
     && grep -q "Managed by split-tunnel installer" "${nginx_conf_dir}/split-tunnel.conf" 2>/dev/null; then
    rm -f "${nginx_conf_dir}/split-tunnel.conf"
    if command -v nginx >/dev/null 2>&1; then
      if nginx -t >/dev/null 2>&1; then
        systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null || true
      fi
    fi
    info "Removed nginx config /etc/nginx/conf.d/split-tunnel.conf"
  fi
  systemctl daemon-reload
  info "${svc} removed. (Xray config backups in the Xray config directory were kept.)"
  return 0
}

run_uninstall() {
  check_root
  local roles
  if [ -n "$ROLE" ]; then
    roles="$ROLE"
  else
    roles="iran germany"
  fi
  local r
  for r in $roles; do
    uninstall_role "$r"
  done
  info "Uninstall complete."
  return 0
}

# ------------------------------------------------------------
# Summary
# ------------------------------------------------------------
print_banner() {
  echo ""
  printf "${CYAN}==================================================${NC}\n"
  printf "${CYAN}   Iran-Germany Split-Tunnel Installer v${VERSION}${NC}\n"
  printf "${CYAN}==================================================${NC}\n"
}

print_summary() {
  local metrics_line="disabled"
  if [ "$METRICS_PORT" != "0" ]; then
    metrics_line="http://127.0.0.1:${METRICS_PORT}/metrics"
  fi

  echo ""
  printf "${GREEN}==================================================${NC}\n"
  printf "${GREEN}   Installation complete: ${ROLE}-splitter v${VERSION}${NC}\n"
  printf "${GREEN}==================================================${NC}\n"
  info " Role:          ${ROLE}"
  case "$ROLE" in
    iran)
      info " SOCKS5:        ${SOCKS_LISTEN} (local Xray -> splitter)"
      if [ "$NGINX_CONFIG" = "y" ]; then
        info " Up-carrier:    ${WS_LISTEN} (nginx :${NGINX_PORT:-80}/upload -> ${WS_LISTEN})"
      else
        info " Up-carrier:    ${WS_LISTEN}"
      fi
      info " Down-carrier:  dials ${DOWN_CARRIER_ADDR} (local Xray tunnel)"
      ;;
    germany)
      info " Down-carrier:  listens on ${DOWN_LISTEN} (Iran via Reality tunnel)"
      info " Up-carrier:    ${UP_WS_URL}"
      ;;
  esac
  info " Secret:        ${SECRET}"
  info " Metrics:       ${metrics_line}"
  info " Status:        systemctl status ${ROLE}-splitter"
  info " Logs:          journalctl -u ${ROLE}-splitter -f"

  case "$ROLE" in
    iran)
      local url="wss://cdn.example.com/upload"
      if [ -n "$CDN_DOMAIN" ]; then
        url="wss://${CDN_DOMAIN}/upload"
      fi
      cat <<EOF

  Next steps:
   1. Create your CDN zone (e.g. ArvanCloud) with origin = this server,
      port ${NGINX_PORT:-80}, and make sure the /upload path is forwarded
      with WebSocket support.
   2. In the Iran Xray/3x-ui, make sure the down-carrier path exists: a
      local inbound on ${DOWN_CARRIER_ADDR} that tunnels over VLESS+Reality
      to Germany and targets 127.0.0.1:<Germany down-carrier port>.
   3. On the Germany node, run:
      curl -fsSL ${RAW_INSTALL_SH} | sudo bash -s -- germany --yes \
        --secret ${SECRET} --up-ws-url ${url}
   4. If the Xray config was merged, restart Xray, then test with a
      SOCKS5 client pointed at ${SOCKS_LISTEN}.
EOF
      ;;
    germany)
      cat <<EOF

  Next steps:
   1. On the Iran node, make sure SPLIT_SECRET is exactly: ${SECRET}
   2. In the Germany Xray/3x-ui, route the VLESS+Reality inbound traffic
      destined to 127.0.0.1:${DOWN_LISTEN##*:} directly to the internet
      (freedom/direct outbound) so it reaches this splitter.
   3. Watch both logs while connecting a client:
      journalctl -u ${ROLE}-splitter -f
EOF
      ;;
  esac
  return 0
}

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------
main() {
  parse_args "$@"

  if [ "$UNINSTALL" -eq 1 ]; then
    run_uninstall
    exit 0
  fi

  if [ "$ASSUME_YES" -eq 1 ]; then
    INTERACTIVE=0
  elif [ ! -e /dev/tty ] && [ ! -t 0 ]; then
    INTERACTIVE=0
    warn "No interactive terminal detected - proceeding with flags/defaults only."
  fi

  check_root
  check_system

  TMP_WORK="$(mktemp -d)"

  print_banner
  gather_params

  step "Go toolchain"
  ensure_go

  step "Build & install binary"
  build_binary

  step "Systemd service"
  install_systemd_service

  step "Xray config"
  merge_xray_config

  step "Nginx"
  configure_nginx

  step "Firewall"
  configure_firewall

  print_summary
}

if [ "${BASH_SOURCE[0]:-$0}" = "$0" ]; then
  main "$@"
fi