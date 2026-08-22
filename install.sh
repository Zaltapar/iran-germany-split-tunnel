#!/bin/bash
set -euo pipefail

# ============================================================
# Iran-Germany Split-Tunnel Automated Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/Zaltapar/iran-germany-split-tunnel/main/install.sh | sudo bash -s -- iran|germany [flags]
# ============================================================

VERSION="1.0.0"
REPO="github.com/Zaltapar/iran-germany-split-tunnel"
TARBALL_URL="https://github.com/Zaltapar/iran-germany-split-tunnel/archive/refs/heads/main.tar.gz"
INSTALL_DIR="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"
XRAY_CONFIGS=(
  "/usr/local/etc/xray/config.json"
  "/etc/xray/config.json"
)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

# ============================================================
# Argument parsing (interactive or flag-based)
# ============================================================
ROLE=""
SECRET=""
DOWN_CARRIER_ADDR=""
WS_LISTEN=""
SOCKS_LISTEN=""
UP_WS_URL=""
DOWN_LISTEN=""
METRICS_PORT="0"
RELAY_BUF="32768"
NGINX_CONFIG="n"
XRAY_CONFIG_PATH=""

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      iran|germany)
        ROLE="$1"
        shift ;;
      --secret)
        SECRET="$2"
        shift 2 ;;
      --secret=*)
        SECRET="${1#*=}"
        shift ;;
      --metrics-port)
        METRICS_PORT="$2"
        shift 2 ;;
      --relay-buf)
        RELAY_BUF="$2"
        shift 2 ;;
      --xray-config)
        XRAY_CONFIG_PATH="$2"
        shift 2 ;;
      --socks-listen)
        SOCKS_LISTEN="$2"
        shift 2 ;;
      --socks-listen=*)
        SOCKS_LISTEN="${1#*=}"
        shift ;;
      --ws-listen)
        WS_LISTEN="$2"
        shift 2 ;;
      --ws-listen=*)
        WS_LISTEN="${1#*=}"
        shift ;;
      --down-carrier-addr)
        DOWN_CARRIER_ADDR="$2"
        shift 2 ;;
      --down-carrier-addr=*)
        DOWN_CARRIER_ADDR="${1#*=}"
        shift ;;
      --down-listen)
        DOWN_LISTEN="$2"
        shift 2 ;;
      --down-listen=*)
        DOWN_LISTEN="${1#*=}"
        shift ;;
      --up-ws-url)
        UP_WS_URL="$2"
        shift 2 ;;
      --up-ws-url=*)
        UP_WS_URL="${1#*=}"
        shift ;;
      *)
        error "Unknown flag: $1"
        echo "Usage: $0 [iran|germany] [--secret SECRET] [--metrics-port PORT] [--relay-buf SIZE] [--xray-config PATH] [--socks-listen ADDR] [--ws-listen ADDR] [--down-carrier-addr ADDR] [--down-listen PORT] [--up-ws-url URL]"
        exit 1 ;;
    esac
  done
}

prompt() {
  local prompt_text="$1"
  local default="$2"
  echo -en "${YELLOW}${prompt_text}${NC} "
  if [ -n "$default" ]; then
    echo -en "[${default}]: "
  else
    echo -en ": "
  fi
  if [ -n "$default" ]; then
    read -r input
    echo "${input:-$default}"
  else
    read -r input
    echo "$input"
  fi
}

gather_params_interactive() {
  if [ -z "$ROLE" ]; then
    ROLE=$(prompt "Which role? (iran/germany)" "")
  fi

  if [ -z "$SECRET" ]; then
    SECRET=$(prompt "Shared secret (leave empty for random)" "")
    if [ -z "$SECRET" ]; then
      SECRET=$(openssl rand -hex 24 2>/dev/null || head -c 48 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 48)
      info "Generated random secret: $SECRET"
    fi
  fi

  case "$ROLE" in
    iran)
      SOCKS_LISTEN="${SOCKS_LISTEN:-$(prompt 'SOCKS5 listen (Xray → splitter)' '127.0.0.1:10900')}"
      WS_LISTEN="${WS_LISTEN:-$(prompt 'WS listen (CDN/Nginx → splitter)' '127.0.0.1:9001')}"
      DOWN_CARRIER_ADDR="${DOWN_CARRIER_ADDR:-$(prompt 'Xray down-carrier dial (for download tunnel)' '127.0.0.1:10802')}"
      NGINX_CONFIG="${NGINX_CONFIG:-$(prompt 'Configure Nginx for CDN WebSocket? (y/n)' 'y')}"
      ;;
    germany)
      DOWN_LISTEN="${DOWN_LISTEN:-$(prompt 'Down-carrier TCP listen port (from Iran Xray tunnel)' ':9002')}"
      UP_WS_URL="${UP_WS_URL:-$(prompt 'CDN WebSocket URL (e.g. wss://cdn.example.com/upload)' 'wss://cdn.example.com/upload')}"
      ;;
    *)
      error "Unknown role: $ROLE"
      exit 1
      ;;
  esac
}

# ============================================================
# Pre-flight checks
# ============================================================
check_root() {
  if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run as root (use sudo)."
    exit 1
  fi
}

# ============================================================
# Check & install Go - NON-INTERACTIVE (no read prompt)
# ============================================================
check_go() {
  if ! command -v go &>/dev/null; then
    warn "Go is not installed. Installing golang..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq golang-go 2>/dev/null
    if ! command -v go &>/dev/null; then
      error "Go installation failed. Please install Go 1.21+ manually."
      exit 1
    fi
    info "Go installed: $(go version)"
  fi
}

# ============================================================
# Download and build with dynamic go.mod discovery
# ============================================================
download_and_build() {
  info "Downloading source from $TARBALL_URL ..."
  local tmpdir
  tmpdir=$(mktemp -d)
  cd "$tmpdir"
  curl -fsSL -o split-tunnel.tar.gz "$TARBALL_URL"
  mkdir -p src
  tar xzf split-tunnel.tar.gz -C src 2>/dev/null

  # Dynamic go.mod discovery — handles any extraction depth
  local mod_dir
  mod_dir=$(find "$tmpdir" -type f -name "go.mod" -exec dirname {} \; | head -n 1)
  if [ -z "$mod_dir" ] || [ ! -f "$mod_dir/go.mod" ]; then
    error "go.mod not found in downloaded archive."
    rm -rf "$tmpdir"
    exit 1
  fi
  cd "$mod_dir"

  info "Building for Linux amd64..."
  GOOS=linux GOARCH=amd64 go build -o "${INSTALL_DIR}/iran-splitter" ./cmd/iran-splitter 2>/dev/null || \
    GOOS=linux GOARCH=amd64 go build -o "${INSTALL_DIR}/iran-splitter" . 2>/dev/null

  GOOS=linux GOARCH=amd64 go build -o "${INSTALL_DIR}/germany-splitter" ./cmd/germany-splitter 2>/dev/null || \
    GOOS=linux GOARCH=amd64 go build -o "${INSTALL_DIR}/germany-splitter" . 2>/dev/null

  chmod 755 "${INSTALL_DIR}/iran-splitter" "${INSTALL_DIR}/germany-splitter"
  info "Binaries built and installed to $INSTALL_DIR"
  rm -rf "$tmpdir"
}

# ============================================================
# Systemd service
# ============================================================
install_systemd_service() {
  local service_file="${SYSTEMD_DIR}/${ROLE}-splitter.service"
  info "Installing systemd service: $service_file"

  local env_vars=""
  case "$ROLE" in
    iran)
      env_vars="Environment=SPLIT_SOCKS_LISTEN=${SOCKS_LISTEN}"
      env_vars="$env_vars
Environment=SPLIT_WS_LISTEN=${WS_LISTEN}"
      env_vars="$env_vars
Environment=SPLIT_DOWN_CARRIER_ADDR=${DOWN_CARRIER_ADDR}"
      ;;
    germany)
      env_vars="Environment=SPLIT_DOWN_LISTEN=${DOWN_LISTEN}"
      env_vars="$env_vars
Environment=SPLIT_UP_WS_URL=${UP_WS_URL}"
      ;;
  esac

  cat > "$service_file" <<EOF
[Unit]
Description=${ROLE^} Splitter Daemon (Asymmetric Split-Tunnel v${VERSION})
After=network.target
Wants=xray.service

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/${ROLE}-splitter
Restart=always
RestartSec=5
${env_vars}
Environment=SPLIT_SECRET=${SECRET}
Environment=SPLIT_METRICS_PORT=${METRICS_PORT}
Environment=SPLIT_RELAY_BUF=${RELAY_BUF}
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${ROLE}-splitter

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "${ROLE}-splitter"
  systemctl start "${ROLE}-splitter"

  sleep 2
  if systemctl is-active --quiet "${ROLE}-splitter"; then
    info "${ROLE}-splitter is running."
    journalctl -u "${ROLE}-splitter" --no-pager -n 5
  else
    warn "${ROLE}-splitter failed to start. Check logs:"
    journalctl -u "${ROLE}-splitter" --no-pager -n 20
  fi
}

# ============================================================
# Xray config merge (requires python3 or jq)
# ============================================================
find_xray_config() {
  if [ -n "$XRAY_CONFIG_PATH" ]; then
    echo "$XRAY_CONFIG_PATH"
    return
  fi
  for path in "${XRAY_CONFIGS[@]}"; do
    if [ -f "$path" ]; then
      echo "$path"
      return
    fi
  done
  echo ""
}

merge_xray_config() {
  local xray_conf
  xray_conf=$(find_xray_config)

  if [ -z "$xray_conf" ]; then
    warn "Xray config not found. Please apply the following JSON manually."
    show_xray_snippets
    return
  fi

  if ! command -v python3 &>/dev/null; then
    warn "python3 not found. Please apply the following JSON manually."
    show_xray_snippets
    return
  fi

  info "Backing up Xray config: ${xray_conf}.bak.$(date +%s)"
  cp "$xray_conf" "${xray_conf}.bak.$(date +%s)"

  case "$ROLE" in
    iran)
      python3 -c "
import json, sys

with open('$xray_conf', 'r') as f:
  cfg = json.load(f)

outs = cfg.get('outbounds', [])
if not any(o.get('tag') == 'to-splitter' for o in outs):
    outs.append({
        'tag': 'to-splitter',
        'protocol': 'socks',
        'settings': {'servers': [{'address': '127.0.0.1', 'port': ${SOCKS_LISTEN##*:}}]}
    })
    cfg['outbounds'] = outs

routing = cfg.get('routing', {})
rules = routing.get('rules', [])
user_inbound = input('Enter your user inbound tag (e.g. user-vless-reality): ')
rules = [r for r in rules if not (r.get('type') == 'field' and r.get('inboundTag') and user_inbound in r.get('inboundTag', []))]
rules.append({
    'type': 'field',
    'inboundTag': [user_inbound],
    'outboundTag': 'to-splitter'
})
routing['rules'] = rules
cfg['routing'] = routing

with open('$xray_conf', 'w') as f:
    json.dump(cfg, f, indent=2)

print('Xray config updated successfully.')
" 2>&1
      ;;
    germany)
      info "Germany server: no Xray config changes needed for now."
      ;;
  esac
}

show_xray_snippets() {
  case "$ROLE" in
    iran)
      cat <<'SNIPPET'
Add to Xray config "outbounds":
{
  "tag": "to-splitter",
  "protocol": "socks",
  "settings": {"servers": [{"address": "127.0.0.1", "port": 10900}]}
}

Add to Xray config "routing.rules":
{
  "type": "field",
  "inboundTag": ["your-user-inbound-tag"],
  "outboundTag": "to-splitter"
}
SNIPPET
      ;;
  esac
}

# ============================================================
# Nginx config (Iran only)
# ============================================================
configure_nginx() {
  [ "$NGINX_CONFIG" != "y" ] && [ "$NGINX_CONFIG" != "Y" ] && return
  command -v nginx &>/dev/null || { warn "Nginx not found."; return; }
  info "Configuring Nginx for CDN WebSocket..."
  cat > /etc/nginx/conf.d/split-tunnel.conf <<EOF
server {
    listen ${WS_LISTEN%%:*} default_server;
    server_name _;
    location /upload {
        proxy_pass http://${WS_LISTEN%%:*}:9001;
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
  nginx -t 2>&1 && systemctl reload nginx || error "Nginx config failed."
}

# ============================================================
# Uninstall
# ============================================================
uninstall() {
  warn "Uninstalling ${ROLE}-splitter..."
  systemctl stop "${ROLE}-splitter" 2>/dev/null || true
  systemctl disable "${ROLE}-splitter" 2>/dev/null || true
  rm -f "${SYSTEMD_DIR}/${ROLE}-splitter.service"
  systemctl daemon-reload
  rm -f "${INSTALL_DIR}/${ROLE}-splitter"
  info "Uninstall complete."
}

# ============================================================
# Main
# ============================================================
main() {
  parse_args "$@"
  check_root

  if [ -z "$ROLE" ]; then
    info "Split-Tunnel Installer v${VERSION}"
    gather_params_interactive
  fi

  # Assign defaults for non-interactive mode (CLI flags or hardcoded defaults)
  case "$ROLE" in
    iran)
      SOCKS_LISTEN="${SOCKS_LISTEN:-127.0.0.1:10900}"
      WS_LISTEN="${WS_LISTEN:-127.0.0.1:9001}"
      DOWN_CARRIER_ADDR="${DOWN_CARRIER_ADDR:-127.0.0.1:10802}"
      ;;
    germany)
      DOWN_LISTEN="${DOWN_LISTEN:-:9002}"
      UP_WS_URL="${UP_WS_URL:-wss://cdn.example.com/upload}"
      ;;
  esac

  # Generate secret if not provided
  if [ -z "$SECRET" ]; then
    SECRET=$(openssl rand -hex 24 2>/dev/null || head -c 48 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 48)
    echo ""
    echo -e "${YELLOW}============================================${NC}"
    echo -e "${YELLOW}SECRET: ${SECRET}${NC}"
    echo -e "${YELLOW}============================================${NC}"
    echo ""
  fi

  info "Role: $ROLE"
  info "Secret: ${SECRET:0:4}**** (${#SECRET} chars)"

  case "$ROLE" in
    iran)
      info "SOCKS5: $SOCKS_LISTEN | WS: $WS_LISTEN | Down: $DOWN_CARRIER_ADDR"
      ;;
    germany)
      info "Down: $DOWN_LISTEN | Up WS: $UP_WS_URL"
      ;;
  esac

  check_go
  download_and_build
  install_systemd_service
  merge_xray_config
  configure_nginx

  echo ""
  info "============================================"
  info "Installation complete!"
  info "============================================"
  case "$ROLE" in
    iran)
      info "Next steps:"
      info "  1. Create ArvanCloud CDN zone with origin pointing to this server"
      info "  2. Set SPLIT_UP_WS_URL on Germany to your CDN domain: wss://<cdn-domain>/upload"
      info "  3. Use this secret on Germany: $SECRET"
      info "  4. Check metrics: curl http://127.0.0.1:${METRICS_PORT:-0}/metrics 2>/dev/null || echo 'Metrics disabled'"
      ;;
    germany)
      info "Next steps:"
      info "  1. Use this secret on Iran: $SECRET"
      info "  2. Ensure Xray has inbound for download tunnel (port from SPLIT_DOWN_LISTEN)"
      info "  3. Check metrics: curl http://127.0.0.1:${METRICS_PORT:-0}/metrics 2>/dev/null || echo 'Metrics disabled'"
      ;;
  esac
}

# Handle uninstall flag
if [ "${1:-}" = "uninstall" ]; then
  ROLE="${2:-germany}"
  uninstall
  exit 0
fi

main "$@"
