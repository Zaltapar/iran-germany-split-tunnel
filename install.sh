#!/bin/bash
set -euo pipefail

VERSION="1.0.0"
TARBALL_URL="https://github.com/Zaltapar/iran-germany-split-tunnel/archive/refs/heads/main.tar.gz"
INSTALL_DIR="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

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
      iran|germany) ROLE="$1"; shift ;;
      --secret) SECRET="$2"; shift 2 ;;
      --secret=*) SECRET="${1#*=}"; shift ;;
      --metrics-port) METRICS_PORT="$2"; shift 2 ;;
      --relay-buf) RELAY_BUF="$2"; shift 2 ;;
      --xray-config) XRAY_CONFIG_PATH="$2"; shift 2 ;;
      *) error "Unknown flag: $1"; exit 1 ;;
    esac
  done
}

prompt() {
  local prompt_text="$1"
  local default="$2"
  echo -en "${YELLOW}${prompt_text}${NC} "
  if [ -n "$default" ]; then echo -en "[${default}]: "; else echo -en ": "; fi
  if [ -n "$default" ]; then read -r input; echo "${input:-$default}"; else read -r input; echo "$input"; fi
}

gather_params_interactive() {
  if [ -z "$ROLE" ]; then ROLE=$(prompt "Which role? (iran/germany)" ""); fi
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
      DOWN_CARRIER_ADDR="${DOWN_CARRIER_ADDR:-$(prompt 'Xray down-carrier dial' '127.0.0.1:10802')}"
      NGINX_CONFIG="${NGINX_CONFIG:-$(prompt 'Configure Nginx for CDN WebSocket? (y/n)' 'y')}"
      ;;
    germany)
      DOWN_LISTEN="${DOWN_LISTEN:-$(prompt 'Down-carrier TCP listen' ':9002')}"
      UP_WS_URL="${UP_WS_URL:-$(prompt 'CDN WebSocket URL' 'wss://cdn.example.com/upload')}"
      ;;
  esac
}

check_root() {
  if [ "$(id -u)" -ne 0 ]; then error "Must be run as root."; exit 1; fi
}

check_go() {
  if ! command -v go &>/dev/null; then
    warn "Go not installed. Installing..."
    apt-get update -qq && apt-get install -y -qq golang-go 2>/dev/null
    if ! command -v go &>/dev/null; then error "Go install failed."; exit 1; fi
    info "Go installed: $(go version)"
  fi
}

download_and_build() {
  info "Downloading source..."
  local tmpdir
  tmpdir=$(mktemp -d)
  cd "$tmpdir"
  curl -fsSL -o split-tunnel.tar.gz "$TARBALL_URL"
  mkdir -p src
  tar xzf split-tunnel.tar.gz -C src --strip-components=1 2>/dev/null || tar xzf split-tunnel.tar.gz -C src
  cd "$tmpdir/src"
  if [ ! -f go.mod ]; then error "go.mod not found."; rm -rf "$tmpdir"; exit 1; fi

  info "Building..."
  GOOS=linux GOARCH=amd64 go build -o "${INSTALL_DIR}/iran-splitter" ./cmd/iran-splitter 2>/dev/null || \
    GOOS=linux GOARCH=amd64 go build -o "${INSTALL_DIR}/iran-splitter" . 2>/dev/null
  GOOS=linux GOARCH=amd64 go build -o "${INSTALL_DIR}/germany-splitter" ./cmd/germany-splitter 2>/dev/null || \
    GOOS=linux GOARCH=amd64 go build -o "${INSTALL_DIR}/germany-splitter" . 2>/dev/null
  chmod 755 "${INSTALL_DIR}/iran-splitter" "${INSTALL_DIR}/germany-splitter"
  rm -rf "$tmpdir"
  info "Binaries installed."
}

install_systemd_service() {
  local sf="${SYSTEMD_DIR}/${ROLE}-splitter.service"
  info "Installing systemd service: $sf"
  local env_vars=""
  case "$ROLE" in
    iran) env_vars="Environment=SPLIT_SOCKS_LISTEN=${SOCKS_LISTEN}
Environment=SPLIT_WS_LISTEN=${WS_LISTEN}
Environment=SPLIT_DOWN_CARRIER_ADDR=${DOWN_CARRIER_ADDR}" ;;
    germany) env_vars="Environment=SPLIT_DOWN_LISTEN=${DOWN_LISTEN}
Environment=SPLIT_UP_WS_URL=${UP_WS_URL}" ;;
  esac

  cat > "$sf" <<EOF
[Unit]
Description=${ROLE^} Splitter Daemon v${VERSION}
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
    warn "${ROLE}-splitter failed. Check: journalctl -u ${ROLE}-splitter"
  fi
}

configure_nginx() {
  [ "$NGINX_CONFIG" != "y" ] && [ "$NGINX_CONFIG" != "Y" ] && return
  command -v nginx &>/dev/null || { warn "Nginx not found."; return; }
  info "Configuring Nginx..."
  cat > /etc/nginx/conf.d/split-tunnel.conf <<EOF
server {
    listen ${WS_LISTEN%%:*} default_server;
    server_name _;
    location /upload {
        proxy_pass http://127.0.0.1:9001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 3600s;
    }
}
EOF
  nginx -t 2>&1 && systemctl reload nginx || error "Nginx config failed."
}

uninstall() {
  warn "Uninstalling ${ROLE}-splitter..."
  systemctl stop "${ROLE}-splitter" 2>/dev/null || true
  systemctl disable "${ROLE}-splitter" 2>/dev/null || true
  rm -f "${SYSTEMD_DIR}/${ROLE}-splitter.service"
  systemctl daemon-reload
  rm -f "${INSTALL_DIR}/${ROLE}-splitter"
  info "Uninstall complete."
}

main() {
  parse_args "$@"
  check_root
  [ -z "$ROLE" ] && gather_params_interactive
  info "Role: $ROLE | Secret: ${SECRET:0:4}****"
  check_go
  download_and_build
  install_systemd_service
  configure_nginx
  echo ""
  info "============================================"
  info "Installation complete!"
  info "============================================"
  case "$ROLE" in
    iran) info "1. Create CDN zone. 2. Use secret on Germany: $SECRET" ;;
    germany) info "1. Use secret on Iran: $SECRET" ;;
  esac
}

[ "${1:-}" = "uninstall" ] && { ROLE="${2:-germany}"; uninstall; exit 0; }
main "$@"
