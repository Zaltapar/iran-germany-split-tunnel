#!/bin/bash
set -euo pipefail

VERSION="1.0.0"
REPO="github.com/Zaltapar/iran-germany-split-tunnel"
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

ROLE="" SECRET="" METRICS_PORT="0" RELAY_BUF="32768"
SOCKS_LISTEN="127.0.0.1:10900"
WS_LISTEN="127.0.0.1:9001"
DOWN_CARRIER_ADDR="127.0.0.1:10802"
UP_WS_URL="wss://cdn.example.com/upload"
DOWN_LISTEN=":9002"

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      iran|germany) ROLE="$1"; shift ;;
      --secret) SECRET="$2"; shift 2 ;;
      --metrics-port) METRICS_PORT="$2"; shift 2 ;;
      --relay-buf) RELAY_BUF="$2"; shift 2 ;;
      *) error "Unknown flag: $1"; exit 1 ;;
    esac
  done
}

check_root() { [ "$(id -u)" -ne 0 ] && { error "Run as root."; exit 1; }; }
check_go() {
  command -v go &>/dev/null || { warn "Installing golang..."; apt-get update -qq && apt-get install -y -qq golang-go; }
  command -v go &>/dev/null || { error "Go install failed."; exit 1; }
}

download_and_build() {
  info "Downloading source..."
  local tmpdir=$(mktemp -d)
  cd "$tmpdir"
  curl -fsSL -o split-tunnel.tar.gz "$TARBALL_URL"
  mkdir -p src
  tar xzf split-tunnel.tar.gz -C src --strip-components=1 2>/dev/null || tar xzf split-tunnel.tar.gz -C src
  cd src
  GOOS=linux GOARCH=amd64 go build -o "${INSTALL_DIR}/iran-splitter" ./cmd/iran-splitter 2>/dev/null
  GOOS=linux GOARCH=amd64 go build -o "${INSTALL_DIR}/germany-splitter" ./cmd/germany-splitter 2>/dev/null
  chmod 755 "${INSTALL_DIR}/iran-splitter" "${INSTALL_DIR}/germany-splitter"
  info "Binaries built and installed"
  rm -rf "$tmpdir"
}

install_systemd_service() {
  local service_file="${SYSTEMD_DIR}/${ROLE}-splitter.service"
  local env_vars=""
  case "$ROLE" in
    iran) env_vars="Environment=SPLIT_SOCKS_LISTEN=${SOCKS_LISTEN}
Environment=SPLIT_WS_LISTEN=${WS_LISTEN}
Environment=SPLIT_DOWN_CARRIER_ADDR=${DOWN_CARRIER_ADDR}" ;;
    germany) env_vars="Environment=SPLIT_DOWN_LISTEN=${DOWN_LISTEN}
Environment=SPLIT_UP_WS_URL=${UP_WS_URL}" ;;
  esac
  cat > "$service_file" <<EOF
[Unit]
Description=${ROLE^} Splitter Daemon (v${VERSION})
After=network.target

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
  systemctl is-active --quiet "${ROLE}-splitter" && info "${ROLE}-splitter running" || warn "Check: journalctl -u ${ROLE}-splitter -n 20"
}

main() {
  parse_args "$@"
  [ -z "$ROLE" ] && { error "Usage: $0 [iran|germany] --secret SECRET"; exit 1; }
  [ -z "$SECRET" ] && { error "--secret required"; exit 1; }
  check_root
  check_go
  download_and_build
  install_systemd_service
  info "Installation complete!"
}

if [ "${1:-}" = "uninstall" ]; then
  systemctl stop "${2:-iran}-splitter" 2>/dev/null || true
  systemctl disable "${2:-iran}-splitter" 2>/dev/null || true
  rm -f "${SYSTEMD_DIR}/${2:-iran}-splitter.service"
  systemctl daemon-reload
  rm -f "${INSTALL_DIR}/${2:-iran}-splitter"
  info "Uninstall complete"
  exit 0
fi

main "$@"
