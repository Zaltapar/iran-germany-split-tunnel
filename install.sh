#!/bin/bash
set -euo pipefail

VERSION="1.0.0"
REPO="github.com/Zaltapar/iran-germany-split-tunnel"
TARBALL_URL="https://github.com/Zaltapar/iran-germany-split-tunnel/archive/refs/heads/main.tar.gz"
INSTALL_DIR="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"
XRAY_CONFIGS=( "/usr/local/etc/xray/config.json" "/etc/xray/config.json" )

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

ROLE="" SECRET="" DOWN_CARRIER_ADDR="" WS_LISTEN="" SOCKS_LISTEN="" UP_WS_URL="" DOWN_LISTEN="" METRICS_PORT="0" RELAY_BUF="32768" NGINX_CONFIG="n" XRAY_CONFIG_PATH=""

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      iran|germany) ROLE="$1"; shift ;;
      --secret) SECRET="$2"; shift 2 ;;
      --secret=*) SECRET="${1#*=}"; shift ;;
      --metrics-port) METRICS_PORT="$2"; shift 2 ;;
      --relay-buf) RELAY_BUF="$2"; shift 2 ;;
      --xray-config) XRAY_CONFIG_PATH="$2"; shift 2 ;;
      --socks-listen) SOCKS_LISTEN="$2"; shift 2 ;;
      --socks-listen=*) SOCKS_LISTEN="${1#*=}"; shift ;;
      --ws-listen) WS_LISTEN="$2"; shift 2 ;;
      --ws-listen=*) WS_LISTEN="${1#*=}"; shift ;;
      --down-carrier-addr) DOWN_CARRIER_ADDR="$2"; shift 2 ;;
      --down-carrier-addr=*) DOWN_CARRIER_ADDR="${1#*=}"; shift ;;
      --down-listen) DOWN_LISTEN="$2"; shift 2 ;;
      --down-listen=*) DOWN_LISTEN="${1#*=}"; shift ;;
      --up-ws-url) UP_WS_URL="$2"; shift 2 ;;
      --up-ws-url=*) UP_WS_URL="${1#*=}"; shift ;;
      *) error "Unknown flag: $1"; echo "Usage: $0 [iran|germany] [--secret SECRET] [--metrics-port PORT] [--relay-buf SIZE] [--xray-config PATH] [--socks-listen ADDR] [--ws-listen ADDR] [--down-carrier-addr ADDR] [--down-listen PORT] [--up-ws-url URL]"; exit 1 ;;
    esac
  done
}

prompt() {
  local prompt_text="$1" default="$2"
  echo -en "${YELLOW}${prompt_text}${NC} "
  if [ -n "$default" ]; then echo -en "[${default}]: "; else echo -en ": "; fi
  if [ -n "$default" ]; then read -r input; echo "${input:-$default}"; else read -r input; echo "$input"; fi
}

gather_params_interactive() {
  [ -z "$ROLE" ] && ROLE=$(prompt "Which role? (iran/germany)" "")
  if [ -z "$SECRET" ]; then
    SECRET=$(prompt "Shared secret (leave empty for random)" "")
    [ -z "$SECRET" ] && SECRET=$(openssl rand -hex 24 2>/dev/null || head -c 48 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 48) && info "Generated random secret: $SECRET"
  fi
  case "$ROLE" in
    iran) SOCKS_LISTEN="${SOCKS_LISTEN:-$(prompt 'SOCKS5 listen' '127.0.0.1:10900')}"; WS_LISTEN="${WS_LISTEN:-$(prompt 'WS listen' '127.0.0.1:9001')}"; DOWN_CARRIER_ADDR="${DOWN_CARRIER_ADDR:-$(prompt 'Xray down-carrier dial' '127.0.0.1:10802')}"; NGINX_CONFIG="${NGINX_CONFIG:-$(prompt 'Configure Nginx? (y/n)' 'y')}" ;;
    germany) DOWN_LISTEN="${DOWN_LISTEN:-$(prompt 'Down-carrier TCP listen' ':9002')}"; UP_WS_URL="${UP_WS_URL:-$(prompt 'CDN WebSocket URL' 'wss://cdn.example.com/upload')}" ;;
    *) error "Unknown role: $ROLE"; exit 1 ;;
  esac
}

check_root() { [ "$(id -u)" -ne 0 ] && { error "Must be root."; exit 1; }; }

check_go() {
  if ! command -v go &>/dev/null; then
    warn "Go not installed. Installing golang..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq && apt-get install -y -qq golang-go 2>/dev/null
    if ! command -v go &>/dev/null; then error "Go install failed."; exit 1; fi
    info "Go installed: $(go version)"
  fi
}

download_and_build() {
  info "Downloading source..."
  local tmpdir; tmpdir=$(mktemp -d); cd "$tmpdir"
  curl -fsSL -o split-tunnel.tar.gz "$TARBALL_URL"
  mkdir -p src; tar xzf split-tunnel.tar.gz -C src 2>/dev/null
  local mod_dir; mod_dir=$(find "$tmpdir" -type f -name "go.mod" -exec dirname {} \; | head -n 1)
  if [ -z "$mod_dir" ] || [ ! -f "$mod_dir/go.mod" ]; then error "go.mod not found."; rm -rf "$tmpdir"; exit 1; fi
  cd "$mod_dir"
  info "Building..."
  go build -o "${INSTALL_DIR}/iran-splitter" ./cmd/iran-splitter
  go build -o "${INSTALL_DIR}/germany-splitter" ./cmd/germany-splitter
  chmod 755 "${INSTALL_DIR}/iran-splitter" "${INSTALL_DIR}/germany-splitter"
  info "Binaries installed to $INSTALL_DIR"
  ls -lh "${INSTALL_DIR}/"*splitter
  rm -rf "$tmpdir"
}

install_systemd_service() {
  local service_file="${SYSTEMD_DIR}/${ROLE}-splitter.service"
  info "Installing systemd service: $service_file"
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
  info "Systemd service installed to $service_file"
  ls -l "$service_file"
  systemctl daemon-reload 2>/dev/null || warn "systemctl daemon-reload skipped"
  systemctl enable "${ROLE}-splitter" 2>/dev/null || warn "systemctl enable skipped"
  systemctl restart "${ROLE}-splitter" 2>/dev/null || warn "systemctl restart skipped"
  echo ""
  info "Service status:"
  systemctl status "${ROLE}-splitter" --no-pager -l 2>/dev/null || warn "Could not get service status"
}

find_xray_config() {
  [ -n "$XRAY_CONFIG_PATH" ] && { echo "$XRAY_CONFIG_PATH"; return; }
  for path in "${XRAY_CONFIGS[@]}"; do [ -f "$path" ] && { echo "$path"; return; }; done
  echo ""
}

merge_xray_config() {
  local xray_conf; xray_conf=$(find_xray_config)
  [ -z "$xray_conf" ] && { warn "Xray config not found."; return; }
  command -v python3 &>/dev/null || { warn "python3 not found."; return; }
  info "Backing up Xray config: ${xray_conf}.bak.$(date +%s)"
  cp "$xray_conf" "${xray_conf}.bak.$(date +%s)"
  case "$ROLE" in
    iran) python3 -c "
import json
with open('$xray_conf') as f: cfg=json.load(f)
outs=cfg.get('outbounds',[])
if not any(o.get('tag')=='to-splitter' for o in outs): outs.append({'tag':'to-splitter','protocol':'socks','settings':{'servers':[{'address':'127.0.0.1','port':${SOCKS_LISTEN##*:}}]}}); cfg['outbounds']=outs
cfg.setdefault('routing',{}).setdefault('rules',[]).append({'type':'field','inboundTag':['USER_INBOUND'],'outboundTag':'to-splitter'})
with open('$xray_conf','w') as f: json.dump(cfg,f,indent=2)" 2>&1 ;;
    germany) ;;
  esac
}

configure_nginx() {
  [ "$NGINX_CONFIG" != "y" ] && return
  command -v nginx &>/dev/null || return
  cat > /etc/nginx/conf.d/split-tunnel.conf <<EOF
server { listen ${WS_LISTEN%%:*} default_server; location /upload { proxy_pass http://127.0.0.1:9001; proxy_http_version 1.1; proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection "upgrade"; proxy_read_timeout 3600s; } }
EOF
  nginx -t && systemctl reload nginx
}

main() {
  parse_args "$@"; check_root
  [ -z "$ROLE" ] && gather_params_interactive
  case "$ROLE" in
    iran) SOCKS_LISTEN="${SOCKS_LISTEN:-127.0.0.1:10900}"; WS_LISTEN="${WS_LISTEN:-127.0.0.1:9001}"; DOWN_CARRIER_ADDR="${DOWN_CARRIER_ADDR:-127.0.0.1:10802}" ;;
    germany) DOWN_LISTEN="${DOWN_LISTEN:-:9002}"; UP_WS_URL="${UP_WS_URL:-wss://cdn.example.com/upload}" ;;
  esac
  if [ -z "$SECRET" ]; then
    SECRET=$(openssl rand -hex 24 2>/dev/null || head -c 48 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 48)
    echo -e "${YELLOW}SECRET: ${SECRET}${NC}"
  fi
  info "Role: $ROLE | Secret: ${SECRET:0:4}**** (${#SECRET} chars)"
  check_go; download_and_build; install_systemd_service; merge_xray_config; configure_nginx
  info "Installation complete!"
}

[ "${1:-}" = "uninstall" ] && { ROLE="${2:-germany}"; warn "Uninstalling ${ROLE}-splitter..."; systemctl stop "${ROLE}-splitter" 2>/dev/null; systemctl disable "${ROLE}-splitter" 2>/dev/null; rm -f "${SYSTEMD_DIR}/${ROLE}-splitter.service"; systemctl daemon-reload; rm -f "${INSTALL_DIR}/${ROLE}-splitter"; info "Uninstall complete."; exit 0; }
main "$@"
