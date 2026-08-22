#!/bin/bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

TARGET="${1:-both}"
BUILD_FLAG="${2:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

check_go() {
    if ! command -v go &> /dev/null; then
        log_error "Go is not installed. Please install Go 1.21+ first."
        exit 1
    fi
    log_info "Go version: $(go version)"
}

build() {
    log_info "Building splitters..."
    cd "$SCRIPT_DIR"
    go build -o iran-splitter ./cmd/iran-splitter || { log_error "Failed to build iran-splitter"; exit 1; }
    go build -o germany-splitter ./cmd/germany-splitter || { log_error "Failed to build germany-splitter"; exit 1; }
    log_info "Build complete"
}

deploy_iran() {
    log_info "Deploying iran-splitter..."
    local BIN="$SCRIPT_DIR/iran-splitter"
    if [ ! -f "$BIN" ]; then
        log_error "iran-splitter binary not found. Run with --build first."
        exit 1
    fi
    sudo cp "$BIN" /usr/local/bin/iran-splitter
    sudo chmod 755 /usr/local/bin/iran-splitter
    sudo cp "$SCRIPT_DIR/systemd/iran-splitter.service" /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable iran-splitter
    sudo systemctl restart iran-splitter || true
    log_info "iran-splitter deployed"
}

deploy_germany() {
    log_info "Deploying germany-splitter..."
    local BIN="$SCRIPT_DIR/germany-splitter"
    if [ ! -f "$BIN" ]; then
        log_error "germany-splitter binary not found. Run with --build first."
        exit 1
    fi
    sudo cp "$BIN" /usr/local/bin/germany-splitter
    sudo chmod 755 /usr/local/bin/germany-splitter
    sudo cp "$SCRIPT_DIR/systemd/germany-splitter.service" /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable germany-splitter
    sudo systemctl restart germany-splitter || true
    log_info "germany-splitter deployed"
}

status() {
    log_info "Service status:"
    systemctl status iran-splitter --no-pager -l 2>/dev/null || echo "Not installed"
    echo "---"
    systemctl status germany-splitter --no-pager -l 2>/dev/null || echo "Not installed"
}

main() {
    log_info "Split-Tunnel Deploy Script"
    check_go
    if [ "$BUILD_FLAG" = "--build" ] || [ "$TARGET" = "both" ]; then
        build
    fi
    case "$TARGET" in
        iran) deploy_iran ;;
        germany) deploy_germany ;;
        both) deploy_iran; deploy_germany ;;
        status) status ;;
        *) log_error "Unknown target: $TARGET"; echo "Usage: $0 [iran|germany|both|status] [--build]"; exit 1 ;;
    esac
    log_info "Deployment complete!"
}

main "$@"
