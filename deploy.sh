#!/bin/bash
#
# Deploy script for Iran-Germany Asymmetric Split-Tunnel
# Usage: ./deploy.sh [iran|germany|both|status] [--build]
#
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Parse arguments
TARGET="${1:-both}"
BUILD_FLAG="${2:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check Go is installed
check_go() {
    if ! command -v go &> /dev/null; then
        log_error "Go is not installed. Please install Go 1.21+ first."
        exit 1
    fi
    log_info "Go version: $(go version)"
}

# Build both splitters
build() {
    log_info "Building splitters..."
    cd "$SCRIPT_DIR"

    go build -o iran-splitter ./cmd/iran-splitter
    if [ $? -eq 0 ]; then
        log_info "Built iran-splitter successfully"
    else
        log_error "Failed to build iran-splitter"
        exit 1
    fi

    go build -o germany-splitter ./cmd/germany-splitter
    if [ $? -eq 0 ]; then
        log_info "Built germany-splitter successfully"
    else
        log_error "Failed to build germany-splitter"
        exit 1
    fi

    log_info "Build complete"
}

# Deploy to Iran server
deploy_iran() {
    log_info "Deploying iran-splitter..."

    local BIN="$SCRIPT_DIR/iran-splitter"
    if [ ! -f "$BIN" ]; then
        log_error "iran-splitter binary not found. Run with --build first."
        exit 1
    fi

    sudo cp "$BIN" /usr/local/bin/iran-splitter
    sudo chmod 755 /usr/local/bin/iran-splitter
    log_info "Binary copied to /usr/local/bin/iran-splitter"

    sudo cp "$SCRIPT_DIR/systemd/iran-splitter.service" /etc/systemd/system/
    log_info "Service file installed"

    sudo systemctl daemon-reload
    sudo systemctl enable iran-splitter
    log_info "Service enabled"

    log_info "Restarting iran-splitter service..."
    sudo systemctl restart iran-splitter || true

    sleep 1
    if sudo systemctl is-active --quiet iran-splitter; then
        log_info "iran-splitter is running"
    else
        log_warn "iran-splitter may have failed to start. Check with: journalctl -u iran-splitter -n 20"
    fi
}

# Deploy to Germany server
deploy_germany() {
    log_info "Deploying germany-splitter..."

    local BIN="$SCRIPT_DIR/germany-splitter"
    if [ ! -f "$BIN" ]; then
        log_error "germany-splitter binary not found. Run with --build first."
        exit 1
    fi

    sudo cp "$BIN" /usr/local/bin/germany-splitter
    sudo chmod 755 /usr/local/bin/germany-splitter
    log_info "Binary copied to /usr/local/bin/germany-splitter"

    sudo cp "$SCRIPT_DIR/systemd/germany-splitter.service" /etc/systemd/system/
    log_info "Service file installed"

    sudo systemctl daemon-reload
    sudo systemctl enable germany-splitter
    log_info "Service enabled"

    log_info "Restarting germany-splitter service..."
    sudo systemctl restart germany-splitter || true

    sleep 1
    if sudo systemctl is-active --quiet germany-splitter; then
        log_info "germany-splitter is running"
    else
        log_warn "germany-splitter may have failed to start. Check with: journalctl -u germany-splitter -n 20"
    fi
}

# Show status of services
status() {
    log_info "Service status:"
    echo ""
    echo "=== iran-splitter ==="
    systemctl status iran-splitter --no-pager -l 2>/dev/null || echo "Not installed"
    echo ""
    echo "=== germany-splitter ==="
    systemctl status germany-splitter --no-pager -l 2>/dev/null || echo "Not installed"
}

# Main entry point
main() {
    log_info "Iran-Germany Split-Tunnel Deploy Script"
    echo ""

    check_go

    if [ "$BUILD_FLAG" = "--build" ] || [ "$TARGET" = "both" ]; then
        build
    fi

    case "$TARGET" in
        iran)
            deploy_iran
            ;;
        germany)
            deploy_germany
            ;;
        both)
            deploy_iran
            deploy_germany
            ;;
        status)
            status
            ;;
        *)
            log_error "Unknown target: $TARGET"
            echo "Usage: $0 [iran|germany|both|status] [--build]"
            exit 1
            ;;
    esac

    echo ""
    log_info "Deployment complete!"
}

main "$@"