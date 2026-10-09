#!/usr/bin/env bash
# build-linux.sh — reproducible Linux amd64 build of the four split-tunnel
# binaries (D3 "binaries drift"): splitterctl, iran-splitter, germany-splitter,
# tunneldash.
#
# Reproducibility properties:
#   - CGO_ENABLED=0 GOOS=linux GOARCH=amd64 (static, no libstdc++ variance);
#   - -trimpath strips build-dir paths out of the binary;
#   - -ldflags="-s -w" strips the DWARF debug symbol table so the SHA-256 of
#     the binary depends on source, not the build machine's filesystem;
#   - -X main.buildInfo=<sha> stamps the git commit into each binary. Each
#     cmd/*/main.go declares `var buildInfo = ""` — the -X flag overwrites it
#     at link time. The stamp is a non-secret build identity only.
#
# The script NEVER commits the built binaries; it only writes
# dist_onclick/<name>-linux-amd64 and a SHA256SUMS sidecar so an operator can
# verify the exact bytes that a later deploy consumes. (dist_onclick/ is
# .gitignored — only SHA256SUMS is expected to be copied alongside the
# tarball on release, not the binaries themselves.)
#
# Usage:
#   bash scripts/build-linux.sh            # builds into ./dist_onclick
#   OUT_DIR=/tmp/build bash scripts/build-linux.sh
#
# Requirements: Go 1.21+, git.

set -euo pipefail
IFS=$'\n\t'

OUT_DIR="${OUT_DIR:-dist_onclick}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$REPO_ROOT"

# --- Resolve the commit stamp ------------------------------------------------
# Stamp the git short SHA (with a +dirty suffix if the working tree has
# uncommitted changes) into each binary's main.buildInfo via -X.
GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
GIT_DIRTY="$(git status --porcelain 2>/dev/null | head -1 || true)"
if [ -n "$GIT_DIRTY" ]; then
  BUILD_COMMIT="${GIT_COMMIT}+dirty"
else
  BUILD_COMMIT="${GIT_COMMIT}"
fi
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

info() { printf '  [i] %s\n' "$*"; }

info "building 4 Linux amd64 binaries into ${OUT_DIR}/"
info "  git commit stamp: ${BUILD_COMMIT} (built ${BUILD_DATE})"
info "  flags: CGO_ENABLED=0 GOOS=linux GOARCH=amd64 -trimpath -ldflags=\"-s -w -X main.buildInfo=${BUILD_COMMIT}\""

mkdir -p "$OUT_DIR"

# The four binaries; cmd/tunneldash is Germany-only but we still build it for
# a cross-platform artifact so the operator can pre-stash it. An ARRAY is used
# (not a space-separated string) because this script sets IFS=$'\n\t' above,
# which would break space-splitting of a plain for-loop word list.
TARGETS=(cmd/splitterctl cmd/iran-splitter cmd/germany-splitter cmd/tunneldash)

LDFLAGS="-s -w -X main.buildInfo=${BUILD_COMMIT}"

rm -f "${OUT_DIR}/SHA256SUMS"
for spec in "${TARGETS[@]}"; do
  name="$(basename "$spec")"
  out="${OUT_DIR}/${name}-linux-amd64"
  info "  building ${name} -> ${out}"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags "$LDFLAGS" \
    -o "$out" \
    "./$spec"
done

# --- Write the SHA256SUMS sidecar (D6: canonical name) ----------------------
# sha256sum produces "<hash>  <name>" lines (two-space separator) — this is the
# canonical host-side format the rollback scripts consume. Only the names of
# the just-built binaries, not arbitrary host files.
(
  cd "$OUT_DIR"
  for f in splitterctl-linux-amd64 iran-splitter-linux-amd64 germany-splitter-linux-amd64 tunneldash-linux-amd64; do
    sha256sum "$f"
  done > SHA256SUMS
)

info "SHA256SUMS written to ${OUT_DIR}/SHA256SUMS"
cat "$OUT_DIR/SHA256SUMS"

# --- Refuse to leave the workspace dirty from this script ------------------
# dist_onclick/ is .gitignored so the binaries + sidecar do not enter a git
# index. If an operator wants to publish them, they commit SHA256SUMS only.
info "done. Binaries are in ${OUT_DIR}/ (not committed; SHA256SUMS may be copied to a release manifest)."
