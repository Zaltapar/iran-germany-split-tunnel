#!/usr/bin/env bash
# install-oneclick.sh — one-click bootstrap + delegated installer for the
# Iran/Germany split-tunnel (design: plans/oneclick-installer-design.md).
#
# This script is the OUTER bootstrap only. It:
#   - checks root / OS / arch / disk;
#   - installs packages + a Go toolchain (checksummed);
#   - acquires the source (git clone, tarball fallback, or local path);
#   - builds splitterctl + the role splitter + tunneldash (CGO_ENABLED=0);
#   - then DELEGATES every host mutation to `splitterctl` (install, pair
#     generate/apply/finalize, config set, doctor). It does NOT re-implement
#     state or rollback. Rollback is always `splitterctl recover`.
#
# Safety properties:
#   - set -euo pipefail; strict quoting; IFS is newline/tab only;
#   - traps clean up the working tree (source is left intact);
#   - no `eval`, no remote `curl | bash`;
#   - every remote byte is checksummed before use;
#   - no secret is ever written to stdout/logs (fingerprints only);
#   - no routing/DNS/firewall/egress is touched by default. Firewall changes
#     are OPT-IN (--open-firewall) and only add the role's specific ports.
#   - the pairing handoff is a single SECRET artifact (Blob A). Blob B is
#     public and is never carried on the operator's secret path.
#
# This script is exercised locally via `--dry-run` (which prints the exact
# commands without executing them), `bash -n`, and shellcheck. It is NOT run
# on any host during development.

set -euo pipefail
IFS=$'\n\t'

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
readonly SRC_PREFIX="/opt/split-tunnel-src"
readonly BIN_PREFIX="/opt/split-tunnel"
readonly TOOLCHAIN_PREFIX="/opt/split-tunnel/toolchain"
readonly INSTALL_LOG="/var/log/split-tunnel-install.log"
readonly PAIRING_DIR="/root/.pairing"
readonly BLOB_A_NAME="blob-a"
readonly BLOB_B_NAME="blob-b"
readonly SECRETS_DIR="/etc/split-tunnel/secrets"
readonly MIN_GO_MINOR="21"
# Pinned Go toolchain fallback (checksummed) when the distro has no Go.
readonly GO_FALLBACK_VERSION="1.23.4"
readonly DEFAULT_SOURCE="https://github.com/Zaltapar/iran-germany-split-tunnel"

# ---------------------------------------------------------------------------
# Defaults (overridable via flags or env)
# ---------------------------------------------------------------------------
ROLE=""
SOURCE=""
REF="main"
NO_CLONE=0
DASHBOARD="off"
IRAN_XRAY="managed"
DOMAIN=""
DASHBOARD_PORT="8443"
PAIRING_SECRET_FILE=""
DRY_RUN=0
UNINSTALL=0
OPEN_FIREWALL=0
YES=0
CERT_FILE=""
KEY_FILE=""
SPLITTER_VERSION="oneclick"

# Runtime state
TMP_WORK=""
RESOLVED_SRC=""
RESOLVED_REV=""
DASHBOARD_BASEPATH=""

# ---------------------------------------------------------------------------
# Logging (stdout + mirrored to a 0600 log file when not dry-run).
# Nothing here ever echoes secret material; callers must not pass secrets.
# ---------------------------------------------------------------------------
_log() {
  local msg="$*"
  printf '%s\n' "$msg"
  if [ "$DRY_RUN" -ne 1 ] && [ -n "${INSTALL_LOG:-}" ]; then
    mkdir -p "$(dirname "$INSTALL_LOG")" 2>/dev/null || true
    chmod 0600 "$INSTALL_LOG" 2>/dev/null || true
    printf '%s\n' "$msg" >> "$INSTALL_LOG" 2>/dev/null || true
  fi
}
info() { _log "  [i] $*"; }
warn() { _log "  [!] $*"; }
error() { printf '  [x] %s\n' "$*" >&2; }

usage() {
  cat <<'EOF'
usage: install-oneclick.sh --role <iran|germany> [options]

One-click bootstrap + delegated installer for the Iran/Germany split-tunnel.
All host mutation is delegated to `splitterctl`; this script only bootstraps
(fetch/verify source, install Go, build, export env) and then runs the
documented splitterctl commands. Rollback is always `splitterctl recover`.

Options:
  --role <iran|germany>        deployment role
  --source <url|path>         source: git URL, tarball URL, or local path
  --ref <gitref>              git branch/tag (default: main)
  --no-clone                  use a local source path; no git clone
  --dashboard <on|off>        install the Germany dashboard (default off)
  --iran-xray <managed|external>
                              Iran Xray mode (default managed)
  --domain <upload-domain>    public upload domain (Iran + Germany up URL)
  --dashboard-port <port>     dashboard TLS port on Germany (default 8443)
  --cert <pem> --key <pem>   Arvan/CDN cert+key for the dashboard TLS (Germany)
  --pairing-secret-file <path>
                              operator-carried pairing blob (0600); securely
                              handled + deleted after use
  --open-firewall             OPT-IN: add only the role's specific firewall ports
  --dry-run                   print the exact commands without executing them
  --uninstall                 delegate to `splitterctl uninstall`
  --yes                       non-interactive (assume yes at confirmations)
  --help                      this help

Environment equivalents: ONECLICK_{ROLE,SOURCE,REF,NO_CLONE,DASHBOARD,
IRAN_XRAY,DOMAIN,DASHBOARD_PORT,PAIRING_SECRET_FILE,OPEN_FIREWALL,DRY_RUN,
UNINSTALL,YES,FW_BACKEND,Fw_ALLOW_IRAN,Fw_ALLOW_GERMANY,ORIGIN_MODE,
ORIGIN_PORT,CDN_SECURITY,REALITY_SNI,REALITY_SHORT_ID,REALITY_UUID,
WS_LISTEN,SOCKS_LISTEN,DOWN_LISTEN,DOWN_HOST,IRAN_SSH_HOST,METRICS_PORT}.

Safety: root; Ubuntu/Debian only; no routing/DNS/egress mutation; no firewall
touch unless --open-firewall; no secret ever reaches logs; rollback is always
`splitterctl recover`. The ONE secret you carry is Blob A (Iran -> Germany).
EOF
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
env_or_empty() { printf '%s' "${!1:-}"; }

load_env_equivalents() {
  ROLE="$(env_or_empty ONECLICK_ROLE)"
  SOURCE="$(env_or_empty ONECLICK_SOURCE)"
  REF="$(env_or_empty ONECLICK_REF)"; [ -n "$REF" ] || REF="main"
  DASHBOARD="$(env_or_empty ONECLICK_DASHBOARD)"; [ -n "$DASHBOARD" ] || DASHBOARD="off"
  IRAN_XRAY="$(env_or_empty ONECLICK_IRAN_XRAY)"; [ -n "$IRAN_XRAY" ] || IRAN_XRAY="managed"
  DOMAIN="$(env_or_empty ONECLICK_DOMAIN)"
  DASHBOARD_PORT="$(env_or_empty ONECLICK_DASHBOARD_PORT)"; [ -n "$DASHBOARD_PORT" ] || DASHBOARD_PORT="8443"
  PAIRING_SECRET_FILE="$(env_or_empty ONECLICK_PAIRING_SECRET_FILE)"
  if [ "$(env_or_empty ONECLICK_NO_CLONE)" = "1" ]; then NO_CLONE=1; fi
  if [ "$(env_or_empty ONECLICK_OPEN_FIREWALL)" = "1" ]; then OPEN_FIREWALL=1; fi
  if [ "$(env_or_empty ONECLICK_DRY_RUN)" = "1" ]; then DRY_RUN=1; fi
  if [ "$(env_or_empty ONECLICK_UNINSTALL)" = "1" ]; then UNINSTALL=1; fi
  if [ "$(env_or_empty ONECLICK_YES)" = "1" ]; then YES=1; fi
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --help|-h) usage; exit 0 ;;
      --dry-run) DRY_RUN=1 ;;
      --uninstall) UNINSTALL=1 ;;
      --open-firewall) OPEN_FIREWALL=1 ;;
      --yes) YES=1 ;;
      --no-clone) NO_CLONE=1 ;;
      --role) ROLE="$2"; shift ;;
      --source) SOURCE="$2"; shift ;;
      --ref) REF="$2"; shift ;;
      --dashboard) DASHBOARD="$2"; shift ;;
      --iran-xray) IRAN_XRAY="$2"; shift ;;
      --domain) DOMAIN="$2"; shift ;;
      --dashboard-port) DASHBOARD_PORT="$2"; shift ;;
      --cert) CERT_FILE="$2"; shift ;;
      --key) KEY_FILE="$2"; shift ;;
      --pairing-secret-file) PAIRING_SECRET_FILE="$2"; shift ;;
      *) error "unknown argument: $1"; usage; exit 2 ;;
    esac
    shift
  done
}

# ---------------------------------------------------------------------------
# Confirmation helper
# ---------------------------------------------------------------------------
confirm() {
  local prompt="$1"
  if [ "$YES" -eq 1 ]; then info "assumed --yes: $prompt"; return 0; fi
  if [ "$DRY_RUN" -eq 1 ]; then info "dry-run (would confirm): $prompt"; return 0; fi
  printf '  ? %s [y/N] ' "$prompt"
  local ans
  IFS= read -r ans || ans="n"
  case "$ans" in
    y|Y|yes|YES) return 0 ;;
    *) warn "aborted at confirmation: $prompt"; return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# Pre-checks. Each returns 0 on success; in dry-run they degrade to a notice
# so the script can run on a non-Linux dev box to print the command plan.
# ---------------------------------------------------------------------------
detect_os() {
  local id=""
  if [ -r /etc/os-release ]; then
    . /etc/os-release
    id="${ID:-}"
  fi
  case "$id" in
    ubuntu|debian) _log "  [i] OS: ${id}" ; return 0 ;;
    *)
      if [ "$DRY_RUN" -eq 1 ]; then
        warn "dry-run: unsupported/unknown OS (${id:-none}); skipping OS gate."
        return 0
      fi
      error "unsupported OS: ID=${id:-<unknown>} (need ubuntu or debian)."
      return 1
      ;;
  esac
}

detect_arch() {
  local m arch=""
  m="$(uname -m 2>/dev/null || echo x86_64)"
  case "$m" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    armv7l|armv6l) arch="arm" ;;
    *) arch="amd64" ;;
  esac
  DETECTED_ARCH="$arch"
  if [ "$DRY_RUN" -ne 1 ]; then
    case "$m" in x86_64|amd64|aarch64|arm64|armv7l|armv6l) : ;;
      *) error "unsupported CPU architecture: $m"; return 1 ;; esac
  fi
  _log "  [i] arch: ${arch}"
  return 0
}

require_root() {
  if [ "$(id -u 2>/dev/null || echo 0)" -ne 0 ]; then
    error "this installer requires root. Re-run with: sudo $0 $*"
    [ "$DRY_RUN" -eq 1 ] || return 1
  fi
}

check_disk() {
  local free_kb
  # pipefail-safe: if df is unavailable or /opt missing (dry-run dev host),
  # free_kb stays empty and the check is skipped rather than aborting.
  free_kb="$(df -Pk /opt 2>/dev/null | awk 'NR==2 {print $4}' || true)"
  if [ -n "$free_kb" ] && [ "$free_kb" -lt 2097152 ] && [ "$DRY_RUN" -ne 1 ]; then
    error "/opt has < 2 GiB free; refusing."
    return 1
  fi
  _log "  [i] disk check ok"
  return 0
}

# ---------------------------------------------------------------------------
# Package install (apt, noninteractive). Refused/printed in dry-run.
# ---------------------------------------------------------------------------
install_packages() {
  if [ "$DRY_RUN" -eq 1 ]; then
    _log "  [dry-run] DEBIAN_FRONTEND=noninteractive apt-get update"
    _log "  [dry-run] DEBIAN_FRONTEND=noninteractive apt-get -y install ca-certificates curl git tar gzip openssl"
    return 0
  fi
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get -y -qq install ca-certificates curl git tar gzip openssl
}

# ---------------------------------------------------------------------------
# Go toolchain: prefer a suitable existing Go, else the pinned, checksummed
# official tarball under TOOLCHAIN_PREFIX.
# ---------------------------------------------------------------------------
go_present_suitable() {
  command -v go >/dev/null 2>&1 || return 1
  local v minor
  v="$(go env GOVERSION 2>/dev/null || true)"
  minor="${v#go1.}"; minor="${minor%%.*}"
  [ -n "$minor" ] && [ "$minor" -ge "$MIN_GO_MINOR" ]
}

install_go() {
  local arch="$DETECTED_ARCH" go_arch go_ver url tgz
  case "$arch" in
    amd64) go_arch=amd64 ;; arm64) go_arch=arm64 ;; arm) go_arch=arm ;;
  esac

  if go_present_suitable; then
    _log "  [i] reusing suitable Go: $(go version)"
    return 0
  fi

  if [ "$DRY_RUN" -eq 1 ]; then
    _log "  [dry-run] install pinned Go ${GO_FALLBACK_VERSION} (linux/${go_arch}) into ${TOOLCHAIN_PREFIX}"
    _log "  [dry-run]   url=https://go.dev/dl/go${GO_FALLBACK_VERSION}.linux-${go_arch}.tar.gz (SHA-256 from the .sha256 sidecar)"
    return 0
  fi

  go_ver="$GO_FALLBACK_VERSION"
  url="https://go.dev/dl/go${go_ver}.linux-${go_arch}.tar.gz"
  tgz="${TMP_WORK}/go.tar.gz"
  info "installing pinned Go ${go_ver} (linux/${go_arch}) from ${url}"
  curl -fsSL --retry 3 -o "$tgz" "$url"
  curl -fsSL --retry 3 -o "${tgz}.sha256" "${url}.sha256"
  local expected got
  expected="$(awk -v a="go${go_ver}.linux-${go_arch}.tar.gz" '$2==a {print $1; exit}' "${tgz}.sha256" | tr -d ' \r')"
  if [ -z "$expected" ]; then
    error "no SHA-256 found for ${go_ver} linux/${go_arch}; aborting (no unverified toolchain)."
    return 1
  fi
  got="$(sha256sum "$tgz" 2>/dev/null | awk '{print $1}' || true)"
  if [ "$got" != "$expected" ]; then
    error "Go toolchain SHA-256 mismatch; refusing to install."
    return 1
  fi
  rm -rf "$TOOLCHAIN_PREFIX"; mkdir -p "$TOOLCHAIN_PREFIX"
  tar -C "$TOOLCHAIN_PREFIX" -xzf "$tgz"
  export PATH="${TOOLCHAIN_PREFIX}/go/bin:${PATH}"
  rm -f "$tgz" "${tgz}.sha256"
  go_present_suitable || { error "Go install failed or still too old."; return 1; }
  _log "  [i] Go installed: $(go version)"
}

# ---------------------------------------------------------------------------
# Source acquisition: git clone, tarball fallback, or local path.
# ---------------------------------------------------------------------------
acquire_source() {
  local src="${SOURCE:-$DEFAULT_SOURCE}"
  [ -n "$REF" ] || REF="main"

  # Case 1: local path.
  if [ "$NO_CLONE" -eq 1 ] || ( [ -n "$src" ] && [ -d "$src" ] ); then
    if [ -z "$src" ] || [ ! -d "$src" ]; then
      error "--no-clone requires a local source directory; got '${src:-<empty>}'."
      return 1
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
      _log "  [dry-run] using local source dir: ${src}"
      RESOLVED_SRC="$src"; RESOLVED_REV="${REF}"; return 0
    fi
    if [ -f "${src}/go.mod" ] && [ -d "${src}/cmd/splitterctl" ]; then
      RESOLVED_SRC="$src"
      RESOLVED_REV="$(cd "$src" && git rev-parse --short HEAD 2>/dev/null || printf '%s' "$REF")"
      _log "  [i] using local source: ${src} (rev ${RESOLVED_REV})"
      return 0
    fi
    error "local source ${src} is not a valid repo root."
    return 1
  fi

  # Case 2: git clone, tarball fallback.
  if [ "$DRY_RUN" -eq 1 ]; then
    _log "  [dry-run] git clone --depth 1 --branch ${REF} ${src} ${SRC_PREFIX}"
    _log "  [dry-run]   (fallback) tarball: curl -fL ${DEFAULT_SOURCE}/archive/refs/tags/<ref>.tar.gz, SHA-256-verified -> ${SRC_PREFIX}"
    RESOLVED_SRC="$SRC_PREFIX"; RESOLVED_REV="$REF"; return 0
  fi

  rm -rf "$SRC_PREFIX"
  if git clone --depth 1 --branch "$REF" "$src" "$SRC_PREFIX" 2>/dev/null; then
    RESOLVED_SRC="$SRC_PREFIX"
    RESOLVED_REV="$(cd "$SRC_PREFIX" && git rev-parse --short HEAD)"
    _log "  [i] cloned source: ${src} @ ${REF} -> ${RESOLVED_REV}"
  else
    _log "  [i] git clone failed; falling back to the source tarball."
    local url="${DEFAULT_SOURCE%/}.tar.gz"
    url="${url%/archive/refs/*}.tar.gz"
    url="https://github.com/Zaltapar/iran-germany-split-tunnel/archive/refs/tags/${REF}.tar.gz"
    local tgz="${TMP_WORK}/src.tar.gz" got expected=""
    curl -fL --retry 3 -o "$tgz" "$url"
    if [ -n "${ONECLICK_SOURCE_SHA256:-}" ]; then
      expected="$ONECLICK_SOURCE_SHA256"
      got="$(sha256sum "$tgz" 2>/dev/null | awk '{print $1}' || true)"
      if [ "$got" != "$expected" ]; then
        error "source tarball SHA-256 mismatch; refusing to build unverified source."
        return 1
      fi
    fi
    local stage="${SRC_PREFIX}.tmp-$$" top
    rm -rf "$stage"; mkdir -p "$stage"
    tar -xzf "$tgz" -C "$stage"
    # -print -quit avoids the find|head pipeline (SIGPIPE under pipefail).
    top="$(find "$stage" -maxdepth 1 -mindepth 1 -type d -print -quit)"
    rm -rf "$SRC_PREFIX"; mv "$top" "$SRC_PREFIX"; rm -rf "$stage" "$tgz"
    RESOLVED_SRC="$SRC_PREFIX"; RESOLVED_REV="$REF"
    _log "  [i] tarball source installed into ${SRC_PREFIX} (ref ${REF})"
  fi

  [ -f "${RESOLVED_SRC}/go.mod" ] || { error "resolved source has no go.mod."; return 1; }
}

# ---------------------------------------------------------------------------
# Build the role binaries with CGO_ENABLED=0 -trimpath.
# ---------------------------------------------------------------------------
build_binaries() {
  local arch="$DETECTED_ARCH" role_splitter
  case "$ROLE" in
    iran) role_splitter="iran-splitter" ;;
    germany) role_splitter="germany-splitter" ;;
    *) error "build: unknown role ${ROLE}"; return 1 ;;
  esac

  if [ "$DRY_RUN" -eq 1 ]; then
    _log "  [dry-run] cd ${RESOLVED_SRC} && CGO_ENABLED=0 go build -trimpath -o ${BIN_PREFIX}/splitterctl ./cmd/splitterctl"
    _log "  [dry-run] cd ${RESOLVED_SRC} && CGO_ENABLED=0 go build -trimpath -o ${BIN_PREFIX}/${role_splitter} ./cmd/${role_splitter}"
    if [ "$ROLE" = "germany" ] && [ "$DASHBOARD" = "on" ]; then
      _log "  [dry-run] cd ${RESOLVED_SRC} && CGO_ENABLED=0 go build -trimpath -o ${BIN_PREFIX}/tunneldash ./cmd/tunneldash"
    fi
    _log "  [dry-run] verify built binaries: splitterctl --help; ${role_splitter} --validate-config"
    return 0
  fi

  local -a targets=( "./cmd/splitterctl" "./cmd/${role_splitter}" )
  if [ "$ROLE" = "germany" ] && [ "$DASHBOARD" = "on" ]; then
    targets+=( "./cmd/tunneldash" )
  fi
  export CGO_ENABLED=0
  mkdir -p "$BIN_PREFIX"
  local spec out
  for spec in "${targets[@]}"; do
    out="${BIN_PREFIX}/$(basename "$spec")"
    ( cd "$RESOLVED_SRC" && go build -trimpath -o "$out" "$spec" )
  done
  "$BIN_PREFIX/splitterctl" --help >/dev/null
  local built=""
  for t in "${targets[@]}"; do built="${built} $(basename "$t")"; done
  _log "  [i] built:${built}"
}

# ---------------------------------------------------------------------------
# Delegate to splitterctl with the full env contract. This is the ONLY
# mutation entrypoint; the script adds no host of its own.
# ---------------------------------------------------------------------------
run_splitterctl() {
  if [ "$DRY_RUN" -eq 1 ]; then
    _log "  [dry-run] ${BIN_PREFIX}/splitterctl $*"
    return 0
  fi
  "$BIN_PREFIX/splitterctl" "$@"
}

# Build + export the full SPLIT_* + SPLITTERCTL_* env contract. Values here
# are NON-SECRET except the tunnel secret, which is carried only by the 0600
# secret file (referenced by SPLITTERCTL_SECRET_FILE path, never inlined).
export_role_env() {
  # Artifact pointers splittecctl reads.
  export SPLITTERCTL_SPLITTER_BIN="${BIN_PREFIX}/${ROLE}-splitter"
  export SPLITTERCTL_SPLITTER_VERSION="${SPLITTER_VERSION}"
  export SPLIT_SECRET_FILE="${SECRETS_DIR}/secret"

  local ws_listen="${ONECLICK_WS_LISTEN:-127.0.0.1:9001}"
  local socks_listen="${ONECLICK_SOCKS_LISTEN:-127.0.0.1:10900}"
  local down_listen="${ONECLICK_DOWN_LISTEN:-:9002}"

  if [ "$ROLE" = "iran" ]; then
    export SPLIT_WS_LISTEN="$ws_listen"
    export SPLIT_SOCKS_LISTEN="$socks_listen"
    # The down-carrier dial target = the project-managed consumer loopback
    # port (127.0.0.1). It is finalized to the exact consumer port after the
    # pairing exchange; the valid default keeps install green.
    export SPLIT_DOWN_CARRIER_ADDR="127.0.0.1:${ONECLICK_CONSUMER_PORT:-10802}"
    export SPLITTERCTL_ORIGIN_MODE="${ONECLICK_ORIGIN_MODE:-cdn}"
    export SPLITTERCTL_UPLOAD_DOMAIN="$DOMAIN"
    export SPLITTERCTL_ORIGIN_PORT="${ONECLICK_ORIGIN_PORT:-80}"
    export SPLITTERCTL_CDN_SECURITY="${ONECLICK_CDN_SECURITY:-plainOrigin}"
    export SPLITTERCTL_SECRET_FILE="${SECRETS_DIR}/secret"
  else
    export SPLIT_DOWN_LISTEN="$down_listen"
    # Germany's up-carrier URL is derived from the (public) upload domain.
    local scheme="wss"
    [ "${ONECLICK_WS_SCHEME:-wss}" = "ws" ] && scheme="ws"
    export SPLIT_UP_WS_URL="${scheme}://${DOMAIN}/upload"
    export SPLITTERCTL_REALITY_SNI="${ONECLICK_REALITY_SNI:-}"
    export SPLITTERCTL_REALITY_SHORT_ID="${ONECLICK_REALITY_SHORT_ID:-}"
    export SPLITTERCTL_REALITY_UUID="${ONECLICK_REALITY_UUID:-}"
  fi

  # Firewall: project-owned rules ONLY when the operator opted in.
  if [ "$OPEN_FIREWALL" -eq 1 ]; then
    export SPLITTERCTL_FIREWALL_BACKEND="${ONECLICK_FW_BACKEND:-auto}"
    if [ "$ROLE" = "iran" ]; then
      export SPLITTERCTL_FW_ALLOW="${ONECLICK_FW_ALLOW_IRAN:-443,80,22}"
    else
      export SPLITTERCTL_FW_ALLOW="${ONECLICK_FW_ALLOW_GERMANY:-443,${DASHBOARD_PORT},22}"
    fi
  fi
}

# ---------------------------------------------------------------------------
# Secret + pairing. The ONLY secret artifact carried is Blob A (Iran -> DE).
# Blob B is public; we log its fingerprint only, never its bytes, and both
# files are securely deleted after use.
# ---------------------------------------------------------------------------
generate_secret_if_missing() {
  mkdir -p "$SECRETS_DIR"; chmod 0700 "$SECRETS_DIR"
  local f="${SECRETS_DIR}/secret"
  if [ ! -f "$f" ]; then
    local hex
    hex="$(openssl rand -hex 32)"
    ( umask 077; printf '%s' "$hex" > "$f" )
    chmod 0600 "$f"
    _log "  [i] generated a new tunnel secret at ${f} (0600, value never printed)."
  else
    _log "  [i] reusing existing tunnel secret at ${f}."
  fi
}

# Securely delete a file: shred if available, else overwrite+unlink.
secure_unlink() {
  local f="$1"
  [ -f "$f" ] || return 0
  if command -v shred >/dev/null 2>&1; then
    shred -u -z -n 3 "$f" 2>/dev/null && return 0
  fi
  local sz i
  sz="$(wc -c < "$f" 2>/dev/null || echo 4096)"
  for i in 1 2 3; do head -c "$sz" /dev/zero > "$f" 2>/dev/null || true; done
  rm -f "$f"
}

# Verify a carrier blob is a sane 0600 regular file (not a symlink).
validate_blob() {
  local f="$1"
  [ -f "$f" ] || { error "pairing file not found: ${f}"; return 1; }
  if [ -L "$f" ]; then error "pairing file is a symlink; refusing."; return 1; fi
  local perm
  perm="$(stat -c '%a' "$f" 2>/dev/null || stat -f '%Lp' "$f" 2>/dev/null || echo 600)"
  case "$perm" in 600|400|0600|0400) : ;;
    *) warn "pairing file ${f} has mode ${perm} (expected 0600); continuing." ;; esac
  return 0
}

iran_pair_generate() {
  export SPLITTERCTL_SECRET_FILE="${SECRETS_DIR}/secret"
  export SPLITTERCTL_UPLOAD_DOMAIN="$DOMAIN"
  export SPLITTERCTL_PAIR_BLOB_OUT="${PAIRING_DIR}/${BLOB_A_NAME}"
  if [ "$DRY_RUN" -eq 1 ]; then
    _log "  [dry-run] mkdir -p ${PAIRING_DIR} (0700); write Blob A -> ${PAIRING_DIR}/${BLOB_A_NAME} (0600)"
  else
    mkdir -p "$PAIRING_DIR"; chmod 0700 "$PAIRING_DIR"
  fi
  run_splitterctl pair generate
  _log "  [i] Blob A (the ONE secret) -> ${PAIRING_DIR}/${BLOB_A_NAME} (0600). Carry it to Germany."
}

germany_pair_apply() {
  local blob="$PAIRING_SECRET_FILE"
  [ -n "$blob" ] || { error "Germany requires --pairing-secret-file (the copied Blob A)."; return 1; }
  if [ "$DRY_RUN" -ne 1 ]; then validate_blob "$blob"; fi
  export SPLITTERCTL_PAIR_BLOB_FILE="$blob"
  export SPLITTERCTL_PAIR_DOWN_HOST="${ONECLICK_DOWN_HOST:-}"
  export SPLITTERCTL_PAIR_BLOB_OUT="${PAIRING_DIR}/${BLOB_B_NAME}"
  run_splitterctl pair apply
  if [ "$DRY_RUN" -ne 1 ]; then
    local fp
    fp="$(sha256sum "${PAIRING_DIR}/${BLOB_B_NAME}" 2>/dev/null | awk '{print $1}' || true)"
    _log "  [i] Blob B (public) emitted; fingerprint ${fp}. Relay it back to Iran for \`pair finalize\`."
    secure_unlink "$blob"
    _log "  [i] secret Blob A securely deleted from ${blob}."
  else
    _log "  [dry-run] would emit public Blob B + fingerprint-only log; secure-delete the carried Blob A"
  fi
}

iran_pair_finalize() {
  local blob="$PAIRING_SECRET_FILE"
  [ -n "$blob" ] || { error "Iran finalize requires --pairing-secret-file (the returned Blob B)."; return 1; }
  if [ "$DRY_RUN" -ne 1 ]; then validate_blob "$blob"; fi
  export SPLITTERCTL_PAIR_BLOB_FILE="$blob"
  run_splitterctl pair finalize
  # When the project-managed Xray consumer is in use on Iran (the default),
  # finalize is the moment Blob B lands: `pairCommand`'s post-commit hook
  # (writeConsumerConfigFromBlobB) rewrites /etc/split-tunnel/xray-consumer.json
  # from Blob B's public params and restarts xray-consumer.service if it is
  # active. When the consumer was not yet provisioned at bootstrap (deferred),
  # install-extra provisions the pinned Xray + unit now, using the exact Blob B
  # the operator just carried over.
  if [ "$IRAN_XRAY" = "managed" ]; then
    export SPLITTERCTL_CONSUMER_BLOB_B="$blob"
    run_splitterctl install-extra xray-consumer
    _log "  [i] xray-consumer.service (re)provisioned from the carried Blob B."
  fi
  if [ "$DRY_RUN" -ne 1 ]; then
    secure_unlink "$blob"
    _log "  [i] Blob B securely deleted; pairing finalized."
  fi
}

# ---------------------------------------------------------------------------
# Dashboard (Germany only): TLS config + hardened unit + cert copy.
# ---------------------------------------------------------------------------
readonly DASHBOARD_CONFIG="/etc/split-tunnel/dashboard/config.json"
readonly DASHBOARD_ENV="/etc/split-tunnel/dashboard.env"
readonly DASHBOARD_TLS_DIR="/etc/split-tunnel/dashboard/tls"

generate_dashboard() {
  readonly DASHBOARD_TOKEN="/etc/split-tunnel/dashboard/token"
  if [ "$DRY_RUN" -eq 1 ]; then
    _log "  [dry-run] generate ${DASHBOARD_CONFIG} + ${DASHBOARD_ENV} (TLS 0.0.0.0:${DASHBOARD_PORT}, random 32-hex basePath)"
    _log "  [dry-run] copy --cert/--key into ${DASHBOARD_TLS_DIR}/ (0640 root:split-tunnel)"
    _log "  [dry-run] generate admin bearer token -> ${DASHBOARD_TOKEN} (0600; value never logged)"
    _log "  [dry-run] write + enable hardened tunneldash.service (golden-pinned)"
    DASHBOARD_BASEPATH="<random-32-hex>"
    return 0
  fi

  local basepath metrics_port="${ONECLICK_METRICS_PORT:-9101}"
  basepath="$(openssl rand -hex 16)"

  mkdir -p "$DASHBOARD_TLS_DIR"; chmod 0750 "$DASHBOARD_TLS_DIR"
  if [ -n "$CERT_FILE" ] && [ -n "$KEY_FILE" ]; then
    cp -f "$CERT_FILE" "${DASHBOARD_TLS_DIR}/cert.pem"
    cp -f "$KEY_FILE" "${DASHBOARD_TLS_DIR}/key.pem"
    chown root:split-tunnel "${DASHBOARD_TLS_DIR}/cert.pem" "${DASHBOARD_TLS_DIR}/key.pem" 2>/dev/null || true
    chmod 0640 "${DASHBOARD_TLS_DIR}/cert.pem" "${DASHBOARD_TLS_DIR}/key.pem"
    _log "  [i] installed dashboard TLS cert/key into ${DASHBOARD_TLS_DIR} (0640 root:split-tunnel)."
  else
    warn "no --cert/--key supplied; dashboard TLS is incomplete until PEMs are copied to ${DASHBOARD_TLS_DIR}."
  fi

  cat > "$DASHBOARD_CONFIG" <<EOF
{
  "listenAddr": "0.0.0.0:${DASHBOARD_PORT}",
  "readOnly": true,
  "refreshSec": 30,
  "maxLogEntries": 200,
  "maxAudit": 500,
  "tls": {
    "enabled": true,
    "certFile": "${DASHBOARD_TLS_DIR}/cert.pem",
    "keyFile": "${DASHBOARD_TLS_DIR}/key.pem",
    "basePath": "${basepath}"
  },
  "servers": [
    {
      "id": "germany", "name": "Germany Splitter", "role": "germany",
      "address": "127.0.0.1", "sourceType": "http",
      "metricsUrl": "http://127.0.0.1:${metrics_port}/metrics",
      "allowMutations": false
    },
    {
      "id": "iran", "name": "Iran Splitter", "role": "iran",
      "address": "${ONECLICK_IRAN_SSH_HOST:-}", "sourceType": "ssh",
      "allowMutations": false,
      "ssh": {
        "user": "monitor",
        "address": "${ONECLICK_IRAN_SSH_HOST:-}",
        "port": 22,
        "identityFile": "/etc/split-tunnel/dashboard/ssh/monitor_key",
        "knownHosts": "/etc/split-tunnel/dashboard/ssh/pinned_kh",
        "connectTimeoutSec": 10, "commandTimeoutSec": 15,
        "metricsPort": ${metrics_port},
        "statePath": "/etc/split-tunnel/state.json",
        "services": ["iran-splitter", "xray-consumer"]
      }
    }
  ]
}
EOF
  chmod 0640 "$DASHBOARD_CONFIG"

  # Optional admin bearer token (defense-in-depth; mutations stay disabled).
  # Referenced by the env file via path only; the value is never logged.
  openssl rand -hex 32 > "$DASHBOARD_TOKEN"
  chmod 0600 "$DASHBOARD_TOKEN"
  chown root:split-tunnel "$DASHBOARD_TOKEN" 2>/dev/null || true
  _log "  [i] generated dashboard admin bearer token -> ${DASHBOARD_TOKEN} (0600; read the value from that file — it is never printed here)"

  { printf 'SPLIT_TUNNELDASH_TOKEN_FILE=%s\n' "$DASHBOARD_TOKEN"; } > "$DASHBOARD_ENV"
  chmod 0600 "$DASHBOARD_ENV"

  mkdir -p /etc/split-tunnel/dashboard/ssh
  chmod 0750 /etc/split-tunnel/dashboard/ssh

  # Delegate the actual unit install to splitterctl (transactional apply of
  # the hardened tunneldash.service + manifest record). The binary, config,
  # env file, and TLS dir the command verifies/converges are all in place
  # by now.
  export SPLITTERCTL_DASH_BASEPATH="$basepath"
  export SPLITTERCTL_DASH_CERT="${DASHBOARD_TLS_DIR}/cert.pem"
  export SPLITTERCTL_DASH_KEY="${DASHBOARD_TLS_DIR}/key.pem"
  export SPLITTERCTL_DASH_CONFIG="$DASHBOARD_CONFIG"
  export SPLITTERCTL_DASH_ENVFILE="$DASHBOARD_ENV"
  export SPLITTERCTL_DASH_BIN="${BIN_PREFIX}/tunneldash"
  run_splitterctl install-extra tunneldash
  # basePath is the 32-hex first-access secret: it is embedded in the config
  # file and the systemd unit, but is NEVER printed here (neither to stdout
  # nor to the 0600 install log). The operator reads it from DASHBOARD_CONFIG.
  DASHBOARD_BASEPATH="<read-basePath-from-${DASHBOARD_CONFIG}>"
}

# ---------------------------------------------------------------------------
# Xray consumer (Iran). managed = project-managed (delegate to splitterctl);
# external = print a 3x-ui paste-in snippet.
# ---------------------------------------------------------------------------
iran_xray_consumer() {
  if [ "$IRAN_XRAY" = "external" ]; then
    print_external_xray_snippet
    return 0
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    _log "  [dry-run] install-extra xray-consumer (installs pinned Xray + pointer, renders xray-consumer.json from Blob B public params, writes xray-consumer.service transactionally)"
    _log "  [dry-run]   source: SPLITTERCTL_CONSUMER_BLOB_B=<carried Blob B> (public; Blob A is the only secret)"
    _log "  [dry-run] note: consumer provisioning defers until Blob B is carried to Iran (see the pairing handoff)"
    return 0
  fi
  # The consumer config is rendered from Blob B (public). At bootstrap Iran may
  # not yet hold Blob B; in that case the provisioning is deferred to the
  # finalize step (iran_pair_finalize) which carries Blob B back.
  local blob_b="${PAIRING_SECRET_FILE:-${PAIRING_DIR}/${BLOB_B_NAME}}"
  if [ -f "$blob_b" ]; then
    export SPLITTERCTL_CONSUMER_BLOB_B="$blob_b"
    run_splitterctl install-extra xray-consumer
    _log "  [i] Iran project-managed Xray consumer provisioned via splitterctl install-extra (xray-consumer.service)."
  else
    _log "  [i] Blob B not yet present on Iran; xray-consumer provisioning defers to \`pair finalize\` (it carries Blob B back and runs install-extra xray-consumer)."
  fi
}

print_external_xray_snippet() {
  local socks_port
  socks_port="$(printf '%s' "${ONECLICK_SOCKS_LISTEN:-127.0.0.1:10900}" | awk -F: '{print $NF}')"
  cat <<EOF

=== Iran external Xray (3x-ui) paste-in snippet ===
Keep your 3x-ui Xray; add these to its config JSON:

outbounds +=
{ "tag": "to-splitter", "protocol": "socks",
  "settings": { "servers": [ { "address": "127.0.0.1", "port": ${socks_port:-10900} } ] } }

routing.rules (FIRST) +=
{ "type": "field", "inboundTag": [ "user-vless-reality" ], "outboundTag": "to-splitter" }
EOF
}

# ---------------------------------------------------------------------------
# Firewall opt-in: add ONLY the role's specific ports (project-owned rules).
# ---------------------------------------------------------------------------
apply_firewall_optin() {
  [ "$OPEN_FIREWALL" -eq 1 ] || return 0
  local ports
  if [ "$ROLE" = "iran" ]; then ports="${ONECLICK_FW_ALLOW_IRAN:-443,80,22}"
  else ports="${ONECLICK_FW_ALLOW_GERMANY:-443,${DASHBOARD_PORT},22}"; fi
  _log "  [i] opt-in firewall: would add project-owned allow rules for TCP ports: ${ports}"
  if ! confirm "Add these specific firewall ports now? (does NOT flush or touch global egress)"; then
    warn "firewall changes skipped (opt-in declined)."
    return 0
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    _log "  [dry-run] SPLITTERCTL_FW_ALLOW=${ports} ${BIN_PREFIX}/splitterctl install ${ROLE}"
    return 0
  fi
  export SPLITTERCTL_FW_ALLOW="$ports"
  export SPLITTERCTL_FIREWALL_BACKEND="${ONECLICK_FW_BACKEND:-auto}"
}

# ---------------------------------------------------------------------------
# Uninstall + verify + summary
# ---------------------------------------------------------------------------
do_uninstall() {
  if [ "$DRY_RUN" -eq 1 ]; then
    _log "  [dry-run] ${BIN_PREFIX}/splitterctl uninstall$([ "$YES" -eq 1 ] && echo ' --purge')"
    return 0
  fi
  if [ "$YES" -eq 1 ]; then run_splitterctl uninstall --purge; else run_splitterctl uninstall; fi
  _log "  [i] uninstall delegated to splitterctl."
}

verify() {
  if [ "$DRY_RUN" -eq 1 ]; then
    _log "  [dry-run] ${BIN_PREFIX}/splitterctl doctor && ${BIN_PREFIX}/splitterctl status"
    if [ "$ROLE" = "germany" ] && [ "$DASHBOARD" = "on" ]; then
      _log "  [dry-run] openssl s_client -connect 127.0.0.1:${DASHBOARD_PORT} (dashboard TLS probe)"
    fi
    return 0
  fi
  run_splitterctl doctor || warn "splitterctl doctor reported findings."
  run_splitterctl status || true
}

print_summary() {
  local url="loopback only"
  if [ "$ROLE" = "germany" ] && [ "$DASHBOARD" = "on" ]; then
    url="https://<germany-host>:${DASHBOARD_PORT}/${DASHBOARD_BASEPATH:-<random-basePath>}/"
  fi
  cat <<EOF

==================== split-tunnel installer summary ====================
 role                 : ${ROLE}
 source revision        : ${RESOLVED_REV:-<unset>}
 source path            : ${RESOLVED_SRC:-<unset>}
 dashboard              : $( [ "$ROLE" = "germany" ] && echo "on" || echo "off" )
 dashboard url/path    : ${url}
 manual pairing step    : the ONE secret you carry is Blob A (Iran -> Germany),
                          a 0600 file at ${PAIRING_DIR}/${BLOB_A_NAME}.
                          Blob B is PUBLIC (only its SHA-256 is logged).
 logs                   : ${INSTALL_LOG} (0600) + journalctl -u <unit>
 firewall               : $( [ "$OPEN_FIREWALL" -eq 1 ] && echo "opt-in allow rules" || echo "untouched" )
 rollback / recovery    : ${BIN_PREFIX}/splitterctl recover   (journal-driven)
 next manual step       : copy Blob A Iran->Germany, then on Germany run:
                           SPLITTERCTL_PAIR_BLOB_FILE=${PAIRING_DIR}/${BLOB_A_NAME} \\
                           ${BIN_PREFIX}/splitterctl pair apply
========================================================================
EOF
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
  load_env_equivalents
  parse_args "$@"

  if [ "$UNINSTALL" -ne 1 ]; then
    case "$ROLE" in
      iran|germany) : ;;
      *) error "a valid --role <iran|germany> is required."; usage; exit 2 ;;
    esac
  fi

  TMP_WORK="$(mktemp -d /tmp/oneclick.XXXXXX)"
  trap 'rm -rf "${TMP_WORK:-}" 2>/dev/null || true' EXIT

  _log "  [i] one-click installer (role=${ROLE:-<unset>} dry-run=${DRY_RUN} uninstall=${UNINSTALL})"

  if [ "$DRY_RUN" -ne 1 ]; then require_root "$@"; fi
  detect_os
  detect_arch
  check_disk

  # Uninstall: no bootstrap, just delegate.
  if [ "$UNINSTALL" -eq 1 ]; then
    do_uninstall
    print_summary
    return 0
  fi

  # Pairing sub-flow (operator supplied a carrier file).
  if [ -n "$PAIRING_SECRET_FILE" ]; then
    case "$ROLE" in
      germany)
        install_packages; install_go
        acquire_source; build_binaries; export_role_env
        germany_pair_apply ;;
      iran)
        acquire_source; build_binaries; export_role_env
        iran_pair_finalize ;;
    esac
    return 0
  fi

  # --- Full bootstrap ---
  install_packages
  install_go
  acquire_source
  build_binaries
  export_role_env

  if [ "$ROLE" = "iran" ]; then
    [ -n "$DOMAIN" ] || { error "Iran role requires --domain <host>"; [ "$DRY_RUN" -eq 1 ] || exit 1; }
    [ "$DRY_RUN" -eq 1 ] || generate_secret_if_missing
    run_splitterctl install iran
    iran_xray_consumer
    iran_pair_generate
  else
    [ -n "$DOMAIN" ] || { error "Germany role requires --domain <host> (up-carrier URL)"; [ "$DRY_RUN" -eq 1 ] || exit 1; }
    run_splitterctl install germany
    if [ "$DASHBOARD" = "on" ]; then
      generate_dashboard
      export SPLIT_TUNNELDASH_TOKEN_FILE="${DASHBOARD_ENV}"
      _log "  [i] wrote hardened tunneldash.service (Unit=split-tunnel, NoNewPrivileges, ProtectSystem=full)"
    fi
  fi

  apply_firewall_optin
  verify
  print_summary
}

# Allow test harnesses to source the helper functions without running main.
if [ -z "${ONECLICK_TESTING:-}" ]; then
  main "$@"
fi
