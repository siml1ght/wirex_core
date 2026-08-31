#!/usr/bin/env bash
#
# Hydra-Tunnel server one-click installer for Debian 11+/Ubuntu 20.04+ (amd64).
# - checks root, architecture and distro
# - installs Go if missing/too old
# - clones the repo (or uses the local checkout when run from it)
# - builds hydra-server into /usr/local/bin
# - firewall: ufw if present, otherwise prints the exact rules to add
# - creates a hardened systemd service under a dedicated non-root user
#   (CAP_NET_BIND_SERVICE for UDP :53, everything else unprivileged)
# - prints and saves the subscription share link
#
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/siml1ght/wirex_core.git}"
INSTALL_DIR="${INSTALL_DIR:-/opt/hydra-tunnel}"
GO_VERSION="${GO_VERSION:-1.25.1}"
SERVICE_NAME="hydra-server"
SERVICE_USER="hydra"
HOP_BASE="${HOP_BASE:-44000}"
HOP_RANGE="${HOP_RANGE:-10}"
RELAY_PORT="${RELAY_PORT:-16335}"

log()  { printf '\n\033[1;36m[hydra]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[hydra]\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m[hydra] FATAL:\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- environment

[[ "$(id -u)" -eq 0 ]] || die "run as root: sudo ./install.sh"

[[ "$(uname -m)" == "x86_64" ]] || die "unsupported architecture: $(uname -m) (amd64 only)"

if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  case "${ID:-}" in
    debian|ubuntu) log "distro: ${PRETTY_NAME:-$ID}" ;;
    *) warn "untested distro '${ID:-unknown}' — proceeding, systemd + glibc required" ;;
  esac
fi

if ! command -v git >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
  log "installing base packages (git, curl)"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq git curl ca-certificates
fi

log "environment ok: $(uname -srm)"

# ---------------------------------------------------------------- go toolchain

go_major_min=1
go_minor_min=25

go_ok() {
  command -v go >/dev/null 2>&1 || return 1
  local v
  v="$(go env GOVERSION 2>/dev/null | sed 's/^go//')" || return 1
  local major minor
  major="${v%%.*}"
  minor="${v#*.}"
  minor="${minor%%.*}"
  [[ "${major:-0}" -gt "$go_major_min" ]] ||
    { [[ "$major" -eq "$go_major_min" ]] && [[ "${minor:-0}" -ge "$go_minor_min" ]]; }
}

install_go() {
  log "installing Go ${GO_VERSION} -> /usr/local/go"
  local url="https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
  local tmp="/tmp/go${GO_VERSION}.linux-amd64.tar.gz"
  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 3 -o "$tmp" "$url" || die "go download failed: $url"
  else
    wget -q -O "$tmp" "$url" || die "go download failed: $url"
  fi
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "$tmp"
  rm -f "$tmp"
  ln -sf /usr/local/go/bin/go /usr/local/bin/go
  ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
  go version
}

if go_ok; then
  log "Go already present: $(go version)"
else
  install_go
fi
export PATH="/usr/local/go/bin:$PATH"

# ---------------------------------------------------------------- sources

if [[ -f "${PWD}/go.mod" && -d "${PWD}/cmd/server" ]]; then
  log "building from the local checkout: ${PWD}"
  SRC_DIR="${PWD}"
else
  if [[ -d "${INSTALL_DIR}/.git" ]]; then
    log "updating existing clone: ${INSTALL_DIR}"
    git -C "${INSTALL_DIR}" pull --ff-only || warn "pull failed, building the current tree as-is"
  else
    log "cloning ${REPO_URL} -> ${INSTALL_DIR}"
    git clone --depth 1 "${REPO_URL}" "${INSTALL_DIR}"
  fi
  SRC_DIR="${INSTALL_DIR}"
fi

# ---------------------------------------------------------------- build

log "building hydra-server (linux/amd64, cgo off)"
( cd "${SRC_DIR}" && \
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags "-s -w" -o /usr/local/bin/hydra-server ./cmd/server )
chmod 0755 /usr/local/bin/hydra-server

# ---------------------------------------------------------------- secret

SECRET_KEY="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
[[ "$SECRET_KEY" =~ ^[0-9a-f]{64}$ ]] || die "secret generation failed"
SESSION_ID=0
while [[ "$SESSION_ID" -eq 0 ]]; do
  SESSION_ID="$(printf '%d' 0x"$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')" 2>/dev/null || echo 0)"
done
[[ "$SESSION_ID" =~ ^[0-9]+$ ]] || die "session id generation failed"

# ---------------------------------------------------------------- service user

if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
  log "creating system user: ${SERVICE_USER}"
  useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
fi

# ---------------------------------------------------------------- port 53

DNS_PORT=53
port53_busy() {
  command -v ss >/dev/null 2>&1 && ss -uln 2>/dev/null | awk '{print $5}' | grep -qE ':53$'
}

if port53_busy; then
  if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    log "port 53 is held by systemd-resolved stub — disabling DNSStubListener"
    mkdir -p /etc/systemd/resolved.conf.d
    printf '[Resolve]\nDNSStubListener=no\n' > /etc/systemd/resolved.conf.d/hydra-no-stub.conf
    systemctl restart systemd-resolved
    sleep 1
  fi
  if port53_busy; then
    DNS_PORT=30053
    warn "port 53 is still busy — falling back to base port ${DNS_PORT}"
    warn "use ${DNS_PORT} as Base Port in the GUI (STUN becomes $((DNS_PORT + 3425)))"
  fi
fi

# ---------------------------------------------------------------- firewall

HOP_END=$((HOP_BASE + HOP_RANGE - 1))

if command -v ufw >/dev/null 2>&1; then
  log "configuring ufw: 53/udp, 3478/udp, ${HOP_BASE}:${HOP_END}/udp"
  ufw allow "${HOP_BASE}:${HOP_END}/udp" >/dev/null || true
  ufw allow 53/udp  >/dev/null || true
  ufw allow 3478/udp >/dev/null || true
else
  warn "ufw not found (common on Debian). If you use nftables/iptables, allow:"
  warn "  nft add rule inet filter input udp dport { 53, 3478, ${HOP_BASE}-${HOP_END} } accept"
  warn "and check the firewall of your VPS provider panel as well."
fi

# ---------------------------------------------------------------- systemd

log "writing systemd unit: /etc/systemd/system/${SERVICE_NAME}.service"

# no --session here on purpose: the server accepts any session id of key holders;
# subscribers are separated by their unique client-side session_id
EXEC_ARGS="--secret ${SECRET_KEY} --port ${DNS_PORT} --hop-base ${HOP_BASE} --hop-range ${HOP_RANGE}"

cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Hydra-Tunnel Server (Wire-X protocol)
After=network.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ExecStart=/usr/local/bin/${SERVICE_NAME} ${EXEC_ARGS}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}" >/dev/null 2>&1 || true
sleep 1
systemctl is-active --quiet "${SERVICE_NAME}" || {
  journalctl -u "${SERVICE_NAME}" -n 12 --no-pager >&2 || true
  die "service failed to start"
}

# ---------------------------------------------------------------- subscription link

PUBLIC_IP="$(curl -4s --max-time 5 ifconfig.me 2>/dev/null || true)"
[[ -z "$PUBLIC_IP" ]] && PUBLIC_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[[ -z "$PUBLIC_IP" ]] && PUBLIC_IP="<server-ip>"

SHARE_LINK="hydra://${PUBLIC_IP}:${DNS_PORT}?secret_key=${SECRET_KEY}&session_id=${SESSION_ID}&hop_base=${HOP_BASE}&hop_range=${HOP_RANGE}&relay_port=${RELAY_PORT}"

cat > /root/hydra-sub.txt <<EOF
# Hydra-Tunnel subscription entry (generated by install.sh)
# paste this link into NekoBox: Add Profile -> Import from clipboard,
# or put the base64 of this file behind an HTTPS URL for subscriptions.
${SHARE_LINK}

# For a v2ray-style subscription feed:
#   base64 -w0 /root/hydra-sub.txt > /var/www/html/sub.txt   (serve over HTTPS!)
# Rotate: edit --secret in /etc/systemd/system/${SERVICE_NAME}.service,
#   systemctl daemon-reload && systemctl restart ${SERVICE_NAME}, then update the feed.
EOF
chmod 0600 /root/hydra-sub.txt

# ---------------------------------------------------------------- summary

HOP_END=$((HOP_BASE + HOP_RANGE - 1))

printf '\n'
printf '\033[1;32m'
printf ' ============================================================\n'
printf '   Hydra-Tunnel server is up and running\n'
printf ' ============================================================\n'
printf '\033[0m'
printf '   Server IP     : %s\n' "$PUBLIC_IP"
printf '   Base Port     : %s\n' "$DNS_PORT"
printf '   Secret Key    : %s\n' "$SECRET_KEY"
printf '   Session ID    : %s\n' "$SESSION_ID"
printf '   Hopping       : %s..%s/udp\n' "$HOP_BASE" "$HOP_END"
printf '   Service user  : %s (CAP_NET_BIND_SERVICE only)\n' "$SERVICE_USER"
printf '   Service       : systemctl status %s\n' "$SERVICE_NAME"
printf '\n'
printf '   Share link    :\n'
printf '   %s\n' "$SHARE_LINK"
printf '\n'
printf '   Sub file      : /root/hydra-sub.txt (chmod 0600)\n'
printf '   Logs          : journalctl -u %s -f\n' "$SERVICE_NAME"
printf '   Verbose       : add --verbose to ExecStart, then daemon-reload + restart\n'
printf ' ============================================================\n'
