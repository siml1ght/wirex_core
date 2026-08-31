#!/usr/bin/env bash
#
# Reprints the Hydra-Tunnel subscription share link from the installed
# systemd unit. Run as root on the server after deploy/install.sh.
#
set -euo pipefail

UNIT="/etc/systemd/system/hydra-server.service"
[[ -r "$UNIT" ]] || { echo "unit not found: $UNIT" >&2; exit 1; }

exec_line="$(grep -oP '^ExecStart=\K.*' "$UNIT")"

get_val() {
  local key="$1"
  echo "$exec_line" | grep -oP "(?<=--${key} )[0-9a-f]+" | head -n1
}

SECRET_KEY="$(get_val secret)"
DNS_PORT="$(get_val port)"
HOP_BASE="$(get_val hop-base)"
HOP_RANGE="$(get_val hop-range)"

[[ -n "$SECRET_KEY" && -n "$DNS_PORT" && -n "$HOP_BASE" && -n "$HOP_RANGE" ]] || {
  echo "could not parse ExecStart of $UNIT" >&2
  exit 1
}
HOP_END=$((HOP_BASE + HOP_RANGE - 1))

PUBLIC_IP="$(curl -4s --max-time 5 ifconfig.me 2>/dev/null || true)"
[[ -z "$PUBLIC_IP" ]] && PUBLIC_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[[ -z "$PUBLIC_IP" ]] && PUBLIC_IP="<server-ip>"

echo "hydra://${PUBLIC_IP}:${DNS_PORT}?secret_key=${SECRET_KEY}&session_id=<unique-per-user>&hop_base=${HOP_BASE}&hop_range=${HOP_RANGE}&relay_port=16335"
echo
echo "hopping range: ${HOP_BASE}..${HOP_END}/udp"
echo "give every subscriber a unique session_id so flows never mix."
