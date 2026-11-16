#!/usr/bin/env bash
# Fails unless the host carries nothing of the lite profile: no units,
# containers, networks, volumes, secrets, files or runtime state. Images are
# reported, not required to be gone (lite.sh uninstall keeps the lab's).
set -uo pipefail

left=()
check() { # check WHAT OUTPUT
  [[ -z $2 ]] || left+=("$1: $(tr '\n' ' ' <<<"$2")")
}
check units "$(systemctl list-units --all --plain --no-legend 'netsoldier*' | awk '{print $1}')"
check unit-files "$(ls -d /etc/containers/systemd/netsoldier-* /etc/systemd/system/netsoldier.target 2>/dev/null)"
check containers "$(podman ps -a --format '{{.Names}}' | grep '^netsoldier-')"
check networks "$(podman network ls --format '{{.Name}}' | grep '^netsoldier-')"
check volumes "$(podman volume ls --format '{{.Name}}' | grep '^netsoldier-')"
check secrets "$(podman secret ls --format '{{.Name}}' | grep '^netsoldier-')"
check files "$(ls -d /etc/netsoldier /run/netsoldier /etc/tmpfiles.d/netsoldier.conf /usr/local/sbin/netsoldier-lite /usr/local/share/netsoldier-lite 2>/dev/null)"
check bridges "$(ip -br link | awk '$1 ~ /^podman[0-9]+$/ {print $1}')"
check nft "$(nft list table inet netavark 2>/dev/null | grep -E '10\.231\.47|netsoldier')"
# With no container running, any port-forwarding rule is left over (it
# would shadow the next install's published ports).
if [[ -z $(podman ps -q) ]]; then
  check stale-dnat "$(nft list table inet netavark 2>/dev/null | grep 'dnat ip to')"
fi

echo "images kept: $(podman images --format '{{.Repository}}:{{.Tag}}' | grep -E 'netsoldier|adguard' | tr '\n' ' ')"
if ((${#left[@]})); then
  printf 'NOT CLEAN: %s\n' "${left[@]}"
  exit 1
fi
echo "clean: no netsoldier unit, container, network, volume, secret, file or bridge on $(hostname)"
