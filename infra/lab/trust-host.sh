#!/usr/bin/env bash
# First contact with a new lab VM, done explicitly.
#
#   infra/lab/trust-host.sh            trust the inventory host on first contact
#   infra/lab/trust-host.sh --forget   drop its key (the VM was destroyed)
#
# SSH host-key checking stays on for every connection (ansible.cfg,
# lib.sh). A brand-new VM has a key nobody has seen, and Proxmox's native
# cloud-init cannot inject one, so the first key is accepted once, here:
# trust on first use, written to the lab's own known_hosts
# ($LAB_STATE/known_hosts), never to ~/.ssh/known_hosts. If the host already
# has an entry, nothing is accepted: a different key later fails loudly.
#
# To check the key out of band, compare the fingerprint printed below with
# the one cloud-init writes to the VM's serial console (Proxmox UI >
# netsoldier-soc > Console, lines "BEGIN SSH HOST KEY FINGERPRINTS").
set -euo pipefail
# shellcheck source=infra/lab/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

read -r _user host port < <(lab_target)
entry=$host
[[ $port == 22 ]] || entry="[$host]:$port"

mkdir -p "$LAB_STATE"
touch "$LAB_KNOWN_HOSTS"
chmod 600 "$LAB_KNOWN_HOSTS"

if [[ ${1:-} == --forget ]]; then
  ssh-keygen -R "$entry" -f "$LAB_KNOWN_HOSTS" >/dev/null 2>&1 || true
  rm -f "$LAB_KNOWN_HOSTS.old"
  echo "forgot the host key of $entry"
  exit 0
fi

if ssh-keygen -F "$entry" -f "$LAB_KNOWN_HOSTS" >/dev/null; then
  echo "host key of $entry already trusted ($LAB_KNOWN_HOSTS)"
  exit 0
fi

echo "waiting for SSH on $entry ..."
keys=""
for _ in $(seq 1 60); do
  keys=$(ssh-keyscan -T 5 -t ed25519 -p "$port" "$host" 2>/dev/null | grep -v '^#' || true)
  [[ -n $keys ]] && break
  sleep 5
done
[[ -n $keys ]] || lab_die "no SSH host key from $entry after 5 minutes"

printf '%s\n' "$keys" >>"$LAB_KNOWN_HOSTS"
echo "trusted on first contact: $entry"
ssh-keygen -lf <(printf '%s\n' "$keys")
