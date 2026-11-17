#!/usr/bin/env bash
# Shared settings for the lab scripts (sourced, not run).
#
# Every location can be overridden from the environment. Nothing here
# depends on a particular home directory.

LAB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd "$LAB_DIR/../.." && pwd)

# Credentials and the Proxmox CA (written by the owner, read-only here).
LAB_CONFIG=${LAB_CONFIG:-${XDG_CONFIG_HOME:-$HOME/.config}/netsoldier-lab}
# Terraform state, the generated inventory and the lab's known_hosts.
LAB_STATE=${LAB_STATE:-${XDG_STATE_HOME:-$HOME/.local/state}/netsoldier-lab}
# Provider plugin cache.
LAB_CACHE=${LAB_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/netsoldier-lab}
LAB_KUBECONFIG=${LAB_KUBECONFIG:-$LAB_CONFIG/kubeconfig}
LAB_SSH_KEY=${LAB_SSH_KEY:-$HOME/.ssh/id_ed25519}
LAB_VENV=${LAB_VENV:-$REPO_DIR/.venv}

LAB_INVENTORY=$LAB_STATE/inventory.yml
LAB_KNOWN_HOSTS=$LAB_STATE/known_hosts
# Extra ssh options for this workstation's network, appended to every ssh
# the lab scripts run (lab_ssh and Ansible), e.g. LAB_SSH_EXTRA_OPTS="-o
# IPQoS=none" where a network drops OpenSSH's default DSCP marking. Split on
# whitespace; empty by default.
LAB_SSH_EXTRA_OPTS=${LAB_SSH_EXTRA_OPTS:-}

# Optional build host. With LAB_BUILD_HOST (an ssh destination) set, images.sh
# builds the lab images there instead of on this machine, pushes them to a
# registry on that host and has the lab node pull from it; this machine only
# copies the checkout over. LAB_BUILD_REGISTRY is that registry as the lab
# node reaches it (host:port). It is spoken to over plain HTTP: a lab
# convenience on a trusted segment, not a way to ship images.
LAB_BUILD_HOST=${LAB_BUILD_HOST:-}
LAB_BUILD_REGISTRY=${LAB_BUILD_REGISTRY:-}
LAB_BUILD_KNOWN_HOSTS=${LAB_BUILD_KNOWN_HOSTS:-$LAB_CONFIG/known_hosts_build}

lab_die() {
  echo "error: $*" >&2
  exit 1
}

# lab_build_ssh_opts: prints the ssh options for the build host, one per line
# (the host key must already be in $LAB_BUILD_KNOWN_HOSTS).
lab_build_ssh_opts() {
  local -a extra
  read -ra extra <<<"$LAB_SSH_EXTRA_OPTS"
  printf '%s\n' -i "$LAB_SSH_KEY" -o IdentitiesOnly=yes \
    -o "UserKnownHostsFile=$LAB_BUILD_KNOWN_HOSTS" -o StrictHostKeyChecking=yes \
    -o BatchMode=yes -o ConnectTimeout=10 "${extra[@]}"
}

# lab_build_ssh ARGS...: ssh to the build host.
lab_build_ssh() {
  local -a opts
  mapfile -t opts < <(lab_build_ssh_opts)
  # The command is meant to be expanded here, like lab_ssh's.
  # shellcheck disable=SC2029
  ssh "${opts[@]}" "$LAB_BUILD_HOST" "$@"
}

# lab_target: prints "user host port" of the single lab host in the
# generated inventory.
lab_target() {
  [[ -s $LAB_INVENTORY ]] || lab_die "no inventory at $LAB_INVENTORY (run: task lab:inventory)"
  # ansible-inventory costs about a second of CPU and the scripts ssh dozens
  # of times: its answer is kept until the inventory file changes.
  local cache=$LAB_STATE/.target target
  if [[ -s $cache && $cache -nt $LAB_INVENTORY ]]; then
    cat "$cache"
    return
  fi
  target=$("$LAB_VENV/bin/ansible-inventory" -i "$LAB_INVENTORY" --list 2>/dev/null |
    jq -er '._meta.hostvars | to_entries
            | if length == 1 then .[0].value else error("expected exactly one lab host") end
            | "\(.ansible_user) \(.ansible_host) \(.ansible_port // 22)"') ||
    lab_die "the inventory does not hold exactly one lab host (is the VM up?)"
  printf '%s\n' "$target" >"$cache.$$" && mv "$cache.$$" "$cache"
  printf '%s\n' "$target"
}

# lab_ssh ARGS...: ssh to the lab host, trusting only the lab's known_hosts.
# Calls share one multiplexed connection (kept for a minute): the deploy and
# scenario scripts make dozens of short calls.
lab_ssh() {
  local user host port
  local -a extra
  read -r user host port < <(lab_target)
  read -ra extra <<<"$LAB_SSH_EXTRA_OPTS"
  mkdir -p "$LAB_STATE"
  ssh -i "$LAB_SSH_KEY" -o IdentitiesOnly=yes \
    -o UserKnownHostsFile="$LAB_KNOWN_HOSTS" -o StrictHostKeyChecking=yes \
    -o BatchMode=yes -o ConnectTimeout=10 \
    -o ControlMaster=auto -o ControlPersist=60s -o ControlPath="${XDG_RUNTIME_DIR:-$LAB_STATE}/nslab-%C" \
    "${extra[@]}" -p "$port" "$user@$host" "$@"
}
