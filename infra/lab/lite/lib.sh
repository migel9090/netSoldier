#!/usr/bin/env bash
# Shared settings for the lite lab scripts (sourced, not run). Every
# location can be overridden from the environment.

LITE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd "$LITE_DIR/../../.." && pwd)

# The lab host: an unprivileged Debian 13 LXC container with Podman 5. There
# is no default: these scripts install and remove things there as root, so
# the address has to be stated, not guessed.
: "${LITE_HOST:?set LITE_HOST to the address of the lite lab host}"
LITE_USER=${LITE_USER:-root}
LITE_SSH_KEY=${LITE_SSH_KEY:-$HOME/.ssh/claude_homelab_ed25519}
# Where the repository copy and the lab helpers live on the host.
LITE_SRC=${LITE_SRC:-/opt/netsoldier/src}
LITE_TAG=${LITE_TAG:-lab}

# IPQoS=none: ssh marks its packets as high priority (DSCP EF) by default.
# A Wi-Fi adapter on the way to the lab lost exactly those and nothing else,
# which looks like a host that is down. A lab script gains nothing from the
# marking.
LITE_SSH_OPTS=(-i "$LITE_SSH_KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=10 -o IPQoS=none)

lite_die() {
  echo "error: $*" >&2
  exit 1
}

# lite_ssh ARGS...: run a command on the lab host.
lite_ssh() {
  ssh "${LITE_SSH_OPTS[@]}" "$LITE_USER@$LITE_HOST" "$@"
}

# lite_sync: copy the working tree (not .git, not build output) to the host.
lite_sync() {
  local rev ignored
  rev=$(git -C "$REPO_DIR" rev-parse --short HEAD)
  git -C "$REPO_DIR" diff --quiet HEAD || rev+=-dirty
  # Only what git would commit goes to the host. Ignored files are where
  # credentials, working notes, build output and other worktrees live;
  # --delete-excluded also removes copies of them an earlier sync left there.
  ignored=$(mktemp)
  git -C "$REPO_DIR" ls-files --others --ignored --exclude-standard --directory |
    sed 's|^|/|' >"$ignored"
  lite_ssh "mkdir -p '$LITE_SRC'"
  rsync -a --delete --delete-excluded --exclude /.git --exclude-from="$ignored" \
    -e "ssh ${LITE_SSH_OPTS[*]}" "$REPO_DIR/" "$LITE_USER@$LITE_HOST:$LITE_SRC/"
  rm -f "$ignored"
  lite_ssh "printf '%s\n' '$rev' >'$LITE_SRC/.lab-revision'"
}
