#!/usr/bin/env bash
# Workstation side of the lite lab. Everything runs on the lab host over SSH
# (LITE_HOST, required); see lib.sh for the settings.
#
#   lite.sh sync          copy the working tree to the host (LITE_SRC)
#   lite.sh build         build the six images there with Podman (tag LITE_TAG;
#                         LITE_BUILD=local: like build-local)
#   lite.sh build-local   build them here with Docker and load them there
#   lite.sh lan-up|lan-down   the simulated home LAN (host/lan.sh)
#   lite.sh install       netsoldier-lite install with netsoldier.lab.conf
#   lite.sh install-ansible   the same through the podman_edge role
#   lite.sh uninstall     netsoldier-lite uninstall --keep-images, then check
#                         that nothing is left
#   lite.sh uninstall-ansible the role with podman_edge_state=absent (removes
#                         the images too), then the same check
#   lite.sh scenario      the smoke scenario (host/scenario.sh), memory sampled
#   lite.sh measure       memory per container, now
#   lite.sh e2e           all of it from a clean host: sync, build, uninstall,
#                         lan, install, scenario
#   lite.sh e2e-ansible   the same through the role: absent, build, install
#                         twice (idempotency), scenario
set -euo pipefail
# shellcheck source=infra/lab/lite/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

H=$LITE_SRC/infra/lab/lite/host
NL=$LITE_SRC/deploy/podman/netsoldier-lite

cmd_install() {
  # The site configuration an installer would write, then the installer.
  lite_ssh "install -d -m 0755 /etc/netsoldier && install -m 0600 $LITE_SRC/infra/lab/lite/netsoldier.lab.conf /etc/netsoldier/netsoldier.conf &&
    printf '%s\n' '# lab: known-bad for the scenario (infra/lab/lite/host/scenario.sh)' example.com example.net example.org >/etc/netsoldier/local-indicators.txt &&
    time $NL install"
}

cmd_ansible() { # extra ansible-playbook arguments, e.g. -e podman_edge_state=absent
  local venv=${LITE_VENV:-$REPO_DIR/.venv}
  [[ -x $venv/bin/ansible-playbook ]] || lite_die "no Ansible in $venv (run: task lab:tools, or set LITE_VENV)"
  # The LXC lab host has no sudo; logged in as root there is nothing to become.
  [[ $LITE_USER != root ]] || set -- -e ansible_become=false "$@"
  ANSIBLE_CONFIG=$REPO_DIR/infra/ansible/ansible.cfg \
    ANSIBLE_SSH_ARGS="-o IdentitiesOnly=yes -o IPQoS=none -o ControlMaster=auto -o ControlPersist=60s" \
    "$venv/bin/ansible-playbook" -i "$LITE_HOST," -u "$LITE_USER" --private-key "$LITE_SSH_KEY" \
    -e "@$LITE_DIR/ansible-vars.yml" "$@" "$LITE_DIR/playbook.yml"
}

# Build the six images on the workstation with Docker instead (faster when
# the host's downloads are slow) and load them into the host's Podman.
cmd_build_local() {
  local svc ctx file images=()
  for svc in threat-intel-sync detection-engine device-inventory killswitch-controller netagent web-ui; do
    ctx=$REPO_DIR file=$REPO_DIR/apps/$svc/Dockerfile
    [[ $svc == web-ui ]] && ctx=$REPO_DIR/apps/web-ui
    docker buildx build -q --load --label "org.opencontainers.image.revision=$(git -C "$REPO_DIR" rev-parse --short HEAD)" \
      -t "localhost/netsoldier/$svc:$LITE_TAG" -f "$file" "$ctx" >/dev/null
    echo "built localhost/netsoldier/$svc:$LITE_TAG"
    images+=("localhost/netsoldier/$svc:$LITE_TAG")
  done
  docker save "${images[@]}" | lite_ssh "podman load -q"
  # The file capability has to survive Docker's export and Podman's import.
  lite_ssh "m=\$(podman image mount localhost/netsoldier/netagent:$LITE_TAG) && getcap \$m/netagent;
    podman image unmount localhost/netsoldier/netagent:$LITE_TAG >/dev/null"
}

# LITE_BUILD=host (default): Podman on the lab host; local: Docker here.
cmd_build() {
  case ${LITE_BUILD:-host} in
    host) lite_ssh "bash $H/build-images.sh $LITE_SRC $LITE_TAG" ;;
    local) cmd_build_local ;;
    *) lite_die "LITE_BUILD must be host or local" ;;
  esac
}

cmd_uninstall() {
  # The worktree's copy, not the installed one: it is the version under test.
  lite_ssh "$NL uninstall --keep-images; bash $H/clean-check.sh"
}

cmd_scenario() {
  local log
  log=/var/log/netsoldier-lab/scenario-$(date +%Y%m%d-%H%M%S).log
  lite_ssh "set -eo pipefail; mkdir -p /var/log/netsoldier-lab
    echo '=== memory, idle (before the scenario)'; bash $H/measure.sh | tee /var/log/netsoldier-lab/idle.txt
    rm -f /run/netsoldier-lab-samples
    bash $H/measure.sh sample /run/netsoldier-lab-samples & sampler=\$!
    rc=0; bash $H/scenario.sh 2>&1 | tee $log || rc=\$?
    kill \$sampler 2>/dev/null || echo 'warning: the memory sampler had stopped early'; echo; echo '=== peak memory during the scenario (per container; TOTAL = sum of the peaks)'
    bash $H/measure.sh peaks /run/netsoldier-lab-samples | tee /var/log/netsoldier-lab/peaks.txt; echo log: $log; exit \$rc"
}

case ${1:-} in
  sync) lite_sync ;;
  build) cmd_build ;;
  build-local) cmd_build_local ;;
  lan-up) lite_ssh "bash $H/lan.sh up" ;;
  lan-down) lite_ssh "bash $H/lan.sh down" ;;
  install) cmd_install ;;
  install-ansible) cmd_ansible ;;
  uninstall-ansible) cmd_ansible -e podman_edge_state=absent && lite_ssh "bash $H/clean-check.sh" ;;
  uninstall) cmd_uninstall ;;
  scenario) cmd_scenario ;;
  measure) lite_ssh "bash $H/measure.sh" ;;
  e2e)
    lite_sync
    cmd_build
    cmd_uninstall
    lite_ssh "bash $H/lan.sh down && bash $H/lan.sh up"
    cmd_install
    cmd_scenario
    ;;
  e2e-ansible)
    # The Ansible path from nothing: the role removes the profile (images
    # too), the images are rebuilt, the role installs twice (the second run
    # must change nothing), then the scenario.
    lite_sync
    cmd_ansible -e podman_edge_state=absent
    lite_ssh "bash $H/clean-check.sh"
    cmd_build
    lite_ssh "bash $H/lan.sh down && bash $H/lan.sh up"
    echo "=== podman_edge, first run"
    cmd_ansible
    echo "=== podman_edge, second run (expect changed=0)"
    cmd_ansible
    cmd_scenario
    ;;
  *) sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
