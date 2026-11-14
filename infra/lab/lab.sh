#!/usr/bin/env bash
# Lab helper behind the `task lab:*` targets (see infra/README.md).
#
#   lab.sh tools        .venv with pinned Ansible, collections and kubectl
#   lab.sh init         terraform init, state in $LAB_STATE
#   lab.sh inventory    write $LAB_STATE/inventory.yml from Terraform outputs
#   lab.sh provision    ansible-playbook site.yml against the lab VM
#   lab.sh kubeconfig   copy the kubeconfig to $LAB_KUBECONFIG (0600)
#   lab.sh ssh [cmd]    ssh to the lab VM (lab known_hosts, host key checked)
#   lab.sh validate     static checks; needs no credentials and no VM
set -euo pipefail
# shellcheck source=infra/lab/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# kubectl, pinned; checksum from
# https://dl.k8s.io/release/v1.37.2/bin/linux/amd64/kubectl.sha256
KUBECTL_VERSION=v1.37.2
KUBECTL_SHA256=c04487523e7aa7d1493f7808174c899db93d7a9cf57531420cd76b9bd415f8f4

ANSIBLE_DIR=$REPO_DIR/infra/ansible

cmd_tools() {
  local stamp
  stamp=$(cat "$ANSIBLE_DIR/requirements.txt" "$ANSIBLE_DIR/requirements.yml" "${BASH_SOURCE[0]}" | sha256sum | cut -c1-16)
  if [[ -f $LAB_VENV/.lab-tools && $(<"$LAB_VENV/.lab-tools") == "$stamp" ]]; then
    echo "tools up to date in $LAB_VENV"
    return
  fi
  python3 -m venv "$LAB_VENV"
  "$LAB_VENV/bin/pip" install --quiet --disable-pip-version-check \
    --require-hashes -r "$ANSIBLE_DIR/requirements.txt"
  "$LAB_VENV/bin/ansible-galaxy" collection install --force \
    -r "$ANSIBLE_DIR/requirements.yml" -p "$LAB_VENV/ansible-collections"

  local tmp
  tmp=$(mktemp "$LAB_VENV/bin/.kubectl.XXXXXX")
  curl -fsSL --retry 2 -o "$tmp" "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/amd64/kubectl"
  echo "$KUBECTL_SHA256  $tmp" | sha256sum -c --quiet - || {
    rm -f "$tmp"
    lab_die "kubectl checksum mismatch"
  }
  chmod 755 "$tmp"
  mv "$tmp" "$LAB_VENV/bin/kubectl"

  echo "$stamp" >"$LAB_VENV/.lab-tools"
  "$LAB_VENV/bin/ansible-playbook" --version | head -n1
  "$LAB_VENV/bin/kubectl" version --client | head -n1
}

cmd_init() {
  "$LAB_DIR/tf.sh" init -input=false -backend-config=path=/state/terraform.tfstate "$@"
}

cmd_inventory() {
  mkdir -p "$LAB_STATE"
  local tmp
  tmp=$(mktemp "$LAB_STATE/.inventory.XXXXXX")
  "$LAB_DIR/tf.sh" output -raw ansible_inventory >"$tmp"
  mv "$tmp" "$LAB_INVENTORY"
  echo "inventory: $LAB_INVENTORY"
  "$LAB_VENV/bin/ansible-inventory" -i "$LAB_INVENTORY" --graph
}

ansible_env() {
  cd "$ANSIBLE_DIR"
  export ANSIBLE_SSH_COMMON_ARGS="-o UserKnownHostsFile=$LAB_KNOWN_HOSTS"
  export ANSIBLE_PRIVATE_KEY_FILE=$LAB_SSH_KEY
}

cmd_provision() {
  ansible_env
  "$LAB_VENV/bin/ansible-playbook" -i "$LAB_INVENTORY" site.yml "$@"
}

cmd_kubeconfig() {
  ansible_env
  "$LAB_VENV/bin/ansible-playbook" -i "$LAB_INVENTORY" kubeconfig.yml \
    -e "k3s_kubeconfig_local_path=$LAB_KUBECONFIG" "$@"
  echo "kubeconfig: $LAB_KUBECONFIG ($(stat -c %a "$LAB_KUBECONFIG"))"
}

cmd_ssh() {
  lab_ssh "$@"
}

cmd_validate() {
  "$LAB_DIR/tf.sh" fmt -check -recursive
  "$LAB_DIR/tf.sh" init -backend=false -input=false >/dev/null
  "$LAB_DIR/tf.sh" validate
  ansible_env
  "$LAB_VENV/bin/ansible-playbook" -i localhost, --syntax-check site.yml kubeconfig.yml
  "$LAB_VENV/bin/ansible-lint" site.yml kubeconfig.yml
  for f in "$LAB_DIR"/*.sh; do bash -n "$f"; done
  echo "validate: ok"
}

sub=${1:-}
shift || true
case $sub in
  tools | init | inventory | provision | kubeconfig | ssh | validate) "cmd_$sub" "$@" ;;
  *) lab_die "usage: $0 {tools|init|inventory|provision|kubeconfig|ssh|validate} [args]" ;;
esac
