#!/usr/bin/env bash
# Run Terraform for the lab from the official image, pinned by version and
# digest. Terraform is not installed on the workstation.
#
#   infra/lab/tf.sh <terraform arguments>
#
# Mounts: infra/terraform (working dir), the state dir (/state), the config
# dir with the token and the Proxmox CA (/config, read-only) and a provider
# cache. TLS to Proxmox is verified: the CA is added to the trust store via
# SSL_CERT_DIR, which Go (Terraform and the provider) reads in addition to
# the image's own CA bundle.
set -euo pipefail
# shellcheck source=infra/lab/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# hashicorp/terraform 1.17.2 (multi-arch index digest). Keep in step with
# required_version in infra/terraform/versions.tf.
TF_IMAGE="docker.io/hashicorp/terraform:1.17.2@sha256:6e9c1e647c31a960dc9b59e13272f9111d90010c10b717f77ffb324767660475"

mkdir -p "$LAB_STATE" "$LAB_CACHE/terraform-plugins"
chmod 700 "$LAB_STATE"

# Run as the calling user, outside any userns-remap, so files Terraform
# writes (.terraform, the lock file, the state) belong to that user.
args=(
  --rm -i
  --userns=host --user "$(id -u):$(id -g)"
  -e HOME=/tmp
  -e TF_INPUT=0
  -e TF_PLUGIN_CACHE_DIR=/cache/terraform-plugins
  -v "$REPO_DIR/infra/terraform:/work" -w /work
  -v "$LAB_STATE:/state"
  -v "$LAB_CACHE:/cache"
)
[[ -t 0 && -t 1 ]] && args+=(-t)

if [[ -f $LAB_CONFIG/pve-root-ca.pem ]]; then
  args+=(
    -v "$LAB_CONFIG/pve-root-ca.pem:/etc/netsoldier-lab/ca/pve-root-ca.pem:ro"
    -e SSL_CERT_DIR=/etc/netsoldier-lab/ca
  )
fi

# Commands that evaluate variables get the token file and the SSH key.
if [[ -f $LAB_CONFIG/lab.auto.tfvars ]]; then
  args+=(-v "$LAB_CONFIG/lab.auto.tfvars:/config/lab.auto.tfvars:ro")
  for cmd in plan apply destroy refresh import console; do
    args+=(-e "TF_CLI_ARGS_${cmd}=-var-file=/config/lab.auto.tfvars")
  done
fi
if [[ -f $LAB_SSH_KEY.pub ]]; then
  args+=(-e "TF_VAR_ssh_public_key=$(<"$LAB_SSH_KEY.pub")")
fi

exec docker run "${args[@]}" "$TF_IMAGE" "$@"
