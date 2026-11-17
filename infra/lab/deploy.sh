#!/usr/bin/env bash
# Deploy the core stack to the lab cluster from this checkout (task lab:deploy).
#
#   deploy.sh              simulated LAN (Ansible) -> images (build, import)
#                          -> Secrets (generated where absent) -> apply -> wait
#   deploy.sh --no-build   reuse the images of the last build (imported again)
#   deploy.sh --no-node    touch only the Kubernetes API: no Ansible run, no
#                          image import (the images of the last build must
#                          already be on the node)
#   deploy.sh --rotate     generate every Secret anew and restart the stack
#   deploy.sh down         delete the stack: namespaces netsoldier and dns with
#                          their volumes (the simulated LAN stays)
#
# LAB_SITE picks what is deployed: deploy/kustomize/sites/$LAB_SITE. The
# default, `lab`, is the core profile. A variant (sites/lab-<name>, normally
# sites/lab plus more bases) may bring infra/lab/site.d/$LAB_SITE.sh, which
# is sourced here and by images.sh and may define, all optional:
#   SITE_IMAGES=("name|Dockerfile|context" ...)  more first-party images
#   site_secrets ROTATE   Secrets of its own, after the core ones exist
#   site_pre_apply        just before `kubectl apply`
#   site_wait             after the core stack is ready
#   site_down             before the namespaces are deleted
# A hook file only defines things; it runs nothing when sourced.
#
# What it deploys by default is deploy/kustomize/sites/lab (profile core + the lab's site
# values) with the images of this build. Every credential is generated here,
# randomly, and applied straight to the cluster: none is written to disk,
# printed or committed. Read one back with
#   kubectl -n netsoldier get secret web-ui-credentials -o jsonpath='{.data.password}' | base64 -d
set -euo pipefail
# shellcheck source=infra/lab/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

KUBECTL=${KUBECTL:-$LAB_VENV/bin/kubectl}
export KUBECONFIG=$LAB_KUBECONFIG
LAB_SITE=${LAB_SITE:-lab}
SITE_DIR=$REPO_DIR/deploy/kustomize/sites/$LAB_SITE
SITE_HOOKS=$LAB_DIR/site.d/$LAB_SITE.sh
IMAGES_STATE=$LAB_STATE/lab-images.env
FIRST_PARTY=(detection-engine device-inventory killswitch-controller threat-intel-sync netagent web-ui)
NS=netsoldier

k() { "$KUBECTL" "$@"; }
step() { printf '==> %s\n' "$*"; }
has_hook() { declare -F "$1" >/dev/null; }

need_tools() {
  [[ -x $KUBECTL && -x $LAB_VENV/bin/python ]] || "$LAB_DIR/lab.sh" tools
  [[ -f $KUBECONFIG ]] || lab_die "no kubeconfig at $KUBECONFIG (run: task lab:kubeconfig)"
}

# ── Secrets ──────────────────────────────────────────────────────────────
# Hex and URL-safe base64 only: every value survives env files, headers and
# the ClickHouse users file without quoting.
rand_hex() { openssl rand -hex "$1"; }
rand_b64() { openssl rand -base64 "$1" | tr -d '\n=' | tr '+/' '-_'; }

secret_exists() { k -n "$1" get secret "$2" >/dev/null 2>&1; }

# apply_secret NAMESPACE NAME: KEY=VALUE lines on stdin -> Secret. The values
# travel through a pipe, never through argv.
apply_secret() {
  k -n "$1" create secret generic "$2" --from-env-file=/dev/stdin \
    --dry-run=client -o yaml | k apply -f - >/dev/null
  echo "    secret $1/$2"
}

bcrypt_hash() { # password on stdin
  "$LAB_VENV/bin/python" -I -c '
import sys, bcrypt
print(bcrypt.hashpw(sys.stdin.buffer.read(), bcrypt.gensalt(rounds=10, prefix=b"2a")).decode())'
}

generate_secrets() {
  local rotate=$1 pw acct

  # ClickHouse: one password per account; the server gets only the SHA-256
  # (rendered into users-override.xml by its init container). Accounts the
  # core stack does not use still need a hash, or the server refuses to
  # start; Vector's and Grafana's plaintext belongs to the observability
  # namespace, which the lab does not run.
  if ((rotate)) || ! secret_exists "$NS" clickhouse-credentials; then
    for acct in default migrate killswitch detection inventory ml-beacon ml-flow \
      zeek suricata vector grafana rita; do
      pw=$(rand_hex 32)
      [[ $acct == vector || $acct == grafana ]] || echo "$acct-password=$pw"
      echo "$acct-password-sha256=$(printf %s "$pw" | sha256sum | cut -d' ' -f1)"
    done | apply_secret "$NS" clickhouse-credentials
  fi

  # AdGuard: the services hold the password, AdGuard only its bcrypt hash.
  # Generated together, so they always match.
  if ((rotate)) || ! secret_exists "$NS" adguard-credentials || ! secret_exists dns adguard-users; then
    pw=$(rand_b64 24)
    printf 'username=netsoldier\npassword=%s\n' "$pw" | apply_secret "$NS" adguard-credentials
    printf 'username=netsoldier\npassword-bcrypt=%s\n' "$(printf %s "$pw" | bcrypt_hash)" |
      apply_secret dns adguard-users
  fi

  # Killswitch: operator token (web UI), ingest token (detection-engine),
  # signature key. Three independent values (contract 4).
  if ((rotate)) || ! secret_exists "$NS" killswitch-credentials; then
    printf 'api-key=%s\ningest-token=%s\nwebhook-secret=%s\n' \
      "$(rand_hex 32)" "$(rand_hex 32)" "$(rand_hex 32)" | apply_secret "$NS" killswitch-credentials
  fi

  # netagent: its own credential towards each peer (contract 8).
  if ((rotate)) || ! secret_exists "$NS" netagent-credentials; then
    printf 'inventory-token=%s\nkillswitch-token=%s\n' "$(rand_hex 32)" "$(rand_hex 32)" |
      apply_secret "$NS" netagent-credentials
  fi

  if ((rotate)) || ! secret_exists "$NS" device-inventory-credentials; then
    printf 'api-key=%s\n' "$(rand_hex 32)" | apply_secret "$NS" device-inventory-credentials
  fi
  if ((rotate)) || ! secret_exists "$NS" detection-engine-credentials; then
    printf 'api-key=%s\n' "$(rand_hex 32)" | apply_secret "$NS" detection-engine-credentials
  fi

  # Web UI: session signing key (>= 32 chars) and the household password
  # (>= 12 chars, different from the key).
  if ((rotate)) || ! secret_exists "$NS" web-ui-credentials; then
    printf 'session-secret=%s\npassword=%s\n' "$(rand_b64 48)" "$(rand_b64 18)" |
      apply_secret "$NS" web-ui-credentials
  fi
}

# ── Manifests ────────────────────────────────────────────────────────────
# The lab site with this build's image tags. The override lives in a
# throw-away kustomization so the committed manifests keep their :main.
render() {
  local tag=$1 dir name rc=0
  dir=$(mktemp -d)
  {
    echo "apiVersion: kustomize.config.k8s.io/v1beta1"
    echo "kind: Kustomization"
    echo "resources:"
    # kustomize takes no absolute path to a base.
    echo "  - $(realpath --relative-to="$dir" "$SITE_DIR")"
    echo "images:"
    for name in "${FIRST_PARTY[@]}"; do
      printf '  - name: ghcr.io/migel9090/%s\n    newTag: "%s"\n' "$name" "$tag"
    done
  } >"$dir/kustomization.yaml"
  k kustomize "$dir" 2> >(grep -v "^# Warning: 'commonLabels' is deprecated" >&2) || rc=$?
  rm -rf "$dir"
  return "$rc"
}

only_kind() { # KIND: filter a multi-document manifest on stdin
  "$LAB_VENV/bin/python" -I -c '
import sys, yaml
docs = [d for d in yaml.safe_load_all(sys.stdin) if d and d.get("kind") == sys.argv[1]]
yaml.safe_dump_all(docs, sys.stdout)' "$1"
}

wait_ready() {
  step "wait for the stack"
  k -n "$NS" rollout status statefulset/clickhouse --timeout=300s
  k -n "$NS" wait --for=condition=complete job/clickhouse-migrate --timeout=900s
  k -n dns rollout status statefulset/adguard-home --timeout=300s
  local d
  for d in threat-intel-sync detection-engine device-inventory killswitch-controller web-ui; do
    k -n "$NS" rollout status "deployment/$d" --timeout=300s
  done
  k -n "$NS" rollout status daemonset/netagent --timeout=300s
}

summary() {
  step "pods"
  k get pods -n "$NS" -o custom-columns='POD:.metadata.name,READY:.status.containerStatuses[*].ready,RUNTIME:.spec.runtimeClassName,HOSTNET:.spec.hostNetwork,CAPS_ADD:.spec.containers[*].securityContext.capabilities.add,IMAGE:.spec.containers[*].image'
  k get pods -n dns -o custom-columns='POD:.metadata.name,READY:.status.containerStatuses[*].ready,RUNTIME:.spec.runtimeClassName,HOSTNET:.spec.hostNetwork,CAPS_ADD:.spec.containers[*].securityContext.capabilities.add,IMAGE:.spec.containers[*].image'
}

cmd_up() {
  local build=1 import=1 lan=1 rotate=0 tag manifest
  for a in "$@"; do
    case $a in
      --no-build) build=0 ;;
      --no-node) build=0 import=0 lan=0 ;;
      --rotate) rotate=1 ;;
      *) lab_die "unknown option $a" ;;
    esac
  done
  need_tools

  if ((lan)); then
    step "simulated home LAN (infra/ansible/lab-lan.yml)"
    "$LAB_DIR/lab.sh" lan
  fi

  if ((build)); then
    step "images: build and import"
    "$LAB_DIR/images.sh"
  elif ((import)); then
    step "images: import the last build again"
    "$LAB_DIR/images.sh" --no-build
  fi
  [[ -s $IMAGES_STATE ]] || lab_die "no image build recorded in $IMAGES_STATE (run without --no-build)"
  # shellcheck disable=SC1090
  source "$IMAGES_STATE"
  tag=$LAB_IMAGE_TAG

  step "render deploy/kustomize/sites/$LAB_SITE with images :$tag"
  manifest=$(render "$tag") || lab_die "deploy/kustomize/sites/$LAB_SITE does not render"

  step "namespaces"
  only_kind Namespace <<<"$manifest" | k apply -f -

  step "secrets$( ((rotate)) && echo ' (rotating every one)')"
  generate_secrets "$rotate"
  if has_hook site_secrets; then site_secrets "$rotate"; fi

  # A finished Job is immutable; it runs again (a no-op when the schema is
  # current) with the migrations of this checkout.
  k -n "$NS" delete job clickhouse-migrate --ignore-not-found --wait=true >/dev/null

  if has_hook site_pre_apply; then site_pre_apply; fi

  step "apply"
  k apply -f - <<<"$manifest"

  if ((rotate)); then
    step "restart everything that read the old Secrets"
    k -n "$NS" rollout restart statefulset/clickhouse daemonset/netagent
    k -n "$NS" rollout restart deployment
    k -n dns rollout restart statefulset/adguard-home
  fi

  wait_ready
  if has_hook site_wait; then site_wait; fi
  summary
}

cmd_down() {
  need_tools
  if has_hook site_down; then site_down; fi
  step "delete namespaces netsoldier and dns (and their volumes)"
  k delete namespace "$NS" dns --ignore-not-found --wait=true
}

[[ -d $SITE_DIR ]] || lab_die "no site at deploy/kustomize/sites/$LAB_SITE"
SITE_IMAGES=()
if [[ -f $SITE_HOOKS ]]; then
  # shellcheck disable=SC1090
  source "$SITE_HOOKS"
fi
for entry in "${SITE_IMAGES[@]}"; do
  FIRST_PARTY+=("${entry%%|*}")
done

case ${1:-up} in
  up) shift || true; cmd_up "$@" ;;
  --*) cmd_up "$@" ;;
  down) cmd_down ;;
  *) lab_die "usage: $0 [up] [--no-build|--no-node] [--rotate] | down" ;;
esac
