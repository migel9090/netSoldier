#!/usr/bin/env bash
# Render every deployable kustomize target and validate it, strictly.
#
#   scripts/ci/render-manifests.sh [--render-only] [OUT_DIR]
#                                         (task validate:manifests)
#
# --render-only skips kubeconform: the scanner jobs need the rendered
# targets but should not fail a second time for what `validate` reports.
#
# Targets, as deploy/README.md defines them: every site under
# deploy/kustomize/sites/ (a site is what gets deployed) and every profile
# under deploy/kustomize/overlays/ (core, pi-edge, proxmox-soc; a profile is
# not deployable alone, but the sites are built from them and the
# unexercised ones would otherwise go unchecked). Each renders to
# OUT_DIR/<site|profile>-<name>.yaml, which is also what the IaC scanners
# judge (scripts/ci/iac-gate.py): the objects that reach the cluster, not the
# patch fragments and bases they are assembled from.
#
# kubeconform runs with -strict (unknown fields are errors) and without
# -ignore-missing-schemas: an object with no schema fails rather than passing
# unvalidated. The schemas are pinned to commits of their repositories, so
# the gate cannot change under a moved branch.
#
# Every target is attempted; the ones that fail to render or to validate are
# named at the end and the script exits non-zero.
set -euo pipefail

REPO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
validate=1
if [[ ${1:-} == --render-only ]]; then
  validate=0
  shift
fi
OUT_DIR=${1:-${TMPDIR:-/tmp}/netsoldier-rendered}

# The cluster version the lab runs (infra/ansible/roles/k3s_server).
KUBERNETES_VERSION=1.37.2
# Kubernetes' own kinds, generated from its OpenAPI (Apache-2.0).
K8S_SCHEMAS='https://raw.githubusercontent.com/yannh/kubernetes-json-schema/6ea44f54bb5cdedb2f61fba42c9b342e97959262/{{.NormalizedKubernetesVersion}}-standalone{{.StrictSuffix}}/{{.ResourceKind}}{{.KindSuffix}}.json'
# Custom resources (ServiceMonitor, PrometheusRule in proxmox-soc), MIT.
CRD_SCHEMAS='https://raw.githubusercontent.com/datreeio/CRDs-catalog/3e8a8916ca1b7af6464606c2c2f5869dbafa9653/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'
SCHEMA_CACHE=${NETSOLDIER_SCHEMA_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/netsoldier/kubeconform}

# The pinned, checksum-verified binaries (installed on first use).
bin=$("$REPO_DIR/scripts/ci/tools.sh" install kustomize kubeconform)
KUSTOMIZE=$bin/kustomize
KUBECONFORM=$bin/kubeconform

# base/misp generates its Secret with ksops, which needs a key CI does not
# have and an encrypted file that is never committed. The stub stands in for
# the plugin with a placeholder Secret (see its header), on this script's
# PATH only, so a real ksops elsewhere on the machine is never shadowed.
stub_dir=$(mktemp -d)
trap 'rm -rf "$stub_dir"' EXIT
ln -s "$REPO_DIR/scripts/ci/ksops-stub.py" "$stub_dir/ksops"

mkdir -p "$OUT_DIR" "$SCHEMA_CACHE"
rm -f "$OUT_DIR"/*.yaml

targets=()
for dir in "$REPO_DIR"/deploy/kustomize/sites/*/; do
  [[ -f $dir/kustomization.yaml ]] && targets+=("site:$dir")
done
for dir in "$REPO_DIR"/deploy/kustomize/overlays/*/; do
  [[ -f $dir/kustomization.yaml ]] && targets+=("profile:$dir")
done
# A glob that matches nothing must not turn into a green job that checked
# nothing.
grep -q '^site:' < <(printf '%s\n' "${targets[@]}") || { echo "no site under deploy/kustomize/sites/" >&2; exit 1; }

failed=()
for entry in "${targets[@]}"; do
  kind=${entry%%:*}
  dir=${entry#*:}
  name="$kind-$(basename "$dir")"
  rel=${dir#"$REPO_DIR"/}
  out=$OUT_DIR/$name.yaml
  echo "::group::$name (${rel%/})"
  if ! PATH="$stub_dir:$PATH" "$KUSTOMIZE" build --enable-alpha-plugins --enable-exec "$dir" >"$out"; then
    echo "::error::$name: ${rel%/} does not render"
    rm -f "$out"
    failed+=("$name (render)")
  elif ((validate)) && ! "$KUBECONFORM" -strict -summary \
    -kubernetes-version "$KUBERNETES_VERSION" \
    -schema-location "$K8S_SCHEMAS" -schema-location "$CRD_SCHEMAS" \
    -cache "$SCHEMA_CACHE" "$out"; then
    echo "::error::$name: ${rel%/} renders but does not validate"
    failed+=("$name (kubeconform)")
  fi
  echo "::endgroup::"
done

if ((${#failed[@]})); then
  echo "Targets that failed:" >&2
  printf '  - %s\n' "${failed[@]}" >&2
  exit 1
fi
if ((validate)); then
  echo "OK: ${#targets[@]} targets rendered and validated into $OUT_DIR"
else
  echo "OK: ${#targets[@]} targets rendered into $OUT_DIR (not validated)"
fi
