#!/usr/bin/env bash
# Build the first-party images of the core stack from this checkout and load
# them into the lab node's containerd. Nothing is pushed to a registry.
#
#   images.sh            build, import, record the tag in $LAB_STATE/lab-images.env
#   images.sh --no-build import the images of the recorded tag again
#
# With LAB_BUILD_HOST and LAB_BUILD_REGISTRY set (see lib.sh) the build runs
# on that host and the node pulls the result from its registry; without them
# it runs on this machine's Docker and the images are piped to the node.
#
# Every build gets a tag of its own, lab-<commit>[-dirty]-<UTC time>, so a pod
# can never keep running an older image under the same name (and never :main).
# The tag is what deploy.sh puts into the manifests.
set -euo pipefail
# shellcheck source=infra/lab/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

REGISTRY=ghcr.io/migel9090
# name|Dockerfile|build context (relative to the repository root). Each
# Dockerfile documents its context: the Go images build from the root so
# their go.mod replace targets under libs/ resolve; web-ui from its own dir.
IMAGES=(
  "detection-engine|apps/detection-engine/Dockerfile|."
  "device-inventory|apps/device-inventory/Dockerfile|."
  "killswitch-controller|apps/killswitch-controller/Dockerfile|."
  "threat-intel-sync|apps/threat-intel-sync/Dockerfile|."
  "netagent|apps/netagent/Dockerfile|."
  "web-ui|apps/web-ui/Dockerfile|apps/web-ui"
)
STATE_FILE=$LAB_STATE/lab-images.env

# A site variant may add first-party images (see deploy.sh, LAB_SITE).
SITE_IMAGES=()
SITE_HOOKS=$LAB_DIR/site.d/${LAB_SITE:-lab}.sh
if [[ -f $SITE_HOOKS ]]; then
  # shellcheck disable=SC1090
  source "$SITE_HOOKS"
fi
IMAGES+=("${SITE_IMAGES[@]}")

build=1
[[ ${1:-} == --no-build ]] && build=0

remote=0
if [[ -n $LAB_BUILD_HOST ]]; then
  [[ $LAB_BUILD_REGISTRY == *:* ]] || lab_die "LAB_BUILD_HOST needs LAB_BUILD_REGISTRY=host:port (the registry as the lab node reaches it)"
  remote=1
  # Where the checkout is mirrored on the build host, one per lab instance.
  build_dir=${LAB_BUILD_DIR:-/var/tmp/netsoldier-lab-build/$(basename "$LAB_STATE")}
  # The build host pushes to its own registry by its local name.
  push_registry=localhost:${LAB_BUILD_REGISTRY##*:}
fi

# remote_build TAG: mirror what git would commit to the build host, then
# build and push every image there.
remote_build() {
  local tag=$1 ignored entry name dockerfile context
  local -a opts
  mapfile -t opts < <(lab_build_ssh_opts)
  ignored=$(mktemp)
  git -C "$REPO_DIR" ls-files --others --ignored --exclude-standard --directory |
    sed 's|^|/|' >"$ignored"
  lab_build_ssh "mkdir -p '$build_dir'"
  rsync -a --delete --delete-excluded --exclude /.git --exclude-from="$ignored" \
    -e "ssh ${opts[*]}" "$REPO_DIR/" "$LAB_BUILD_HOST:$build_dir/"
  rm -f "$ignored"
  for entry in "${IMAGES[@]}"; do
    IFS='|' read -r name dockerfile context <<<"$entry"
    echo "==> build $name:$tag on $LAB_BUILD_HOST"
    lab_build_ssh "cd '$build_dir' &&
      docker build --quiet -f '$dockerfile' -t '$push_registry/netsoldier/$name:$tag' '$context' >/dev/null &&
      docker push --quiet '$push_registry/netsoldier/$name:$tag' >/dev/null"
  done
}

if ((build)); then
  sha=$(git -C "$REPO_DIR" rev-parse --short=10 HEAD)
  git -C "$REPO_DIR" diff --quiet HEAD -- apps libs || sha="$sha-dirty"
  tag="lab-$sha-$(date -u +%Y%m%d%H%M%S)"
  if ((remote)); then
    remote_build "$tag"
  else
    for entry in "${IMAGES[@]}"; do
      IFS='|' read -r name dockerfile context <<<"$entry"
      echo "==> build $name:$tag"
      docker build --quiet -f "$REPO_DIR/$dockerfile" -t "$REGISTRY/$name:$tag" "$REPO_DIR/$context" >/dev/null
    done
  fi
  mkdir -p "$LAB_STATE"
  printf 'LAB_IMAGE_TAG=%s\n' "$tag" >"$STATE_FILE"
else
  [[ -s $STATE_FILE ]] || lab_die "no recorded image tag in $STATE_FILE; run without --no-build"
  # shellcheck disable=SC1090
  source "$STATE_FILE"
  tag=$LAB_IMAGE_TAG
fi

refs=()
for entry in "${IMAGES[@]}"; do
  refs+=("$REGISTRY/${entry%%|*}:$tag")
done
if ((remote)); then
  echo "==> the node pulls ${#refs[@]} images from $LAB_BUILD_REGISTRY"
  for entry in "${IMAGES[@]}"; do
    name=${entry%%|*}
    src=$LAB_BUILD_REGISTRY/netsoldier/$name:$tag
    lab_ssh "sudo k3s ctr --namespace k8s.io images pull --plain-http '$src' >/dev/null &&
      sudo k3s ctr --namespace k8s.io images tag --force '$src' '$REGISTRY/$name:$tag' >/dev/null"
  done
else
  echo "==> import ${#refs[@]} images into the node's containerd"
  docker save "${refs[@]}" | lab_ssh sudo k3s ctr --namespace k8s.io images import - >/dev/null
fi
imported=$(lab_ssh sudo k3s ctr --namespace k8s.io images ls -q)
for ref in "${refs[@]}"; do
  grep -qxF "$ref" <<<"$imported" || lab_die "$ref is not in the node's containerd after the import"
  echo "    $ref"
done
echo "LAB_IMAGE_TAG=$tag"
