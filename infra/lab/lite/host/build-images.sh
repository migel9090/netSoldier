#!/usr/bin/env bash
# Build the six netSoldier images of the lite profile with Podman, on the lab
# host, from a copy of the repository (lite.sh sync puts it at SRC).
#
#   build-images.sh [SRC] [TAG] [SERVICE...]
#                   default SRC=/opt/netsoldier/src TAG=lab, all six services
#
# Images are tagged localhost/netsoldier/<service>:<TAG>, which is what
# netsoldier.lab.conf points the installer at. Nothing is pushed anywhere.
# RUN steps use the host network: the LXC lab host has no pasta, and the
# builds only download Go modules and npm packages.
set -euo pipefail

SRC=${1:-/opt/netsoldier/src}
TAG=${2:-lab}
shift 2 || shift $#
cd "$SRC"

# service -> "context dockerfile"
declare -A BUILD=(
  [threat-intel-sync]=". apps/threat-intel-sync/Dockerfile"
  [detection-engine]=". apps/detection-engine/Dockerfile"
  [device-inventory]=". apps/device-inventory/Dockerfile"
  [killswitch-controller]=". apps/killswitch-controller/Dockerfile"
  [netagent]=". apps/netagent/Dockerfile"
  [web-ui]="apps/web-ui apps/web-ui/Dockerfile"
)

rev=$(cat .lab-revision 2>/dev/null || echo unknown)
services=("$@")
((${#services[@]})) || services=(threat-intel-sync detection-engine device-inventory killswitch-controller netagent web-ui)
for svc in "${services[@]}"; do
  [[ -n ${BUILD[$svc]:-} ]] || { echo "unknown service $svc" >&2; exit 2; }
  read -r ctx file <<<"${BUILD[$svc]}"
  start=$SECONDS
  podman build -q --network=host --label "org.opencontainers.image.revision=$rev" \
    -t "localhost/netsoldier/$svc:$TAG" -f "$file" "$ctx" >/dev/null
  printf 'built localhost/netsoldier/%s:%s in %ds (%s)\n' "$svc" "$TAG" $((SECONDS - start)) \
    "$(podman image inspect --format '{{.Size}}' "localhost/netsoldier/$svc:$TAG" | numfmt --to=iec)"
done
# The netagent binary must still carry its file capability after the build.
if podman image exists "localhost/netsoldier/netagent:$TAG"; then
  mnt=$(podman image mount "localhost/netsoldier/netagent:$TAG")
  getcap "$mnt/netagent"
  podman image unmount "localhost/netsoldier/netagent:$TAG" >/dev/null
fi
podman image prune -f >/dev/null
