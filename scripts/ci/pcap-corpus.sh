#!/usr/bin/env bash
# Replay the PCAP corpus through the sensors (task test:corpus and
# test:corpus:zeek-image; CI: the detections workflow).
#
#   scripts/ci/pcap-corpus.sh [VERIFY_ARGS...]
#       Suricata and Zeek, each pinned by digest: Suricata is the image the
#       manifests deploy (deploy/kustomize/base/suricata/deployment.yaml),
#       Zeek the upstream image the netSoldier Zeek image is built FROM
#       (deploy/docker/zeek/Dockerfile), running the repository's scripts.
#   scripts/ci/pcap-corpus.sh --zeek-image [VERIFY_ARGS...]
#       Builds deploy/docker/zeek as it is shipped and replays the corpus
#       through that image, so a change to the image (base, zkg packages,
#       baked-in scripts, file capabilities) is judged too. The image is
#       removed afterwards.
#
# detections/pcap-corpus/test/verify.py does the work: it regenerates the
# deterministic captures, checks their sha256 pins and asserts the SIDs and
# Zeek logs manifest.yaml expects, including zero alerts on benign traffic.
# Its own defaults name the sensors by tag only; this wrapper hands it the
# digests, so the gate cannot move under an unchanged tree.
set -euo pipefail

REPO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$REPO_DIR"

die() {
  echo "pcap-corpus: $*" >&2
  exit 1
}

# The first image reference of a file that is pinned by digest.
pinned_image() {
  local file=$1 pattern=$2 ref
  ref=$(grep -oE "$pattern" "$file" | head -n1) || true
  [[ -n $ref ]] || die "no image matching $pattern in $file"
  [[ $ref == *@sha256:* ]] || die "$file names $ref without a digest"
  echo "$ref"
}

suricata=$(pinned_image deploy/kustomize/base/suricata/deployment.yaml \
  'jasonish/suricata:[^[:space:]"]+')
zeek=$(pinned_image deploy/docker/zeek/Dockerfile 'zeek/zeek:[^[:space:]]+')

if [[ ${1:-} == --zeek-image ]]; then
  shift
  tag=netsoldier-zeek-corpus:$(git rev-parse --short=12 HEAD 2>/dev/null || echo local)-$$
  trap 'docker image rm -f "$tag" >/dev/null 2>&1 || true' EXIT
  echo "pcap-corpus: building deploy/docker/zeek as $tag"
  docker build --pull=false -q -t "$tag" deploy/docker/zeek >/dev/null
  # The shipped image runs Zeek non-root with file capabilities, which
  # exec needs in the container's bounding set (--docker-caps). Not exec'd:
  # the trap removes the image afterwards.
  python3 detections/pcap-corpus/test/verify.py --sensor zeek \
    --zeek-image "$tag" --docker-caps "$@"
  exit
fi

echo "pcap-corpus: suricata $suricata"
echo "pcap-corpus: zeek     $zeek"
exec python3 detections/pcap-corpus/test/verify.py \
  --suricata-image "$suricata" --zeek-image "$zeek" "$@"
