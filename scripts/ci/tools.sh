#!/usr/bin/env bash
# The pinned tools behind the CI gates, identical for CI and for a developer.
#
#   scripts/ci/tools.sh install [TOOL...]   download, verify and install TOOL
#                                           (default: all binaries), then print
#                                           the directory to put on PATH
#   scripts/ci/tools.sh image NAME          print the pinned container image
#                                           of a scanner (checkov, kics)
#
# Why this exists: the validate job piped kustomize's install_kustomize.sh,
# taken from the project's master branch, into bash. That ran unpinned remote
# code in CI, and the script queried the GitHub API without a token, so the
# job failed whenever the runner's address was rate-limited. Here every tool
# is a release artefact at a pinned version, checked against a pinned SHA-256
# before it is unpacked or run; a mismatch aborts. Scanner images are pinned
# by digest for the same reason.
#
# Bumping a tool: change its version and both checksums, copied from the
# checksum file the project publishes with that release (named next to each
# entry), never computed from a fresh download alone.
#
# Binaries land in $NETSOLDIER_TOOLS (default ~/.cache/netsoldier/tools), one
# directory per tool and version, linked from its bin/. Linux amd64 and arm64.
set -euo pipefail

TOOLS_DIR=${NETSOLDIER_TOOLS:-${XDG_CACHE_HOME:-$HOME/.cache}/netsoldier/tools}
GH=https://github.com

die() {
  echo "tools.sh: $*" >&2
  exit 1
}

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64) ARCH=amd64 ;;
  Linux/aarch64 | Linux/arm64) ARCH=arm64 ;;
  *) die "no pinned checksums for $(uname -s)/$(uname -m); only Linux amd64 and arm64" ;;
esac

# pick AMD64_VALUE ARM64_VALUE: the value for this machine's architecture.
pick() { if [[ $ARCH == amd64 ]]; then echo "$1"; else echo "$2"; fi; }

# ── binaries ────────────────────────────────────────────────────────────────
# Each tool_<name> sets VERSION, URL, SHA256 and MEMBER (the file inside a
# tarball; empty when the artefact is the binary itself).

# kustomize: the same minor as the kustomize built into the kubectl that
# infra/lab/deploy.sh renders the lab with (kubectl v1.37.2 -> kustomize
# v5.8.1), so CI renders exactly what is deployed.
# Checksums: $GH/kubernetes-sigs/kustomize/releases/download/kustomize%2Fv5.8.1/checksums.txt
tool_kustomize() {
  VERSION=v5.8.1
  URL=$GH/kubernetes-sigs/kustomize/releases/download/kustomize%2F$VERSION/kustomize_${VERSION}_linux_$ARCH.tar.gz
  SHA256=$(pick 029a7f0f4e1932c52a0476cf02a0fd855c0bb85694b82c338fc648dcb53a819d \
    0953ea3e476f66d6ddfcd911d750f5167b9365aa9491b2326398e289fef2c142)
  MEMBER=kustomize
}

# kubeconform. Checksums: $GH/yannh/kubeconform/releases/download/v0.8.0/CHECKSUMS
tool_kubeconform() {
  VERSION=v0.8.0
  URL=$GH/yannh/kubeconform/releases/download/$VERSION/kubeconform-linux-$ARCH.tar.gz
  SHA256=$(pick 9bc2bffbf71f261128533edaf912153948b7ff238f9a531ae6d34466ec287883 \
    1f53fc8e81258197a35e8603054162a5af1de8c5af13746c71ab680d9534ed87)
  MEMBER=kubeconform
}

# hadolint. v2.14.0 rather than the newer v2.15.x: it is the latest release
# that publishes checksum files. Checksums:
# $GH/hadolint/hadolint/releases/download/v2.14.0/hadolint-linux-{x86_64,arm64}.sha256
tool_hadolint() {
  VERSION=v2.14.0
  URL=$GH/hadolint/hadolint/releases/download/$VERSION/hadolint-linux-$(pick x86_64 arm64)
  SHA256=$(pick 6bf226944684f56c84dd014e8b979d27425c0148f61b3bd99bcc6f39e9dc5a47 \
    331f1d3511b84a4f1e3d18d52fec284723e4019552f4f47b19322a53ce9a40ed)
  MEMBER=
}

BINARIES=(kustomize kubeconform hadolint)

# ── scanner images ──────────────────────────────────────────────────────────
# Multi-arch index digests (docker buildx imagetools inspect <image:tag>).
declare -A IMAGES=(
  [checkov]=docker.io/bridgecrew/checkov:3.4.0@sha256:ece5efac4443084ca273072909985dce988a81e8cc94faa305aeda0df27c68f9
  [kics]=docker.io/checkmarx/kics:v2.2.0@sha256:ef29dbac14b046b1ef65f3280646112e927a61781c5f01bca1aeb723e0b96003
)

install_one() {
  local name=$1
  declare -F "tool_$name" >/dev/null || die "unknown tool '$name' (known: ${BINARIES[*]})"
  "tool_$name"
  local dest=$TOOLS_DIR/$name-$VERSION
  mkdir -p "$TOOLS_DIR/bin"
  if [[ ! -x $dest/$name ]]; then
    local tmp
    tmp=$(mktemp -d "$TOOLS_DIR/.download.XXXXXX")
    curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$tmp/artefact" "$URL" ||
      { rm -rf "$tmp"; die "$name $VERSION: download failed: $URL"; }
    # Verified before anything reads the artefact, tar included.
    echo "$SHA256  $tmp/artefact" | sha256sum -c --quiet - >&2 ||
      { rm -rf "$tmp"; die "$name $VERSION: checksum mismatch for $URL"; }
    if [[ -n $MEMBER ]]; then
      tar -xzf "$tmp/artefact" -C "$tmp" "$MEMBER"
      mv "$tmp/$MEMBER" "$tmp/bin"
    else
      mv "$tmp/artefact" "$tmp/bin"
    fi
    chmod 0755 "$tmp/bin"
    mkdir -p "$dest"
    mv "$tmp/bin" "$dest/$name"
    rm -rf "$tmp"
  fi
  ln -sfn "../$name-$VERSION/$name" "$TOOLS_DIR/bin/$name"
}

cmd=${1:-}
shift || true
case $cmd in
  install)
    (($# > 0)) || set -- "${BINARIES[@]}"
    for t in "$@"; do install_one "$t"; done
    echo "$TOOLS_DIR/bin"
    ;;
  image)
    [[ -n ${1:-} && -n ${IMAGES[$1]:-} ]] || die "usage: $0 image {${!IMAGES[*]}}"
    echo "${IMAGES[$1]}"
    ;;
  *) die "usage: $0 install [TOOL...] | image NAME" ;;
esac
