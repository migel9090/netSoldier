#!/usr/bin/env bash
# The pinned tools behind the CI gates, identical for CI and for a developer.
#
#   scripts/ci/tools.sh install [TOOL...]   download, verify and install TOOL
#                                           (default: all binaries), then print
#                                           the directory to put on PATH;
#                                           `install semgrep` builds Semgrep's
#                                           hash-locked virtualenv instead
#   scripts/ci/tools.sh image NAME          print the pinned container image
#                                           NAME (checkov, kics, podman)
#   scripts/ci/tools.sh rules semgrep       fetch the pinned Semgrep rules and
#                                           print the directory holding them
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
REPO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
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

# actionlint (MIT), the workflow linter. Checksums:
# $GH/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_checksums.txt
tool_actionlint() {
  VERSION=v1.7.12
  URL=$GH/rhysd/actionlint/releases/download/$VERSION/actionlint_${VERSION#v}_linux_$ARCH.tar.gz
  SHA256=$(pick 8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8 \
    325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6)
  MEMBER=actionlint
}

# ShellCheck (GPL-3.0, run as a tool). The project publishes no checksum
# file; these are the SHA-256 digests GitHub records for the release assets
# (gh api repos/koalaman/shellcheck/releases/tags/v0.11.0, `.assets[].digest`).
tool_shellcheck() {
  VERSION=v0.11.0
  URL=$GH/koalaman/shellcheck/releases/download/$VERSION/shellcheck-$VERSION.linux.$(pick x86_64 aarch64).tar.gz
  SHA256=$(pick b7af85e41cc99489dcc21d66c6d5f3685138f06d34651e6d34b42ec6d54fe6f6 \
    68a8133197a50beb8803f8d42f9908d1af1c5540d4bb05fdfca8c1fa47decefc)
  MEMBER=shellcheck-$VERSION/shellcheck
}

# Task (MIT), so CI runs the same Taskfile targets a developer runs.
# Checksums: $GH/go-task/task/releases/download/v3.54.0/task_checksums.txt
tool_task() {
  VERSION=v3.54.0
  URL=$GH/go-task/task/releases/download/$VERSION/task_linux_$ARCH.tar.gz
  SHA256=$(pick 680859dbb4d881a9c72d4d9a8f510825450849af8567deacd7302c01124416fb \
    d7189d439d4a6058e39e1b2acd7c8b27acd4856691b408f23b242e4294e1df5b)
  MEMBER=task
}

# promtool from the Prometheus release (Apache-2.0), for the alert rules.
# Checksums: $GH/prometheus/prometheus/releases/download/v3.16.0/sha256sums.txt
tool_promtool() {
  VERSION=v3.16.0
  URL=$GH/prometheus/prometheus/releases/download/$VERSION/prometheus-${VERSION#v}.linux-$ARCH.tar.gz
  SHA256=$(pick 68727009472a2c02e1ff7f062fd5b3e637285bffc8fc2d340c76fb449d6e0f34 \
    fd8571b8162f4020232d886f17340bcf92e1722985ae3b4c1d096157826c0fbe)
  MEMBER=prometheus-${VERSION#v}.linux-$ARCH/promtool
}

# gitleaks (MIT). gitleaks-action downloaded the newest release on every
# run; the secret scan now runs this one, here and in CI.
# Checksums: $GH/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_checksums.txt
tool_gitleaks() {
  VERSION=v8.30.1
  URL=$GH/gitleaks/gitleaks/releases/download/$VERSION/gitleaks_${VERSION#v}_linux_$(pick x64 arm64).tar.gz
  SHA256=$(pick 551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb \
    e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080)
  MEMBER=gitleaks
}

BINARIES=(kustomize kubeconform hadolint actionlint shellcheck task promtool gitleaks)

# ── Semgrep ─────────────────────────────────────────────────────────────────
# Semgrep itself comes from PyPI by hash (scripts/ci/requirements-semgrep.txt)
# into a virtualenv of its own, keyed by that file's content. Its rules are
# files of github.com/semgrep/semgrep-rules at this commit, the ones listed in
# scripts/ci/semgrep-rules.txt (regenerate both with
# scripts/ci/semgrep-rules-update.py). git checks every object it fetches
# against its id, so the commit pins the rules' exact content.
SEMGREP_RULES_COMMIT=a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2
SEMGREP_REQUIREMENTS=$REPO_DIR/scripts/ci/requirements-semgrep.txt
SEMGREP_RULES_LIST=$REPO_DIR/scripts/ci/semgrep-rules.txt

install_semgrep() {
  local stamp dest
  stamp=$(sha256sum "$SEMGREP_REQUIREMENTS" | cut -c1-16)
  dest=$TOOLS_DIR/semgrep-$stamp
  mkdir -p "$TOOLS_DIR/bin"
  if [[ ! -f $dest/.complete ]]; then
    rm -rf "$dest"
    # A virtualenv cannot be moved after creation, so it is built in place
    # and only marked complete once pip succeeded.
    "${NETSOLDIER_PYTHON:-python3}" -m venv "$dest" >&2
    "$dest/bin/pip" install --quiet --disable-pip-version-check --no-input \
      --require-hashes -r "$SEMGREP_REQUIREMENTS" >&2 ||
      { rm -rf "$dest"; die "semgrep: pip install failed"; }
    touch "$dest/.complete"
  fi
  ln -sfn "../semgrep-$stamp/bin/semgrep" "$TOOLS_DIR/bin/semgrep"
}

semgrep_rules() {
  local list_sum src dest tmp
  list_sum=$(grep -v '^#' "$SEMGREP_RULES_LIST" | sha256sum | cut -c1-16)
  src=$TOOLS_DIR/semgrep-rules-src-$SEMGREP_RULES_COMMIT
  dest=$TOOLS_DIR/semgrep-rules-$list_sum
  if [[ ! -f $dest/.complete ]]; then
    if [[ ! -f $src/.complete ]]; then
      rm -rf "$src"
      mkdir -p "$src"
      git -C "$src" init --quiet
      git -C "$src" fetch --quiet --depth 1 "$GH/semgrep/semgrep-rules" "$SEMGREP_RULES_COMMIT" ||
        { rm -rf "$src"; die "semgrep rules: fetching $SEMGREP_RULES_COMMIT failed"; }
      git -C "$src" -c advice.detachedHead=false checkout --quiet FETCH_HEAD
      [[ $(git -C "$src" rev-parse HEAD) == "$SEMGREP_RULES_COMMIT" ]] ||
        { rm -rf "$src"; die "semgrep rules: checked out something other than $SEMGREP_RULES_COMMIT"; }
      touch "$src/.complete"
    fi
    rm -rf "$dest"
    tmp=$(mktemp -d "$TOOLS_DIR/.semgrep-rules.XXXXXX")
    local f n=0
    while IFS= read -r f; do
      [[ -z $f || $f == \#* ]] && continue
      [[ -f $src/$f ]] || { rm -rf "$tmp"; die "semgrep rules: $f is not in $SEMGREP_RULES_COMMIT"; }
      mkdir -p "$tmp/rules/$(dirname "$f")"
      cp "$src/$f" "$tmp/rules/$f"
      n=$((n + 1))
    done <"$SEMGREP_RULES_LIST"
    ((n > 0)) || { rm -rf "$tmp"; die "semgrep rules: $SEMGREP_RULES_LIST lists no rule"; }
    touch "$tmp/.complete"
    mv "$tmp" "$dest"
  fi
  echo "$dest/rules"
}

# ── container images ────────────────────────────────────────────────────────
# Multi-arch index digests (docker buildx imagetools inspect <image:tag>).
# podman: the oldest Podman the lite profile supports (Debian 13 ships
# 5.4.2), for the Quadlet dry run; the runner's own Podman is 4.x.
declare -A IMAGES=(
  [checkov]=docker.io/bridgecrew/checkov:3.4.0@sha256:ece5efac4443084ca273072909985dce988a81e8cc94faa305aeda0df27c68f9
  [kics]=docker.io/checkmarx/kics:v2.2.0@sha256:ef29dbac14b046b1ef65f3280646112e927a61781c5f01bca1aeb723e0b96003
  [podman]=quay.io/podman/stable:v5.4.2@sha256:52536d900c9e7e7cc924bb737eb8c570eeaa3c50f6a3b0b563eb0ec9c48807e4
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
    for t in "$@"; do
      if [[ $t == semgrep ]]; then install_semgrep; else install_one "$t"; fi
    done
    echo "$TOOLS_DIR/bin"
    ;;
  image)
    [[ -n ${1:-} && -n ${IMAGES[$1]:-} ]] || die "usage: $0 image {${!IMAGES[*]}}"
    echo "${IMAGES[$1]}"
    ;;
  rules)
    [[ ${1:-} == semgrep ]] || die "usage: $0 rules semgrep"
    semgrep_rules
    ;;
  *) die "usage: $0 install [TOOL...] | image NAME | rules semgrep" ;;
esac
