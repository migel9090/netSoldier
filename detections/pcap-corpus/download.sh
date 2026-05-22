#!/usr/bin/env bash
# Download PCAPs listed in manifest.yaml that have url + sha256 fields.
# Synthetic entries (no url) are skipped — they are generated at test time.
# Usage: ./download.sh [manifest.yaml]
set -euo pipefail

MANIFEST="${1:-$(dirname "$0")/manifest.yaml}"
DIR="$(dirname "$MANIFEST")"

if ! command -v yq &>/dev/null; then
  echo "yq is required — install from https://github.com/mikefarah/yq" >&2
  exit 1
fi

count=$(yq '.corpus | length' "$MANIFEST")
downloaded=0
skipped=0

for ((i=0; i<count; i++)); do
  name=$(yq ".corpus[$i].name" "$MANIFEST")
  url=$(yq ".corpus[$i].url // \"\"" "$MANIFEST")
  sha256=$(yq ".corpus[$i].sha256 // \"\"" "$MANIFEST")

  if [ -z "$url" ]; then
    skipped=$((skipped + 1))
    continue
  fi

  dest="$DIR/${name}.pcap"
  if [ -f "$dest" ]; then
    echo "skip $name (exists)"
    continue
  fi

  echo "downloading $name ..."
  curl -fsSL -o "$dest" "$url"

  if [ -n "$sha256" ]; then
    actual=$(sha256sum "$dest" | cut -d' ' -f1)
    if [ "$actual" != "$sha256" ]; then
      rm -f "$dest"
      echo "CHECKSUM MISMATCH: $name (expected $sha256, got $actual)" >&2
      exit 1
    fi
  fi

  downloaded=$((downloaded + 1))
done

echo "downloaded $downloaded, skipped $skipped synthetic (total $count)"
