#!/usr/bin/env bash
# Fetch the external (real-world) captures listed in manifest.yaml and verify
# them against their pinned sha256. Generated entries are not downloaded —
# they are rebuilt by gen_corpus.py.
#
# These archives are password-protected and the password is published only as
# an image on the source site, which is the operator's way of saying "no
# scripted extraction". This script therefore stops at the verified archive:
# unpack it yourself when you need it.
#
# Usage: ./download.sh [--list] [--dest DIR] [manifest.yaml]
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
MANIFEST="$DIR/manifest.yaml"
DEST="$DIR/external"
LIST_ONLY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --list) LIST_ONLY=1; shift ;;
    --dest) DEST="$2"; shift 2 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) MANIFEST="$1"; shift ;;
  esac
done

# python3 rather than yq: the corpus tooling already depends on PyYAML and
# yq is not installed on the CI runners.
entries() {
  python3 - "$MANIFEST" <<'PY'
import sys, yaml
with open(sys.argv[1]) as f:
    manifest = yaml.safe_load(f)
for e in manifest.get("corpus", []):
    if e.get("source") != "external" or not e.get("url"):
        continue
    print("\t".join([e["name"], e["url"], e.get("sha256", ""),
                     e.get("description", "").strip()]))
PY
}

if [ "$LIST_ONLY" = 1 ]; then
  entries | while IFS=$'\t' read -r name url sha desc; do
    printf '%-34s %s\n' "$name" "$desc"
  done
  exit 0
fi

mkdir -p "$DEST"
downloaded=0
verified=0

while IFS=$'\t' read -r name url sha desc; do
  file="$DEST/$(basename "$url")"

  if [ ! -f "$file" ]; then
    echo "fetching $name ..."
    curl -fSL --retry 2 --max-time 600 -o "$file.part" "$url"
    mv "$file.part" "$file"
    downloaded=$((downloaded + 1))
  fi

  if [ -n "$sha" ]; then
    actual=$(sha256sum "$file" | cut -d' ' -f1)
    if [ "$actual" != "$sha" ]; then
      rm -f "$file"
      echo "CHECKSUM MISMATCH for $name" >&2
      echo "  expected $sha" >&2
      echo "  actual   $actual" >&2
      echo "  file removed — do not use it" >&2
      exit 1
    fi
    verified=$((verified + 1))
  else
    echo "WARNING: $name has no pinned sha256 — cannot verify" >&2
  fi

  echo "ok $name -> $file"
done < <(entries)

cat <<EOF

$downloaded downloaded, $verified checksum-verified, in $DEST

These are password-protected archives of live malware traffic. Extract them
by hand with the password from the source site's about page, into a directory
you control — nothing here unpacks them for you, and the extracted captures
must never be committed (*.pcap is gitignored).
EOF
