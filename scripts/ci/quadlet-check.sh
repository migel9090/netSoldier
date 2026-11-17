#!/usr/bin/env bash
# Quadlet dry run of the lite profile's units (task lint:quadlet; CI:
# static-checks).
#
#   scripts/ci/quadlet-check.sh [UNIT_DIR]     (default deploy/podman/units)
#
# Runs Podman's own Quadlet generator with -dryrun over the units, the way
# systemd runs it at boot on the target host, inside the pinned image of the
# oldest Podman the lite profile supports (5.4.2, Debian 13's; tools.sh
# image podman). The generator fails on an unknown key, a missing Image=, a
# reference to a network or volume unit that does not exist and any other
# unit it cannot convert, which systemd would otherwise only report on the
# user's machine at `systemctl daemon-reload`. GitHub's runners ship Podman
# 4, whose Quadlet does not know several keys the units use, so the host's
# own Podman is never used.
#
# Also checked: every .container/.volume/.network/.pod/.kube file became a
# service, so a unit the generator skipped cannot pass unnoticed. The
# installer's per-site drop-ins (*.container.d/50-site.conf) are generated
# at install time and are not part of this check.
set -euo pipefail

REPO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
UNIT_DIR=$(cd "${1:-$REPO_DIR/deploy/podman/units}" && pwd)
image=$("$REPO_DIR/scripts/ci/tools.sh" image podman)

shopt -s nullglob
sources=("$UNIT_DIR"/*.{container,volume,network,pod,kube})
((${#sources[@]})) || { echo "quadlet-check: no Quadlet unit in $UNIT_DIR" >&2; exit 1; }

out=$(mktemp)
err=$(mktemp)
trap 'rm -f "$out" "$err"' EXIT

echo "quadlet-check: ${#sources[@]} units in ${UNIT_DIR#"$REPO_DIR"/} with $image"
# Rootful generator, the profile's mode: system units in
# /etc/containers/systemd. No network: the generator needs none.
rc=0
docker run --rm --network none -v "$UNIT_DIR:/etc/containers/systemd:ro" \
  "$image" /usr/libexec/podman/quadlet -dryrun >"$out" 2>"$err" || rc=$?
grep -v 'Loading source unit file' "$err" >&2 || true
if ((rc != 0)); then
  echo "quadlet-check: FAILED (the generator exited $rc; see above)" >&2
  exit 1
fi

generated=$(grep -c '^---.*\.service---$' "$out" || true)
if ((generated != ${#sources[@]})); then
  echo "quadlet-check: FAILED: ${#sources[@]} units but $generated services generated" >&2
  grep '^---' "$out" >&2 || true
  exit 1
fi
echo "quadlet-check: OK ($generated services generated)"
