#!/usr/bin/env bash
# Verify the secret-handling story actually holds.
#
# Two things have to be true and neither was enforced:
#   1. .sops.yaml names a real age recipient (it shipped a placeholder, so
#      encryption could not work at all).
#   2. No Kubernetes Secret with plaintext data is committed. The *.example
#      files are allowed — they carry CHANGE-ME values on purpose.
set -euo pipefail

cd "$(dirname "$0")/.."

fail=0

# ── 1. recipient ──────────────────────────────────────────────────────────
# Inspect the configured recipient, not the comments around it.
configured_age="$(grep -E '^\s*age:' .sops.yaml | sed -E 's/^\s*age:\s*//; s/^.//; s/.$//' || true)"
if printf '%s' "$configured_age" | grep -q 'PLACEHOLDER'; then
  echo "ERROR: .sops.yaml names a placeholder recipient; SOPS cannot encrypt." >&2
  fail=1
fi

recipient="${NETSOLDIER_AGE_RECIPIENT:-}"
if [ -z "$recipient" ] && ! grep -qE '^\s*age:\s*.?age1[0-9a-z]{20,}' .sops.yaml; then
  echo "NOTE: no age recipient configured. Set NETSOLDIER_AGE_RECIPIENT or put the" >&2
  echo "      age1... key in .sops.yaml before encrypting secrets." >&2
fi

# ── 2. no plaintext Secrets ───────────────────────────────────────────────
while IFS= read -r file; do
  case "$file" in
    *.example.yaml|*.example.yml) continue ;;   # intentional templates
    *.sops.yaml|*.sops.yml) continue ;;         # encrypted in place
  esac
  if grep -q 'kind: Secret' "$file" && grep -qE '^\s+(data|stringData):' "$file"; then
    # An encrypted file keeps the SOPS metadata block.
    if ! grep -q 'sops:' "$file"; then
      echo "ERROR: $file is a Secret with plaintext data and is not SOPS-encrypted." >&2
      fail=1
    fi
  fi
done < <(find deploy -name '*.yaml' -o -name '*.yml' | sort)

# ── 3. every example has a CHANGE-ME, i.e. nobody shipped a real value ────
while IFS= read -r file; do
  if ! grep -qiE 'CHANGE-ME|CHANGEME|REPLACE-ME|EXAMPLE' "$file"; then
    echo "WARNING: $file looks like a filled-in example — check it carries no real secret." >&2
  fi
done < <(find deploy -name '*secret*.example.yaml' | sort)

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "OK: secret handling checks passed"
