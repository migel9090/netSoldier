#!/usr/bin/env bash
# ShellCheck every tracked shell script (task lint:shell; CI: static-checks).
#
#   scripts/ci/lint-shell.sh [FILE...]
#
# Without arguments: every tracked file ending in .sh or .bash, or starting
# with a shell shebang (deploy/podman/netsoldier-lite has no extension), so a
# new script is covered without anyone adding it to a list. Jinja templates
# (*.j2) are not shell until Ansible renders them and are left out.
#
# Gates on ShellCheck's error and warning levels; info and style notes are
# printed by `shellcheck -x FILE` for whoever wants them, but do not fail
# the job. Sourced files are followed (-x) from the repository root, which
# is what the scripts' `# shellcheck source=` directives are relative to.
# ShellCheck itself is the pinned, checksum-verified release from tools.sh.
set -euo pipefail

REPO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$REPO_DIR"
shellcheck=$("$REPO_DIR/scripts/ci/tools.sh" install shellcheck)/shellcheck

files=()
if (($#)); then
  files=("$@")
else
  while IFS= read -r -d '' f; do
    [[ -f $f && $f != *.j2 ]] || continue
    case $f in
      *.sh | *.bash) files+=("$f") ;;
      *)
        first=$(head -n1 -- "$f" 2>/dev/null | tr -d '\0') || true
        [[ $first =~ ^#!.*(/|env\ )(ba|da|k)?sh([[:space:]]|$) ]] && files+=("$f")
        ;;
    esac
  done < <(git ls-files -z)
fi
# A pattern that stopped matching must not pass by checking nothing.
((${#files[@]})) || { echo "lint-shell: no shell script found" >&2; exit 1; }

echo "shellcheck $("$shellcheck" --version | sed -n 's/^version: //p'): ${#files[@]} files"
if "$shellcheck" -x --severity=warning -f gcc "${files[@]}"; then
  echo "lint-shell: OK"
else
  echo "lint-shell: FAILED (fix the warnings above; \`shellcheck -x FILE\` explains each code)" >&2
  exit 1
fi
