#!/usr/bin/env python3
"""Branch protection of main as code: compare or apply .github/branch-protection.json.

    scripts/ci/branch-protection.py --check [--repo OWNER/NAME]
    scripts/ci/branch-protection.py --print
    scripts/ci/branch-protection.py --apply [--repo OWNER/NAME] [--yes]

--check  reads the live protection through the GitHub API (read-only; it
         needs a token with administration read access, as `gh` has for a
         repository admin) and lists every difference; exit 1 when there is
         one. `task ci:branch-protection`.
--print  prints the request body --apply would send.
--apply  replaces main's protection with the file's (PUT .../protection).
         For the owners to run; it asks first unless --yes is given.

Uses the gh CLI for the API calls. The repository defaults to the one gh
sees in the current directory.

What the file sets (roadmap 125.2): every required check in its one list,
branches up to date before merging, a pull request with one approving review
(stale approvals dismissed), enforced for administrators too, no force
pushes and no deletion of main. Code-owner review is not required: with two
maintainers who each own half the tree, a pull request touching an author's
own half would need a second owner of that half, which does not exist, and
could never merge. The one required approval is always the other maintainer,
and .github/CODEOWNERS makes GitHub request the right one.

The merge methods (squash only, as CONTRIBUTING.md says) are a repository
setting outside this file; --check prints them for information.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / ".github" / "branch-protection.json"


def gh(args: list[str], body: dict | None = None) -> tuple[int, str]:
    argv = ["gh", *args]
    proc = subprocess.run(  # noqa: S603
        argv,
        input=json.dumps(body) if body is not None else None,
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout if proc.returncode == 0 else proc.stderr


def load_spec() -> tuple[str, dict, list[tuple[str, int]]]:
    spec = json.loads(SPEC.read_text())
    checks: list[tuple[str, int]] = []
    for source in spec["required_checks"].values():
        app = source["app_id"]
        for key, names in source.items():
            if key != "app_id":
                checks += [(n, app) for n in names]
    dupes = sorted({c for c in checks if checks.count(c) > 1})
    if dupes:
        sys.exit(f"{SPEC.name}: listed twice: {dupes}")
    return spec["branch"], spec["protection"], checks


def body(protection: dict, checks: list[tuple[str, int]]) -> dict:
    out = json.loads(json.dumps(protection))
    out["required_status_checks"]["checks"] = [{"context": n, "app_id": a} for n, a in checks]
    return out


def live_state(repo: str, branch: str) -> dict | None:
    rc, out = gh(["api", f"repos/{repo}/branches/{branch}/protection"])
    if rc != 0:
        if "Branch not protected" in out:
            return None
        sys.exit(f"cannot read the protection of {repo}:{branch}: {out.strip()}")
    return json.loads(out)


def compare(want: dict, live: dict | None) -> list[str]:
    if live is None:
        return ["main is not protected at all"]
    diffs: list[str] = []
    lrsc = live.get("required_status_checks") or {}
    want_checks = {(c["context"], c["app_id"]) for c in want["required_status_checks"]["checks"]}
    live_checks = {(c["context"], c.get("app_id")) for c in lrsc.get("checks", [])}
    for name, app in sorted(want_checks - live_checks):
        diffs.append(f"required check missing: {name} (app {app})")
    for name, app in sorted(live_checks - want_checks):
        diffs.append(f"required check not in the file: {name} (app {app})")
    if bool(lrsc.get("strict")) != want["required_status_checks"]["strict"]:
        diffs.append(f"strict (up to date before merge): live {lrsc.get('strict')}, want True")
    if (live.get("enforce_admins") or {}).get("enabled") != want["enforce_admins"]:
        diffs.append("enforce_admins: live false, want true (admins bypass protection)")
    wr, lr = want["required_pull_request_reviews"], live.get("required_pull_request_reviews")
    if lr is None:
        diffs.append("no pull request required (direct pushes to main are possible)")
    else:
        for k, v in wr.items():
            if lr.get(k) != v:
                diffs.append(f"required_pull_request_reviews.{k}: live {lr.get(k)}, want {v}")
    if (live.get("restrictions") is None) != (want["restrictions"] is None):
        diffs.append("push restrictions differ")
    for k in ("required_linear_history", "allow_force_pushes", "allow_deletions"):
        lv = (live.get(k) or {}).get("enabled")
        if lv != want[k]:
            diffs.append(f"{k}: live {lv}, want {want[k]}")
    return diffs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--print", action="store_true")
    mode.add_argument("--apply", action="store_true")
    ap.add_argument("--repo", help="OWNER/NAME (default: the repository gh sees here)")
    ap.add_argument("--yes", action="store_true", help="apply without asking")
    args = ap.parse_args()

    branch, protection, checks = load_spec()
    want = body(protection, checks)
    if args.print:
        print(json.dumps(want, indent=2))
        return 0

    repo = args.repo
    if not repo:
        rc, out = gh(["repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"])
        if rc != 0:
            sys.exit(f"cannot tell the repository: {out.strip()} (use --repo)")
        repo = out.strip()

    if args.check:
        diffs = compare(want, live_state(repo, branch))
        methods = (
            "{squash: .allow_squash_merge, merge: .allow_merge_commit, "
            "rebase: .allow_rebase_merge}"
        )
        rc, out = gh(["api", f"repos/{repo}", "--jq", methods])
        if rc == 0:
            print(f"merge methods on {repo} (information, not checked): {out.strip()}")
        if not diffs:
            print(f"{repo}:{branch}: protection matches {SPEC.relative_to(ROOT)}")
            return 0
        print(f"{repo}:{branch}: {len(diffs)} difference(s) from {SPEC.relative_to(ROOT)}:")
        for d in diffs:
            print(f"  - {d}")
        return 1

    print(json.dumps(want, indent=2))
    if not args.yes:
        answer = input(f"Replace the protection of {repo}:{branch} with the above? [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            print("not applied")
            return 1
    rc, out = gh(
        ["api", "--method", "PUT", f"repos/{repo}/branches/{branch}/protection", "--input", "-"],
        want,
    )
    if rc != 0:
        sys.exit(f"apply failed: {out.strip()}")
    print(f"{repo}:{branch}: protection applied")
    return 0


if __name__ == "__main__":
    sys.exit(main())
