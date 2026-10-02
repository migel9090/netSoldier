#!/usr/bin/env python3
"""Verify every first-party image in deploy/ is actually built by CI.

Four of the seven ghcr.io/migel9090/* images referenced by the manifests had
no Dockerfile and no build job. Those workloads could never start, and
Kyverno's verifyImages policy (validationFailureAction: Enforce) would have
rejected them for being unsigned even if they had existed — so the whole
response capability was undeployable while every YAML file still validated.
This check closes that gap in CI rather than in a future audit.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OWNER_PREFIX = "ghcr.io/migel9090/"

IMAGE_RE = re.compile(r"image:\s*[\"']?(" + re.escape(OWNER_PREFIX) + r"[^\"'\s:@]+)")


def referenced_images() -> dict[str, set[Path]]:
    """First-party image names referenced anywhere under deploy/."""
    found: dict[str, set[Path]] = {}
    for path in sorted(ROOT.joinpath("deploy").rglob("*.yaml")):
        for match in IMAGE_RE.finditer(path.read_text()):
            name = match.group(1).removeprefix(OWNER_PREFIX)
            found.setdefault(name, set()).add(path.relative_to(ROOT))
    return found


def dockerfiles() -> set[str]:
    """Image names that have a Dockerfile.

    apps/<name>/Dockerfile covers the services; deploy/docker/<name> covers
    the sidecar images (zeek).
    """
    names = {p.parent.name for p in ROOT.joinpath("apps").glob("*/Dockerfile")}
    names |= {p.parent.name for p in ROOT.joinpath("deploy", "docker").glob("*/Dockerfile")}
    return names


def build_jobs() -> set[str]:
    """Image names that a CI build job pushes."""
    ci = ROOT.joinpath(".github", "workflows", "ci.yml").read_text()
    return {
        m.group(1)
        for m in re.finditer(r"images:\s*ghcr\.io/\$\{\{\s*github\.repository_owner\s*\}\}/(\S+)", ci)
    }


def main() -> int:
    referenced = referenced_images()
    if not referenced:
        print("no first-party images referenced — check the image regex", file=sys.stderr)
        return 1

    have_dockerfile = dockerfiles()
    have_job = build_jobs()
    failures: list[str] = []

    for name in sorted(referenced):
        where = ", ".join(sorted(str(p) for p in referenced[name]))
        if name not in have_dockerfile:
            failures.append(f"{name}: referenced by {where} but has no Dockerfile")
        if name not in have_job:
            failures.append(f"{name}: referenced by {where} but no CI job builds/signs it")

    for name in sorted(have_job - set(referenced)):
        print(f"note: {name} is built by CI but not referenced by any manifest")

    if failures:
        print("\nFirst-party images that cannot be deployed:", file=sys.stderr)
        for line in failures:
            print(f"  - {line}", file=sys.stderr)
        return 1

    print(f"OK: all {len(referenced)} first-party images have a Dockerfile and a build job")
    return 0


if __name__ == "__main__":
    sys.exit(main())
