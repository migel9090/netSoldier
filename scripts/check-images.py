#!/usr/bin/env python3
"""Verify every first-party image the manifests reference is built by CI.

    python3 scripts/check-images.py          (task check:images; CI: validate)

Four of the seven ghcr.io/migel9090/* images referenced by the manifests had
no Dockerfile and no build job. Those workloads could never start, and
Kyverno's verifyImages policy (validationFailureAction: Enforce) would have
rejected them for being unsigned even if they had existed — so the whole
response capability was undeployable while every YAML file still validated.
netagent then repeated it: referenced by the core profile and the lite
profile, built by no job.

"Built by CI" means all of it, for each referenced image:
  - a Dockerfile (apps/<name>/ or deploy/docker/<name>/);
  - a job in .github/workflows/ci.yml whose docker/metadata-action names the
    image and whose docker/build-push-action builds that Dockerfile;
  - the same job signs the image with cosign;
  - a provenance job (the SLSA generator) for the image that needs that job.

Manifests are everything under deploy/ that can name an image (Kubernetes
YAML, Helm values, the lite profile's Quadlet units) and the lab's
standalone manifests under infra/lab/. The check fails when it finds no
first-party reference or no build job at all: a pattern that silently
stopped matching would otherwise pass by checking nothing.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
OWNER_PREFIX = "ghcr.io/migel9090/"
CI = ROOT / ".github" / "workflows" / "ci.yml"
MANIFEST_DIRS = [ROOT / "deploy", ROOT / "infra" / "lab"]
MANIFEST_SUFFIXES = {".yaml", ".yml", ".container", ".tmpl"}

# A concrete image name after the owner prefix (a glob such as the Kyverno
# policy's ghcr.io/migel9090/* is not a reference).
IMAGE_RE = re.compile(re.escape(OWNER_PREFIX) + r"([a-z0-9][a-z0-9._-]*)")
JOB_IMAGE_RE = re.compile(
    r"^ghcr\.io/\$\{\{\s*github\.repository_owner\s*\}\}/([a-z0-9][a-z0-9._-]*)$"
)


def referenced_images() -> dict[str, set[Path]]:
    """First-party image names referenced by any manifest."""
    found: dict[str, set[Path]] = {}
    for base in MANIFEST_DIRS:
        for path in sorted(base.rglob("*")):
            if not path.is_file() or path.suffix not in MANIFEST_SUFFIXES:
                continue
            for match in IMAGE_RE.finditer(path.read_text(errors="replace")):
                found.setdefault(match.group(1), set()).add(path.relative_to(ROOT))
    return found


def dockerfiles() -> dict[str, Path]:
    """Image name -> its Dockerfile.

    apps/<name>/Dockerfile covers the services; deploy/docker/<name> covers
    the sidecar images (zeek).
    """
    found = {p.parent.name: p for p in ROOT.joinpath("apps").glob("*/Dockerfile")}
    found |= {p.parent.name: p for p in ROOT.joinpath("deploy", "docker").glob("*/Dockerfile")}
    return found


def uses(step: dict, action: str) -> bool:
    return str(step.get("uses", "")).split("@")[0] == action


def build_jobs(jobs: dict) -> tuple[dict[str, tuple[str, dict]], list[str]]:
    """Image name -> (job id, job) for every job that builds an image, and problems."""
    built: dict[str, tuple[str, dict]] = {}
    problems: list[str] = []
    for job_id, job in jobs.items():
        steps = job.get("steps") or []
        meta = [s for s in steps if uses(s, "docker/metadata-action")]
        if not meta:
            continue
        images = str((meta[0].get("with") or {}).get("images", "")).strip()
        m = JOB_IMAGE_RE.match(images)
        if not m:
            problems.append(
                f"job {job_id}: metadata-action images {images!r} is not ghcr.io/<owner>/<name>"
            )
            continue
        name = m.group(1)
        if name in built:
            problems.append(f"{name}: built by two jobs, {built[name][0]} and {job_id}")
        built[name] = (job_id, job)
    return built, problems


def check_job(
    name: str, job_id: str, job: dict, dockerfile: Path | None, provenance: dict[str, str]
) -> list[str]:
    steps = job.get("steps") or []
    problems: list[str] = []
    builds = [s for s in steps if uses(s, "docker/build-push-action")]
    if not builds:
        problems.append(f"{name}: job {job_id} has no docker/build-push-action step")
    else:
        w = builds[0].get("with") or {}
        context = ROOT / str(w.get("context", "."))
        file = ROOT / str(w["file"]) if "file" in w else context / "Dockerfile"
        if not file.is_file():
            problems.append(
                f"{name}: job {job_id} builds {file.relative_to(ROOT)}, which does not exist"
            )
        elif dockerfile and file.resolve() != dockerfile.resolve():
            built, expected = file.relative_to(ROOT), dockerfile.relative_to(ROOT)
            problems.append(f"{name}: job {job_id} builds {built}, not {expected}")
    signs = [
        s
        for s in steps
        if "cosign sign" in str(s.get("run", "")) and f"/{name}@" in str(s.get("run", ""))
    ]
    if not signs:
        problems.append(f"{name}: job {job_id} does not sign the image with cosign")
    if provenance.get(name) != job_id:
        problems.append(f"{name}: no provenance job for the image built by {job_id}")
    return problems


def provenance_jobs(jobs: dict) -> dict[str, str]:
    """Image name -> the build job its SLSA provenance job needs."""
    found: dict[str, str] = {}
    for job in jobs.values():
        if "slsa-framework/slsa-github-generator" not in str(job.get("uses", "")):
            continue
        m = JOB_IMAGE_RE.match(str((job.get("with") or {}).get("image", "")).strip())
        needs = job.get("needs")
        needs = [needs] if isinstance(needs, str) else list(needs or [])
        if m and len(needs) == 1:
            found[m.group(1)] = needs[0]
    return found


def main() -> int:
    referenced = referenced_images()
    if not referenced:
        print(
            "no first-party image is referenced by any manifest: the pattern no longer matches",
            file=sys.stderr,
        )
        return 1

    jobs = (yaml.safe_load(CI.read_text()) or {}).get("jobs") or {}
    built, failures = build_jobs(jobs)
    if not built:
        print(
            f"no image build job found in {CI.relative_to(ROOT)}: the parser no longer matches",
            file=sys.stderr,
        )
        return 1
    have_dockerfile = dockerfiles()
    provenance = provenance_jobs(jobs)

    for name in sorted(referenced):
        where = ", ".join(sorted(str(p) for p in referenced[name]))
        if name not in have_dockerfile:
            failures.append(f"{name}: referenced by {where} but has no Dockerfile")
        if name not in built:
            failures.append(f"{name}: referenced by {where} but no CI job builds and signs it")
            continue
        job_id, job = built[name]
        failures += check_job(name, job_id, job, have_dockerfile.get(name), provenance)

    for name in sorted(set(built) - set(referenced)):
        print(f"note: {name} is built by CI but not referenced by any manifest")

    if failures:
        print("\nFirst-party images that cannot be deployed:", file=sys.stderr)
        for line in failures:
            print(f"  - {line}", file=sys.stderr)
        return 1

    print(
        f"OK: all {len(referenced)} first-party images have a Dockerfile, a build, "
        "a signature and provenance:"
    )
    for name in sorted(referenced):
        print(f"  {name}: {built[name][0]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
