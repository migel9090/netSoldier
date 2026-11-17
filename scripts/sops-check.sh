#!/usr/bin/env bash
# Verify that the secret-handling story holds (task scan:sops; CI: the
# sops-check job of .github/workflows/secret-scan.yml).
#
#   scripts/sops-check.sh
#
# 1. .sops.yaml names real age recipients. Every creation rule needs at
#    least one literal age1... recipient; a placeholder or a ${VARIABLE}
#    (SOPS does not expand variables) means `sops -e` fails on a fresh clone.
# 2. No Kubernetes Secret with readable data is committed: in any tracked
#    YAML or JSON file, a Secret's data/stringData must be SOPS-encrypted
#    (every value ENC[...] and a sops block with a MAC). *.example.* files
#    may hold plaintext only if it is visibly a placeholder; a *.sops.yaml
#    that is not encrypted is an error, not a skip.
# 3. Nothing deploys an example or a committed plaintext: no kustomization
#    references an *.example.* file, and no secretGenerator takes literals
#    or reads a tracked file.
#
# The previous version matched `^\s+data:`, which an ordinary Secret's
# top-level `data:` never matches, so a plaintext Secret passed; it skipped
# every *.sops.yaml unread, accepted any file containing the word "sops:",
# and only looked under deploy/. Nothing ran it.
#
# A known gap can be waived like a scanner finding, in scan-exceptions.toml
# with a reason and a review date: tool "sops", rule "recipient" (check 1),
# "plaintext" or "deploys-example" (checks 2 and 3), files = [...].
#
# Needs Python 3.11+ with PyYAML (scripts/ci/requirements.txt).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
exec python3 - "$@" <<'PY'
import datetime as dt
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import yaml

ROOT = Path.cwd()
RECIPIENT = re.compile(r"^age1[02-9ac-hj-np-z]{58}$")  # bech32, X25519
ENC = re.compile(r"^ENC\[[A-Z0-9_]+,data:.*\]$", re.S)
PLACEHOLDER = re.compile(r"change-?me|replace|example|x{8,}|^$", re.I)
TODAY = dt.datetime.now(dt.UTC).date()

errors: list[tuple[str, str, str]] = []  # (rule, file, message)


def tracked() -> list[str]:
    out = subprocess.run(["git", "ls-files", "-z"], check=True, capture_output=True, text=True)
    return [p for p in out.stdout.split("\0") if p]


def waivers() -> dict[tuple[str, str], tuple[dt.date, str]]:
    """(rule, file) -> (until, reason) for the active tool = "sops" entries."""
    data = tomllib.loads((ROOT / "scan-exceptions.toml").read_text())
    out = {}
    for e in data.get("exception", []):
        if e.get("tool") != "sops":
            continue
        until = e.get("until")
        if not isinstance(until, dt.date) or len(str(e.get("reason", "")).split()) < 8:
            sys.exit(f"scan-exceptions.toml: sops exception {e.get('rule')} needs until and a reason")
        for f in e.get("files", []):
            out[(e["rule"], f)] = (until, e["reason"])
    return out


def documents(path: Path):
    text = path.read_text(errors="replace")
    if path.suffix == ".json":
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            return
        yield from (doc if isinstance(doc, list) else [doc])
        return
    try:
        yield from yaml.safe_load_all(text)
    except yaml.YAMLError:
        return  # templates and other non-YAML; YAML syntax is validate's job


def objects(doc):
    if isinstance(doc, dict):
        yield doc
        if doc.get("kind") == "List":
            for item in doc.get("items") or []:
                yield from objects(item)


# ── 1. recipients ────────────────────────────────────────────────────────────
try:
    sops_cfg = yaml.safe_load((ROOT / ".sops.yaml").read_text()) or {}
except FileNotFoundError:
    sops_cfg = {}
rules = sops_cfg.get("creation_rules") or []
if not rules:
    errors.append(("recipient", ".sops.yaml", "no creation_rules: SOPS has nothing to encrypt with"))
for i, rule in enumerate(rules, start=1):
    age = rule.get("age", "")
    recips = [r.strip() for r in (age if isinstance(age, list) else str(age).split(",")) if r.strip()]
    bad = [r for r in recips if not RECIPIENT.match(r)]
    if not recips or bad:
        what = ", ".join(bad) or "nothing"
        errors.append((
            "recipient",
            ".sops.yaml",
            f"creation rule {i} ({rule.get('path_regex', 'any path')}) names {what} as age "
            "recipient; SOPS needs literal age1... keys and does not expand variables",
        ))

files = tracked()

# ── 2. plaintext Secrets ─────────────────────────────────────────────────────
checked = 0
for rel in files:
    if not rel.endswith((".yaml", ".yml", ".json")) or "/templates/" in rel:
        continue
    path = ROOT / rel
    if not path.is_file():
        continue
    example = ".example." in Path(rel).name
    for doc in documents(path):
        for obj in objects(doc):
            if obj.get("kind") != "Secret":
                continue
            values = {
                f"{k}.{key}": v
                for k in ("data", "stringData")
                for key, v in ((obj.get(k) or {}) if isinstance(obj.get(k), dict) else {}).items()
            }
            if not values:
                continue
            checked += 1
            name = (obj.get("metadata") or {}).get("name", "?")
            sops_meta = doc.get("sops") if isinstance(doc, dict) else None
            encrypted = isinstance(sops_meta, dict) and sops_meta.get("mac") and all(
                isinstance(v, str) and ENC.match(v) for v in values.values()
            )
            if encrypted:
                continue
            if example:
                if not any(isinstance(v, str) and PLACEHOLDER.search(v) for v in values.values()):
                    errors.append(("plaintext", rel, f"Secret {name}: an example with no visible placeholder (CHANGE-ME, REPLACE..., empty)"))
                continue
            plain = sorted(k for k, v in values.items() if not (isinstance(v, str) and ENC.match(v)))
            hint = " (a *.sops.yaml file that was never encrypted)" if ".sops." in rel else ""
            errors.append(("plaintext", rel, f"Secret {name} has readable values{hint}: {', '.join(plain)}"))

# ── 3. what kustomize would deploy ───────────────────────────────────────────
tracked_set = set(files)
for rel in files:
    if Path(rel).name not in ("kustomization.yaml", "kustomization.yml", "Kustomization"):
        continue
    base = Path(rel).parent
    try:
        k = yaml.safe_load((ROOT / rel).read_text()) or {}
    except yaml.YAMLError:
        continue
    refs = []
    for key in ("resources", "components", "generators", "transformers", "patchesStrategicMerge"):
        refs += [r for r in k.get(key) or [] if isinstance(r, str)]
    refs += [p["path"] for p in k.get("patches") or [] if isinstance(p, dict) and "path" in p]
    for ref in refs:
        if ".example." in Path(ref).name:
            errors.append(("deploys-example", rel, f"deploys the example {ref}; examples document keys, they are never applied"))
    for gen in k.get("secretGenerator") or []:
        gname = gen.get("name", "?")
        if gen.get("literals"):
            errors.append(("plaintext", rel, f"secretGenerator {gname} has literals: the values are committed"))
        for src in [*(gen.get("files") or []), *(gen.get("envs") or []), *([gen["env"]] if gen.get("env") else [])]:
            target = str(src).split("=", 1)[-1]
            if (base / target).as_posix() in tracked_set:
                errors.append(("plaintext", rel, f"secretGenerator {gname} reads {target}, which is committed"))

if checked == 0:
    errors.append(("plaintext", "-", "no Secret found in any tracked file: the check would judge nothing"))

# ── verdict ──────────────────────────────────────────────────────────────────
active = waivers()
failed = 0
for rule, rel, msg in errors:
    w = active.get((rule, rel))
    if w and w[0] >= TODAY:
        print(f"::warning file={rel},title=sops-check {rule} (waived until {w[0]})::{msg}")
        continue
    lapsed = f" (waiver expired on {w[0]})" if w else ""
    print(f"::error file={rel},title=sops-check {rule}::{msg}{lapsed}")
    failed += 1

if failed:
    print(f"sops-check: FAILED ({failed} problem(s))")
    sys.exit(1)
print(f"sops-check: OK ({checked} Secret objects in tracked files checked)")
PY
