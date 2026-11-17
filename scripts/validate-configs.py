#!/usr/bin/env python3
"""Validate deploy configurations (task validate:configs; CI: validate).

    python3 scripts/validate-configs.py

1. YAML syntax of everything under deploy/.
2. Helm values against their schemas.
3. The clickhouse-migrations ConfigMap generator lists exactly the files in
   deploy/clickhouse/migrations/. kustomize has no globs, so a migration that
   is in the directory but not in the list never reaches the cluster, and a
   listed file that is gone breaks the render (DP-15).
4. No home-network value outside deploy/kustomize/sites/ (roadmap 125.12):
   the owner's LAN prefix and capture interface (HOME_NETWORK below) may
   appear only in a site, in an example file, in tests and their fixtures,
   and in the dated audit records. A
   value that depends on the household belongs to its site. Known offenders
   can be waived with a reason and a review date in scan-exceptions.toml
   (tool "validate", rule "home-network", files = [...]).
"""

import datetime as dt
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import yaml

try:
    from jsonschema import Draft7Validator
except ImportError:
    sys.exit("Missing dependency: pip install jsonschema")

ROOT = Path(__file__).resolve().parent.parent

HOME_NETWORK = re.compile(r"192\.168\.1\.|\beth1\b")
# Where a household value may appear. Paths are repository-relative.
HOME_NETWORK_ALLOWED = [
    re.compile(p)
    for p in (
        r"^deploy/kustomize/sites/",  # a site is where these values live
        r"\.example(\.|$)",  # example files show what a site sets
        r"(^|/)tests?/",  # test code and its fixtures
        r"(^|/)testing/",
        r"_test\.go$",
        r"\.(test|spec)\.ts$",
        r"(^|/)test_[^/]*\.py$",
        r"^detections/pcap-corpus/",  # synthetic captures, pinned by sha256
        r"^docs/audits/",  # dated audit records quote what they found
    )
]


def validate_yaml_syntax(deploy_dir):
    errors = []
    for p in sorted(deploy_dir.rglob("*.yaml")):
        if "/templates/" in str(p):
            continue
        try:
            with open(p) as f:
                list(yaml.safe_load_all(f))
        except yaml.YAMLError as e:
            errors.append(f"{p.relative_to(ROOT)}: {e}")
    return errors


def deep_merge(base, override):
    result = dict(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def validate_helm_chart(chart_dir):
    schema_path = chart_dir / "values.schema.json"
    if not schema_path.exists():
        return []

    with open(schema_path) as f:
        schema = json.load(f)
    validator = Draft7Validator(schema)

    base_path = chart_dir / "values.yaml"
    if not base_path.exists():
        return [f"{chart_dir.relative_to(ROOT)}: missing values.yaml"]

    with open(base_path) as f:
        base_values = yaml.safe_load(f) or {}

    errors = []

    for err in validator.iter_errors(base_values):
        path = ".".join(str(x) for x in err.absolute_path) or "(root)"
        errors.append(f"{base_path.relative_to(ROOT)} [{path}]: {err.message}")

    for vf in sorted(chart_dir.glob("values-*.yaml")):
        with open(vf) as f:
            override = yaml.safe_load(f) or {}
        merged = deep_merge(base_values, override)
        for err in validator.iter_errors(merged):
            path = ".".join(str(x) for x in err.absolute_path) or "(root)"
            errors.append(f"{vf.relative_to(ROOT)} [{path}]: {err.message}")

    return errors


def validate_migration_list():
    """The clickhouse-migrations generator lists exactly migrations/*.sql."""
    kfile = ROOT / "deploy" / "clickhouse" / "kustomization.yaml"
    rel = kfile.relative_to(ROOT)
    k = yaml.safe_load(kfile.read_text()) or {}
    gens = [
        g for g in k.get("configMapGenerator") or [] if g.get("name") == "clickhouse-migrations"
    ]
    if len(gens) != 1:
        return [f"{rel}: expected one configMapGenerator named clickhouse-migrations"]
    # A files entry may be `key=path`; the path is what has to exist.
    listed = [str(f).split("=", 1)[-1] for f in gens[0].get("files") or []]
    on_disk = sorted(
        p.relative_to(kfile.parent).as_posix() for p in kfile.parent.glob("migrations/*.sql")
    )
    errors = []
    if not on_disk:
        errors.append(f"{rel}: no migrations/*.sql next to it")
    for f in sorted({f for f in listed if listed.count(f) > 1}):
        errors.append(f"{rel}: {f} is listed twice")
    for f in sorted(set(on_disk) - set(listed)):
        errors.append(f"{rel}: {f} is not listed, so it never reaches the cluster")
    for f in sorted(set(listed) - set(on_disk)):
        errors.append(f"{rel}: lists {f}, which does not exist (or is not a .sql)")
    return errors


def home_network_waivers(today):
    """file -> review date of the active tool = "validate" home-network entries."""
    data = tomllib.loads((ROOT / "scan-exceptions.toml").read_text())
    out = {}
    for e in data.get("exception", []):
        if e.get("tool") == "validate" and e.get("rule") == "home-network":
            for f in e.get("files", []):
                out[f] = e["until"]
    return {f: d for f, d in out.items() if d >= today}, {
        f: d for f, d in out.items() if d < today
    }


def validate_home_network():
    """(errors, warnings) for household values outside sites/ and examples."""
    argv = ["git", "-C", str(ROOT), "ls-files", "-z"]
    listed = subprocess.run(argv, check=True, capture_output=True, text=True).stdout  # noqa: S603
    today = dt.datetime.now(dt.UTC).date()
    waived, lapsed = home_network_waivers(today)
    errors, warnings, hit = [], [], set()
    for rel in sorted(p for p in listed.split("\0") if p):
        if any(rx.search(rel) for rx in HOME_NETWORK_ALLOWED):
            continue
        path = ROOT / rel
        if not path.is_file():
            continue
        data = path.read_bytes()
        if b"\0" in data:
            continue
        lines = [
            n
            for n, line in enumerate(data.decode(errors="replace").splitlines(), start=1)
            if HOME_NETWORK.search(line)
        ]
        if not lines:
            continue
        hit.add(rel)
        where = "{}:{}".format(
            rel, ",".join(map(str, lines[:8])) + (",..." if len(lines) > 8 else "")
        )
        if rel in waived:
            warnings.append(f"{where} (waived until {waived[rel]})")
        else:
            note = f" (waiver expired on {lapsed[rel]})" if rel in lapsed else ""
            errors.append(
                f"{where}: a home-network value ({HOME_NETWORK.pattern}) outside "
                f"deploy/kustomize/sites/{note}"
            )
    for rel in sorted(set(waived) - hit):
        warnings.append(f"{rel}: waived but clean now; drop it from scan-exceptions.toml")
    return errors, warnings


def main():
    deploy_dir = ROOT / "deploy"
    all_errors = []

    print("==> YAML syntax check")
    yaml_errors = validate_yaml_syntax(deploy_dir)
    all_errors.extend(yaml_errors)
    for e in yaml_errors:
        print(f"  FAIL {e}")
    if not yaml_errors:
        count = sum(1 for p in deploy_dir.rglob("*.yaml") if "/templates/" not in str(p))
        print(f"  OK ({count} files)")

    print("\n==> Helm values schema validation")
    charts = [
        deploy_dir / "helm" / "netsoldier",
        deploy_dir / "helm" / "netsoldier" / "charts" / "detection-engine",
    ]
    for chart_dir in charts:
        helm_errors = validate_helm_chart(chart_dir)
        all_errors.extend(helm_errors)
        for e in helm_errors:
            print(f"  FAIL {e}")
        if not helm_errors:
            n = len(list(chart_dir.glob("values*.yaml")))
            print(f"  OK {chart_dir.relative_to(ROOT)} ({n} values file(s))")

    print("\n==> ClickHouse migration list")
    mig_errors = validate_migration_list()
    all_errors.extend(mig_errors)
    for e in mig_errors:
        print(f"  FAIL {e}")
    if not mig_errors:
        print("  OK (deploy/clickhouse/kustomization.yaml lists every migration)")

    print("\n==> Home-network values outside deploy/kustomize/sites/")
    net_errors, net_warnings = validate_home_network()
    all_errors.extend(net_errors)
    for e in net_errors:
        print(f"  FAIL {e}")
    for w in net_warnings:
        print(f"  WARN {w}")
    if not net_errors:
        print("  OK")

    if all_errors:
        print(f"\n{len(all_errors)} error(s)")
        return 1

    print("\nAll config validations passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
