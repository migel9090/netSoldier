#!/usr/bin/env python3
"""Validate deploy configurations: YAML syntax + Helm values schemas."""

import json
import sys
from pathlib import Path

import yaml

try:
    from jsonschema import Draft7Validator
except ImportError:
    sys.exit("Missing dependency: pip install jsonschema")

ROOT = Path(__file__).resolve().parent.parent


def validate_yaml_syntax(deploy_dir):
    errors = []
    for p in sorted(deploy_dir.rglob("*.yaml")):
        if "/templates/" in str(p):
            continue
        try:
            with open(p) as f:
                list(yaml.safe_load_all(f))
        except yaml.YAMLError as e:
            errors.append("{}: {}".format(p.relative_to(ROOT), e))
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
        return ["{}: missing values.yaml".format(chart_dir.relative_to(ROOT))]

    with open(base_path) as f:
        base_values = yaml.safe_load(f) or {}

    errors = []

    for err in validator.iter_errors(base_values):
        path = ".".join(str(x) for x in err.absolute_path) or "(root)"
        errors.append("{} [{}]: {}".format(base_path.relative_to(ROOT), path, err.message))

    for vf in sorted(chart_dir.glob("values-*.yaml")):
        with open(vf) as f:
            override = yaml.safe_load(f) or {}
        merged = deep_merge(base_values, override)
        for err in validator.iter_errors(merged):
            path = ".".join(str(x) for x in err.absolute_path) or "(root)"
            errors.append("{} [{}]: {}".format(vf.relative_to(ROOT), path, err.message))

    return errors


def main():
    deploy_dir = ROOT / "deploy"
    all_errors = []

    print("==> YAML syntax check")
    yaml_errors = validate_yaml_syntax(deploy_dir)
    all_errors.extend(yaml_errors)
    for e in yaml_errors:
        print("  FAIL {}".format(e))
    if not yaml_errors:
        count = sum(1 for p in deploy_dir.rglob("*.yaml") if "/templates/" not in str(p))
        print("  OK ({} files)".format(count))

    print("\n==> Helm values schema validation")
    charts = [
        deploy_dir / "helm" / "netsoldier",
        deploy_dir / "helm" / "netsoldier" / "charts" / "detection-engine",
    ]
    for chart_dir in charts:
        helm_errors = validate_helm_chart(chart_dir)
        all_errors.extend(helm_errors)
        for e in helm_errors:
            print("  FAIL {}".format(e))
        if not helm_errors:
            n = len(list(chart_dir.glob("values*.yaml")))
            print("  OK {} ({} values file(s))".format(chart_dir.relative_to(ROOT), n))

    if all_errors:
        print("\n{} error(s)".format(len(all_errors)))
        return 1

    print("\nAll config validations passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
