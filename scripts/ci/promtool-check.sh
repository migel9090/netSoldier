#!/usr/bin/env bash
# Check and unit-test the Prometheus alert rules (task lint:prometheus; CI:
# static-checks).
#
#   scripts/ci/promtool-check.sh
#
# The rules ship as PrometheusRule objects (the Prometheus Operator's CRD),
# which promtool cannot read. Each tracked manifest holding one has its
# spec.groups extracted into a plain rules file, and then:
#
#   promtool check rules   every extracted file (syntax, PromQL, templates,
#                          duplicate names)
#   promtool test rules    every test file under
#                          deploy/kustomize/base/observability/tests/ (*.yaml,
#                          *.yml), when that directory exists
#
# A test's rule_files entry may name the PrometheusRule manifest itself,
# relative to the test file as usual (../prometheus-rules.yaml): the check
# swaps in the extracted groups, so the tests always judge the rules that are
# deployed. Entries naming a plain rules file are kept as they are. An
# existing tests directory with no test in it fails: it would check nothing.
#
# promtool is the pinned, checksum-verified release from tools.sh.
set -euo pipefail

REPO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$REPO_DIR"
promtool=$("$REPO_DIR/scripts/ci/tools.sh" install promtool)/promtool
TESTS_DIR=deploy/kustomize/base/observability/tests

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

python3 - "$work" "$TESTS_DIR" <<'PY'
import subprocess
import sys
from pathlib import Path

import yaml

work, tests_dir = Path(sys.argv[1]), Path(sys.argv[2])
listed = subprocess.run(["git", "ls-files", "-z", "*.yaml", "*.yml"], check=True,
                        capture_output=True, text=True).stdout.split("\0")

extracted = {}  # repo path of a PrometheusRule manifest -> plain rules file
for rel in filter(None, listed):
    try:
        docs = list(yaml.safe_load_all(Path(rel).read_text()))
    except yaml.YAMLError:
        continue
    groups = [g for d in docs if isinstance(d, dict) and d.get("kind") == "PrometheusRule"
              for g in (d.get("spec") or {}).get("groups") or []]
    if groups:
        out = work / "rules" / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(yaml.safe_dump({"groups": groups}, sort_keys=False))
        extracted[Path(rel).resolve()] = out
if not extracted:
    sys.exit("promtool-check: no PrometheusRule in any tracked manifest")
(work / "rule-files").write_text("\n".join(str(p) for p in extracted.values()) + "\n")

tests = []
if tests_dir.is_dir():
    tests = sorted(p for p in tests_dir.rglob("*") if p.suffix in (".yaml", ".yml"))
    if not tests:
        sys.exit(f"promtool-check: {tests_dir} exists but holds no test file")
for t in tests:
    doc = yaml.safe_load(t.read_text()) or {}
    files = []
    for f in doc.get("rule_files") or []:
        src = (t.parent / f).resolve()
        files.append(str(extracted.get(src, src)))
    doc["rule_files"] = files
    out = work / "tests" / t.relative_to(tests_dir)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(yaml.safe_dump(doc, sort_keys=False))
(work / "test-files").write_text("".join(f"{work / 'tests' / t.relative_to(tests_dir)}\n" for t in tests))
PY

mapfile -t rules <"$work/rule-files"
mapfile -t tests <"$work/test-files"

echo "promtool $("$promtool" --version 2>&1 | sed -n '1s/^promtool, version \([^ ]*\).*/\1/p'): check rules (${#rules[@]} files)"
"$promtool" check rules "${rules[@]}"

if ((${#tests[@]} == 0)); then
  echo "promtool-check: OK (no $TESTS_DIR yet, so no rule tests ran)"
  exit 0
fi
echo "promtool: test rules (${#tests[@]} files from $TESTS_DIR)"
# promtool resolves paths in a test file against its own directory; the
# rewritten files carry absolute paths, so the copy can live anywhere.
"$promtool" test rules "${tests[@]}"
echo "promtool-check: OK"
