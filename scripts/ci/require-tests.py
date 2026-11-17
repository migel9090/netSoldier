#!/usr/bin/env python3
"""Fail unless named Go tests actually ran and passed.

    go test -v ... 2>&1 | tee e2e.log
    python3 scripts/ci/require-tests.py e2e.log TestNetagentNamespaceE2E [...]

A test that calls t.Skip passes `go test`, so a gate whose environment
cannot run it stays green while proving nothing. That is what happened to
tests/e2e/netagent_ns_test.go, the ADR-0004 proof that device-inventory works
with every capability dropped: GitHub's Ubuntu runners confine unprivileged
user namespaces with AppArmor, `unshare -Urn` fails, and every CI run logged
"--- SKIP: TestNetagentNamespaceE2E" under a green job.

Reads the log of `go test -v` (text) or `go test -json` and exits 1 when a
named test is missing, skipped or failed; a skip's reason is printed. Each
name is a top-level test; a subtest is written Parent/Child, as Go prints it.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

RESULT = re.compile(r"^\s*--- (PASS|FAIL|SKIP): (\S+) \(")


def outcomes(log: str) -> tuple[dict[str, str], dict[str, list[str]]]:
    """test -> last outcome, and test -> its output lines (for skip reasons)."""
    result: dict[str, str] = {}
    output: dict[str, list[str]] = {}
    current = None
    for line in log.splitlines():
        # GitHub's downloaded logs prefix each line with job, step and time.
        text = line.split("\t", 2)[-1] if line.count("\t") >= 2 else line
        text = re.sub(r"^\d{4}-\d\d-\d\dT[\d:.]+Z ", "", text)
        if text.startswith("{"):
            try:
                ev = json.loads(text)
            except json.JSONDecodeError:
                continue
            name, action = ev.get("Test"), ev.get("Action")
            if name and action in ("pass", "fail", "skip"):
                result[name] = action.upper()
            if name and action == "output":
                output.setdefault(name, []).append(ev.get("Output", "").rstrip())
            continue
        if m := RESULT.match(text):
            result[m.group(2)] = m.group(1)
            current = None
            continue
        if text.startswith("=== RUN"):
            current = text.split()[-1]
        elif current:
            output.setdefault(current, []).append(text.strip())
    return result, output


def main() -> int:
    if len(sys.argv) < 3:
        sys.exit(__doc__.split("\n\n")[1])
    log = Path(sys.argv[1]).read_text(errors="replace")
    result, output = outcomes(log)
    failed = 0
    for name in sys.argv[2:]:
        got = result.get(name)
        if got == "PASS":
            print(f"require-tests: {name} ran and passed")
            continue
        failed += 1
        if got is None:
            print(f"::error title=required test missing::{name} did not run at all")
        elif got == "SKIP":
            why = next((x for x in reversed(output.get(name, [])) if x and "---" not in x), "")
            print(f"::error title=required test skipped::{name} was skipped: {why}")
        else:
            print(f"::error title=required test failed::{name} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
