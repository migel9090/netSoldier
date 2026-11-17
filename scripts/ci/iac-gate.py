#!/usr/bin/env python3
"""Scan gate: Checkov, KICS, hadolint and Semgrep, judged one way.

    scripts/ci/iac-gate.py {checkov|kics|hadolint|semgrep} [--rendered DIR] [--sarif FILE]

(`task scan:checkov`, `task scan:kics`, `task scan:hadolint`,
`task scan:sast`; CI runs the same targets, .github/workflows/iac-scan.yml
and sast.yml.)

What is scanned
  Kubernetes objects are judged as they are deployed: every target that
  scripts/ci/render-manifests.sh renders (each site and each profile), not
  the bases and patch fragments under deploy/kustomize/ and deploy/adguard/
  that kustomize assembles them from. Scanning those sources file by file
  read a resources-only patch as a whole workload without a security
  context, and Checkov's own kustomize mode pinned every rendered finding on
  line 2 of a kustomization.yaml. Everything else in the repository is
  scanned as files: Dockerfiles, Terraform, Ansible, the workflows and the
  standalone manifests (infra/lab/smoke.yaml, the Argo CD and Kyverno
  objects). Not scanned: deploy/argocd/patches/ (fragments of the upstream
  Argo CD install) and deploy/helm/ (chart templates that no target renders
  yet).

  Semgrep reads the source code too (Go, Python, TypeScript, shell, the
  workflows and Dependabot configuration), including scripts that live next
  to the manifests (deploy/kustomize/base/garage/bootstrap.py); only the
  YAML of the directories above is left to the rendered targets. It runs the
  pinned rules of scripts/ci/semgrep-rules.txt, offline, and keeps its
  default ignore list (test directories and *_test.go are not scanned).

How it is judged
  A finding fails the gate unless an exception in scan-exceptions.toml
  covers it: same tool, same rule, and the finding's object (Kind/namespace/
  name, for anything in a Kubernetes manifest) or file (anything else) is
  listed. Each exception carries a reason and a review date; once the date
  passes it no longer applies. There is no baseline and no soft fail. KICS
  gates on HIGH and CRITICAL, as before; Checkov reports no severity without
  a commercial key, so every Checkov finding gates; hadolint and Semgrep
  gate on every rule and every level (Semgrep's `--error`, with reviewed
  exceptions instead of an all-or-nothing switch).

  The SARIF written for code scanning holds exactly the findings that
  failed, so a code-scanning alert and a red job always mean the same thing.

Exit status: 0 clean, 1 findings or exception-file errors, 2 a scanner did
not run.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from collections.abc import Callable

REPO = Path(__file__).resolve().parents[2]
EXCEPTIONS_FILE = REPO / "scan-exceptions.toml"
TOOLS = REPO / "scripts" / "ci" / "tools.sh"
RENDER = REPO / "scripts" / "ci" / "render-manifests.sh"

# Kustomize sources (judged rendered), fragments, and templates nothing
# renders. Paths relative to the repository root.
SOURCE_ONLY = ["deploy/kustomize/", "deploy/adguard/", "deploy/argocd/patches/", "deploy/helm/"]

# An exception is reviewed at least once a year.
MAX_HORIZON = dt.timedelta(days=366)
TOOL_NAMES = ("checkov", "kics", "hadolint", "semgrep")
# Tools whose exceptions share the file: "sops" is read by
# scripts/sops-check.sh, "validate" by scripts/validate-configs.py.
EXCEPTION_TOOLS = (*TOOL_NAMES, "sops", "validate")
SEMGREP_RULES_LIST = REPO / "scripts" / "ci" / "semgrep-rules.txt"
EXCEPTION_KEYS = {"tool", "rule", "resources", "files", "until", "reason"}
RESOURCE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]*/([a-z0-9.-]+/)?[a-z0-9.-]+$")


class GateError(Exception):
    """The gate could not judge: a scanner failed or its output is unusable."""


@dataclass
class Finding:
    rule: str
    level: str
    path: str  # repo-relative, or rendered/<target>.yaml
    line: int
    message: str
    resource: str | None  # Kind/namespace/name when in a Kubernetes manifest
    raw: dict
    targets: list[str] = field(default_factory=list)

    @property
    def rendered(self) -> bool:
        return self.path.startswith("rendered/")

    def where(self) -> str:
        if self.resource and self.rendered:
            return f"{self.resource} (in {', '.join(self.targets)})"
        if self.resource:
            return f"{self.resource} ({self.path}:{self.line})"
        return f"{self.path}:{self.line}"


@dataclass
class Entry:
    index: int
    tool: str
    rule: str
    resources: list[str]
    files: list[str]
    until: dt.date
    reason: str
    used: set[str] = field(default_factory=set)

    def covers(self, f: Finding) -> str | None:
        if f.resource and f.resource in self.resources:
            return f.resource
        if not f.rendered and f.path in self.files:
            return f.path
        return None


# ── exceptions file ──────────────────────────────────────────────────────────


def load_exceptions(tool: str, today: dt.date) -> tuple[list[Entry], list[Entry], list[str]]:
    """The active and the expired exceptions for `tool`, and every problem in the file."""
    try:
        data = tomllib.loads(EXCEPTIONS_FILE.read_text())
    except (OSError, tomllib.TOMLDecodeError) as e:
        return [], [], [f"{EXCEPTIONS_FILE.name}: {e}"]
    problems: list[str] = []
    active: list[Entry] = []
    expired: list[Entry] = []
    unknown_top = set(data) - {"exception"}
    if unknown_top:
        problems.append(f"{EXCEPTIONS_FILE.name}: unknown top-level keys {sorted(unknown_top)}")
    for i, e in enumerate(data.get("exception", []), start=1):
        label = f"{EXCEPTIONS_FILE.name} exception #{i} ({e.get('tool')} {e.get('rule')})"
        bad = sorted(set(e) - EXCEPTION_KEYS)
        if bad:
            problems.append(f"{label}: unknown keys {bad}")
            continue
        if e.get("tool") not in EXCEPTION_TOOLS:
            problems.append(f"{label}: tool must be one of {EXCEPTION_TOOLS}")
            continue
        if not isinstance(e.get("rule"), str) or not e["rule"]:
            problems.append(f"{label}: rule is required")
            continue
        reason = e.get("reason")
        if not isinstance(reason, str) or len(reason.split()) < 8:
            problems.append(f"{label}: a reason a reviewer can check is required")
            continue
        until = e.get("until")
        if not isinstance(until, dt.date) or isinstance(until, dt.datetime):
            problems.append(f"{label}: until must be a date (YYYY-MM-DD)")
            continue
        resources, files = e.get("resources", []), e.get("files", [])
        if not (resources or files):
            problems.append(f"{label}: list the resources or files it covers")
            continue
        for r in resources:
            if not isinstance(r, str) or not RESOURCE_RE.match(r):
                problems.append(f"{label}: resource {r!r} is not Kind/namespace/name")
        for p in files:
            if not isinstance(p, str) or not (REPO / p).is_file():
                problems.append(f"{label}: file {p!r} does not exist")
        if until - today > MAX_HORIZON:
            problems.append(f"{label}: until {until} is more than a year away; review sooner")
        if e["tool"] != tool:
            continue
        entry = Entry(i, e["tool"], e["rule"], resources, files, until, reason.strip())
        # Like osv-scanner's ignoreUntil: past the date the entry stops
        # applying, its findings fail again, and the gate says why.
        (expired if until < today else active).append(entry)
    return active, expired, problems


# ── locating findings ────────────────────────────────────────────────────────


def manifest_index(path: Path) -> list[tuple[int, int, str]]:
    """(first line, last line, Kind/namespace/name) of each object in a YAML file."""
    try:
        nodes = list(yaml.compose_all(path.read_text()))
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return []
    index = []
    for node in nodes:
        if not isinstance(node, yaml.MappingNode):
            continue
        top = {k.value: v for k, v in node.value if isinstance(k, yaml.ScalarNode)}
        kind, meta = top.get("kind"), top.get("metadata")
        if not isinstance(kind, yaml.ScalarNode) or not isinstance(meta, yaml.MappingNode):
            continue
        md = {k.value: v for k, v in meta.value if isinstance(k, yaml.ScalarNode)}
        name, ns = md.get("name"), md.get("namespace")
        if not isinstance(name, yaml.ScalarNode):
            continue
        rid = (
            f"{kind.value}/{ns.value}/{name.value}"
            if isinstance(ns, yaml.ScalarNode)
            else f"{kind.value}/{name.value}"
        )
        index.append((node.start_mark.line + 1, node.end_mark.line + 1, rid))
    return index


class Locator:
    """Where a SARIF location points: a repository file or a rendered target."""

    def __init__(self, rendered: Path):
        self.rendered = rendered
        self._cache: dict[str, list[tuple[int, int, str]]] = {}

    @staticmethod
    def normalise(uri: str, origin: str) -> str:
        """Repo-relative path, or rendered/<target>.yaml.

        origin is what the scanner was pointed at: "repo" (paths relative to
        the checkout), "rendered" (paths relative to the rendered directory)
        or "both" (KICS, run in the checkout with the rendered directory
        mounted beside it, which it reports as ../rendered/...).
        """
        parts = [p for p in uri.removeprefix("file://").split("/") if p not in ("", ".")]
        if origin == "rendered" or (
            origin == "both" and "rendered" in parts[:2] and parts[0] in ("..", "rendered")
        ):
            return f"rendered/{parts[-1]}"
        if parts[:1] == ["src"]:
            parts = parts[1:]
        return "/".join(parts)

    def resource(self, path: str, line: int) -> str | None:
        if not path.endswith((".yaml", ".yml")):
            return None
        if path not in self._cache:
            real = (
                self.rendered / path.removeprefix("rendered/")
                if path.startswith("rendered/")
                else REPO / path
            )
            self._cache[path] = manifest_index(real)
        for first, last, rid in self._cache[path]:
            if first <= line <= last:
                return rid
        return None


def read_sarif(
    files: list[tuple[Path, str]], locator: Locator, gated: Callable[[str], bool]
) -> tuple[list[Finding], dict, list[dict], int]:
    """Findings at gate level, the driver, its rules, and how many were below it."""
    findings: list[Finding] = []
    driver: dict = {}
    rules: dict[str, dict] = {}
    below = 0
    for f, origin in files:
        if not f.is_file():
            raise GateError(f"the scanner wrote no SARIF at {f}")
        try:
            doc = json.loads(f.read_text())
        except json.JSONDecodeError as e:
            raise GateError(f"{f}: not SARIF: {e}") from e
        for run in doc.get("runs", []):
            drv = run["tool"]["driver"]
            driver = driver or {k: v for k, v in drv.items() if k != "rules"}
            run_rules = {r["id"]: r for r in drv.get("rules", [])}
            rules.update(run_rules)
            for res in run.get("results", []):
                rule = res.get("ruleId", "")
                level = res.get("level") or run_rules.get(rule, {}).get(
                    "defaultConfiguration", {}
                ).get("level", "warning")
                if not gated(level):
                    below += 1
                    continue
                loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
                path = locator.normalise(loc.get("artifactLocation", {}).get("uri", "?"), origin)
                line = int(loc.get("region", {}).get("startLine", 1))
                findings.append(
                    Finding(
                        rule,
                        level,
                        path,
                        line,
                        res.get("message", {}).get("text", ""),
                        locator.resource(path, line),
                        res,
                    )
                )
    return findings, driver, list(rules.values()), below


def dedupe(findings: list[Finding]) -> list[Finding]:
    """One finding per rule and object: the same base workload is in several targets."""
    out: dict[tuple, Finding] = {}
    for f in findings:
        key = (
            (f.rule, f.resource)
            if f.rendered and f.resource
            else (f.rule, f.path, f.line, f.message)
        )
        target = Path(f.path).stem if f.rendered else None
        if key in out:
            if target and target not in out[key].targets:
                out[key].targets.append(target)
            continue
        if target:
            f.targets.append(target)
        out[key] = f
    return list(out.values())


# ── scanners ─────────────────────────────────────────────────────────────────


def executable(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise GateError(f"{name} is not installed")
    return path


# Every argv below is assembled here from constants and repository paths and
# run without a shell (S603).
def run(cmd: list[str], ok=(0,)) -> None:
    print("+ " + " ".join(cmd), file=sys.stderr, flush=True)
    rc = subprocess.run(cmd, check=False).returncode  # noqa: S603
    if rc not in ok:
        raise GateError(f"{cmd[0]} exited {rc}")


def docker(
    image: str, mounts: list[tuple[Path, str, str]], workdir: str, args: list[str], ok=(0,)
) -> None:
    # No network: the scanners need none, and they read the whole tree.
    docker_bin = executable("docker")
    cmd = [
        docker_bin,
        "run",
        "--rm",
        "--network",
        "none",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
    ]
    cmd += ["-e", "HOME=/tmp"]
    info = subprocess.run(  # noqa: S603
        [docker_bin, "info", "--format", "{{.SecurityOptions}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if "name=userns" in info.stdout:
        # A daemon remapping user namespaces would hand the container a
        # uid that cannot read the bind-mounted checkout.
        cmd.append("--userns=host")
    for host, target, mode in mounts:
        cmd += ["-v", f"{host}:{target}:{mode}"]
    run([*cmd, "-w", workdir, image, *args], ok)


def tool_image(name: str) -> str:
    argv = [str(TOOLS), "image", name]
    return subprocess.run(argv, check=True, capture_output=True, text=True).stdout.strip()  # noqa: S603


def scan_checkov(rendered: Path, out: Path) -> list[tuple[Path, str]]:
    image = tool_image("checkov")
    (out / "repo").mkdir()
    (out / "rendered").mkdir()
    skip = [a for p in SOURCE_ONLY for a in ("--skip-path", p)]
    # Checkov exits 1 when it finds anything; whether that fails the gate is
    # decided below, from the SARIF, against the exceptions.
    docker(
        image,
        [(REPO, "/src", "ro"), (out, "/out", "rw")],
        "/src",
        [
            "-d",
            ".",
            "--skip-framework",
            "kustomize",
            "helm",
            *skip,
            "-o",
            "sarif",
            "--output-file-path",
            "/out/repo",
            "--quiet",
            "--compact",
        ],
        ok=(0, 1),
    )
    docker(
        image,
        [(rendered, "/rendered", "ro"), (out, "/out", "rw")],
        "/rendered",
        [
            "-d",
            ".",
            "--framework",
            "kubernetes",
            "secrets",
            "-o",
            "sarif",
            "--output-file-path",
            "/out/rendered",
            "--quiet",
            "--compact",
        ],
        ok=(0, 1),
    )
    return [
        (out / "repo" / "results_sarif.sarif", "repo"),
        (out / "rendered" / "results_sarif.sarif", "rendered"),
    ]


def scan_kics(rendered: Path, out: Path) -> list[tuple[Path, str]]:
    excludes = ",".join(f"/src/{p}**" for p in SOURCE_ONLY)
    docker(
        tool_image("kics"),
        [(REPO, "/src", "ro"), (rendered, "/rendered", "ro"), (out, "/out", "rw")],
        "/src",
        [
            "scan",
            "-p",
            "/src,/rendered",
            "--exclude-paths",
            excludes,
            "-o",
            "/out",
            "--output-name",
            "kics",
            "--report-formats",
            "sarif",
            "--ignore-on-exit",
            "results",
            "--no-progress",
            "--ci",
        ],
    )
    return [(out / "kics.sarif", "both")]


def dockerfiles() -> list[str]:
    argv = [executable("git"), "-C", str(REPO), "ls-files", "-z"]
    listed = subprocess.run(argv, check=True, capture_output=True, text=True).stdout  # noqa: S603
    pattern = re.compile(
        r"(^|/)(Dockerfile|Containerfile)(\.[^/]+)?$|\.(Dockerfile|Containerfile)$"
    )
    return sorted(p for p in listed.split("\0") if p and pattern.search(p))


def scan_hadolint(_rendered: Path, out: Path) -> list[tuple[Path, str]]:
    files = dockerfiles()
    if not files:
        raise GateError("no Dockerfile or Containerfile is tracked: the gate would check nothing")
    argv = [str(TOOLS), "install", "hadolint"]
    bin_dir = subprocess.run(argv, check=True, capture_output=True, text=True).stdout.strip()  # noqa: S603
    sarif = out / "hadolint.sarif"
    print(f"hadolint: {len(files)} files: {' '.join(files)}", file=sys.stderr)
    # --disable-ignore-pragma: an inline `# hadolint ignore=` has no review
    # date, so exceptions live in scan-exceptions.toml like everyone else's.
    with sarif.open("w") as fh:
        flags = ["--no-color", "--no-fail", "--disable-ignore-pragma", "-f", "sarif"]
        rc = subprocess.run(  # noqa: S603
            [f"{bin_dir}/hadolint", *flags, *files], cwd=REPO, stdout=fh, check=False
        ).returncode
    if rc != 0:
        raise GateError(f"hadolint exited {rc}")
    return [(sarif, "repo")]


def registry_ids(rules_dir: Path, listed: list[str]) -> dict[str, str]:
    """Semgrep's local rule id -> the registry id, for every pinned rule.

    Semgrep names a rule loaded from a directory `<directory path>.<id>`,
    the path being wherever the rules are cached, so the same rule would get
    a new id on every machine and code scanning would see new alerts. The
    registry id, which the existing alerts and scan-exceptions.toml use, is
    `<path of the file inside semgrep-rules, without .yaml>.<id>`.
    """
    out: dict[str, str] = {}
    for rel in listed:
        doc = yaml.safe_load((rules_dir / rel).read_text()) or {}
        stem = rel.rsplit(".", 1)[0].replace("/", ".")
        folder = str(Path(rel).parent).replace("/", ".")
        for rule in doc.get("rules") or []:
            out[f"{folder}.{rule['id']}"] = f"{stem}.{rule['id']}"
    return out


def registry_rule_id(rule_id: str, ids: dict[str, str]) -> str:
    parts = rule_id.split(".")
    for i in range(len(parts)):
        if (suffix := ".".join(parts[i:])) in ids:
            return ids[suffix]
    raise GateError(f"semgrep reported rule {rule_id}, which is not a pinned rule")


def scan_semgrep(rendered: Path, out: Path) -> list[tuple[Path, str]]:
    # stdout is the path tools.sh prints; its progress and errors go to the log.
    tools = [str(TOOLS), "install", "semgrep"]
    bin_dir = subprocess.run(tools, check=True, stdout=subprocess.PIPE, text=True).stdout.strip()  # noqa: S603
    argv = [str(TOOLS), "rules", "semgrep"]
    rules = subprocess.run(argv, check=True, stdout=subprocess.PIPE, text=True).stdout.strip()  # noqa: S603
    listed = [
        line.strip()
        for line in SEMGREP_RULES_LIST.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
    ids = registry_ids(Path(rules), listed)
    # Offline and quiet: no metrics, no version check, no registry. The YAML
    # of the kustomize sources is judged in its rendered form below; scripts
    # in those directories are still read as code.
    flags = [
        "--config",
        rules,
        "--sarif",
        "--metrics",
        "off",
        "--disable-version-check",
        "--quiet",
    ]
    env = {**os.environ, "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"}
    excludes = [
        x for p in SOURCE_ONLY for x in ("--exclude", f"{p}**/*.yaml", "--exclude", f"{p}**/*.yml")
    ]
    runs = [
        (REPO, [*flags, *excludes, "--output", str(out / "repo.sarif"), "."], "repo"),
        (rendered, [*flags, "--output", str(out / "rendered.sarif"), "."], "rendered"),
    ]
    files = []
    for cwd, args, origin in runs:
        cmd = [f"{bin_dir}/semgrep", "scan", *args]
        print("+ (cd " + str(cwd) + ") " + " ".join(cmd), file=sys.stderr, flush=True)
        # Without --error Semgrep exits 0 whatever it finds; anything else
        # means it did not finish (bad rule, crash), which must not pass.
        rc = subprocess.run(cmd, cwd=cwd, env=env, check=False).returncode  # noqa: S603
        if rc != 0:
            raise GateError(f"semgrep exited {rc}")
        sarif = Path(args[args.index("--output") + 1])
        if not sarif.is_file():
            raise GateError(f"semgrep wrote no SARIF at {sarif}")
        doc = json.loads(sarif.read_text())
        for run_ in doc.get("runs", []):
            drv = run_["tool"]["driver"]
            for r in drv.get("rules", []):
                r["id"] = registry_rule_id(r["id"], ids)
                # The short name is the local id too; code scanning shows it.
                r["name"] = r["id"]
            for res in run_.get("results", []):
                res["ruleId"] = registry_rule_id(res.get("ruleId", ""), ids)
        sarif.write_text(json.dumps(doc))
        files.append((sarif, origin))
    return files


SCANNERS = {
    "checkov": (scan_checkov, lambda _level: True),
    "kics": (scan_kics, lambda level: level == "error"),  # HIGH and CRITICAL
    "hadolint": (scan_hadolint, lambda _level: True),
    "semgrep": (scan_semgrep, lambda _level: True),
}


# ── report ───────────────────────────────────────────────────────────────────


def write_sarif(path: Path, driver: dict, rules: list[dict], failed: list[Finding]) -> None:
    used = {f.rule for f in failed}
    results = []
    for f in failed:
        res = {k: v for k, v in f.raw.items() if k != "ruleIndex"}
        if f.rendered and f.resource:
            res["message"] = {
                "text": f"{f.message} [{f.resource}, rendered in {', '.join(f.targets)}]"
            }
        results.append(res)
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {**driver, "rules": [r for r in rules if r["id"] in used]}},
                "results": results,
            }
        ],
    }
    path.write_text(json.dumps(doc, indent=1))


def annotate(f: Finding, note: str = "") -> str:
    text = f"{f.rule}: {f.message} — {f.where()}{note}".replace("\n", " ")
    if f.rendered:
        return f"::error title={f.rule}::{text}"
    return f"::error file={f.path},line={f.line},title={f.rule}::{text}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("tool", choices=TOOL_NAMES)
    ap.add_argument("--rendered", type=Path, help="rendered targets (default: render them now)")
    ap.add_argument(
        "--sarif", type=Path, help="write the failing findings here, for code scanning"
    )
    args = ap.parse_args()
    today = dt.datetime.now(dt.UTC).date()

    exceptions, expired, problems = load_exceptions(args.tool, today)
    scan, gated = SCANNERS[args.tool]

    with tempfile.TemporaryDirectory(prefix=f"iac-gate-{args.tool}-") as tmp:
        tmp_path = Path(tmp)
        rendered = args.rendered
        if rendered is None and args.tool != "hadolint":
            rendered = tmp_path / "rendered"
            run([str(RENDER), "--render-only", str(rendered)])
        rendered = (rendered or tmp_path).resolve()
        if args.tool != "hadolint" and not any(rendered.glob("*.yaml")):
            raise GateError(f"no rendered target in {rendered}: the gate would judge nothing")
        out = tmp_path / "out"
        out.mkdir()
        findings, driver, rules, below = read_sarif(scan(rendered, out), Locator(rendered), gated)

        distinct = dedupe(findings)
        failed: list[Finding] = []
        covered = 0
        for f in distinct:
            for e in exceptions:
                if e.rule == f.rule and (hit := e.covers(f)):
                    e.used.add(hit)
                    covered += 1
                    break
            else:
                failed.append(f)

        if args.sarif:
            write_sarif(args.sarif, driver, rules, failed)

    print(
        f"\n{args.tool}: {len(distinct)} distinct findings at gate level "
        f"({len(findings)} across targets), {covered} covered by exceptions, {len(failed)} failing"
        + (f"; {below} below the gate level, not judged" if below else "")
    )
    for e in exceptions:
        unused = [x for x in [*e.resources, *e.files] if x not in e.used]
        if unused:
            # A fix landed or an object was renamed: the entry should shrink.
            print(
                f"::warning title=unused exception::{EXCEPTIONS_FILE.name} #{e.index} "
                f"({e.tool} {e.rule}) no longer matches: {', '.join(unused)}"
            )
    for e in expired:
        print(
            f"::warning title=expired exception::{EXCEPTIONS_FILE.name} #{e.index} "
            f"({e.tool} {e.rule}) expired on {e.until} and no longer applies; "
            "re-justify it with a new date or remove it"
        )
    for p in problems:
        print(f"::error title={EXCEPTIONS_FILE.name}::{p}")
    for f in sorted(failed, key=lambda f: (f.rule, f.where())):
        lapsed = next((e for e in expired if e.rule == f.rule and e.covers(f)), None)
        print(
            annotate(
                f, f" (exception #{lapsed.index} expired on {lapsed.until})" if lapsed else ""
            )
        )
    if failed or problems:
        print(
            f"\n{args.tool}: FAILED. Fix each finding, or add an exception with a reason and a "
            f"review date to {EXCEPTIONS_FILE.name}."
        )
        return 1
    print(f"{args.tool}: OK")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (GateError, subprocess.CalledProcessError) as e:
        print(f"::error title=iac-gate::{e}", file=sys.stderr)
        sys.exit(2)
