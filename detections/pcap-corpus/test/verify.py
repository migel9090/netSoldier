#!/usr/bin/env python3
"""Replay the PCAP corpus through Suricata and Zeek and assert what each
family must produce — detection-as-code regression testing.

The rules under test are the production ones: netsoldier.rules is read
straight out of deploy/kustomize/base/suricata/local-rules-cm.yaml, and the
IoC datasets are rebuilt in the same ndjson shape threat-intel-sync serves
from /export/suricata/*.json. Zeek runs the first-party scripts from
deploy/docker/zeek/scripts. So a rule or script edit that breaks detection
fails here, not in production.

Both sensors run once per invocation (all pcaps inside a single container),
which keeps the whole corpus under a minute.

Usage:
  ./verify.py                      # assert manifest expectations, both sensors
  ./verify.py --report             # print observed results (for updating the manifest)
  ./verify.py --sensor zeek --only c2-tls-beacon
"""

import argparse
import contextlib
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip install pyyaml")

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.dirname(HERE)
REPO = os.path.dirname(os.path.dirname(CORPUS))
RULES_CM = os.path.join(REPO, "deploy", "kustomize", "base", "suricata", "local-rules-cm.yaml")
ZEEK_SCRIPTS = os.path.join(REPO, "deploy", "docker", "zeek", "scripts")

DEFAULT_SURICATA_IMAGE = "jasonish/suricata:8.0.5"
DEFAULT_ZEEK_IMAGE = "zeek/zeek:8.0.8"


# ── helpers ─────────────────────────────────────────────────────────────


def count_packets(path: str) -> int:
    """Count records in a libpcap file without pulling in a parser library."""
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic not in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1"):
            raise ValueError(f"{path}: not a libpcap file")
        endian = ">" if magic == b"\xa1\xb2\xc3\xd4" else "<"
        f.read(20)
        n = 0
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                return n
            caplen = struct.unpack(endian + "IIII", hdr)[2]
            f.seek(caplen, os.SEEK_CUR)
            n += 1


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 16), b""):
            h.update(block)
    return h.hexdigest()


def docker(args, image, mounts, command):
    # The sensors run as root in the container, so anything they write to the
    # bind-mounted output dir lands root-owned; hand it back before exiting or
    # the host user cannot clean up the temp dir.
    command = f"{command}; rc=$?; chown -R {os.getuid()}:{os.getgid()} /out 2>/dev/null; exit $rc"
    cmd = ["docker", "run", "--rm"]
    for src, dst, mode in mounts:
        cmd += ["-v", f"{src}:{dst}:{mode}" if mode else f"{src}:{dst}"]
    if args.docker_caps:
        # The netSoldier zeek image carries file capabilities on the binary;
        # exec needs them in the bounding set even for offline replay.
        cmd += ["--cap-add", "net_raw", "--cap-add", "net_admin"]
    cmd += ["--entrypoint", "sh", image, "-c", command]
    proc = subprocess.run(cmd, capture_output=True, text=True)  # noqa: S603 — local docker, repo-controlled argv
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout + proc.stderr)
        raise SystemExit(f"docker run failed ({image})")
    return proc.stdout


# ── inputs built from production config ─────────────────────────────────


def write_rules(dest: str):
    with open(RULES_CM) as f:
        cm = yaml.safe_load(f)
    rules = cm["data"]["netsoldier.rules"]
    with open(os.path.join(dest, "netsoldier.rules"), "w") as f:
        f.write(rules)
    return len([r for r in rules.splitlines() if r.strip()])


def write_datasets(dest: str, entries):
    """Rebuild the Suricata datasets threat-intel-sync would serve, from every
    IoC declared in the manifest."""
    domains, ips = {}, {}
    for e in entries:
        for ioc in e.get("iocs", []) or []:
            row = {
                "source": ioc.get("source", "corpus"),
                "severity": ioc.get("severity", "high"),
                "confidence": ioc.get("confidence", 80),
            }
            if ioc["type"] == "domain":
                domains[ioc["value"]] = dict(row, domain=ioc["value"])
            elif ioc["type"] == "ip":
                ips[ioc["value"]] = dict(row, ip=ioc["value"])
    with open(os.path.join(dest, "ioc-domains.json"), "w") as f:
        for v in domains.values():
            f.write(json.dumps(v) + "\n")
    with open(os.path.join(dest, "ioc-ips.json"), "w") as f:
        for v in ips.values():
            f.write(json.dumps(v) + "\n")
    return len(domains), len(ips)


# ── sensor runs ─────────────────────────────────────────────────────────


def run_suricata(args, names, workdir):
    rules, data, out = (os.path.join(workdir, d) for d in ("rules", "data", "sur-out"))
    for d in (rules, data, out):
        os.makedirs(d, exist_ok=True)
    n_rules = write_rules(rules)
    n_dom, n_ip = write_datasets(data, args._entries)
    print(f"  suricata: {n_rules} production rules, {n_dom} domain / {n_ip} ip IoCs")

    script = " ".join(
        f"mkdir -p /out/{n} && suricata -r /pcaps/{n}.pcap "
        f"-S /rules/netsoldier.rules -l /out/{n} >/dev/null 2>&1;"
        for n in names
    )
    docker(
        args,
        args.suricata_image,
        [
            (os.path.join(CORPUS, "pcaps"), "/pcaps", "ro"),
            (rules, "/rules", "ro"),
            (data, "/var/lib/suricata/data", None),
            (out, "/out", None),
        ],
        f"set -u; {script} true",
    )

    observed = {}
    for n in names:
        sids, total = {}, 0
        eve = os.path.join(out, n, "eve.json")
        if os.path.exists(eve):
            with open(eve) as f:
                for line in f:
                    try:
                        ev = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if ev.get("event_type") != "alert":
                        continue
                    total += 1
                    sid = ev["alert"]["signature_id"]
                    sids[sid] = sids.get(sid, 0) + 1
        observed[n] = {"sids": sids, "total": total}
    return observed


def run_zeek(args, names, workdir):
    out = os.path.join(workdir, "zeek-out")
    os.makedirs(out, exist_ok=True)

    script = " ".join(
        f"mkdir -p /out/{n} && cd /out/{n} && "
        f"zeek -r /pcaps/{n}.pcap /scripts/netsoldier-tlsfp.zeek "
        f"LogAscii::use_json=T >/dev/null 2>&1;"
        for n in names
    )
    docker(
        args,
        args.zeek_image,
        [
            (os.path.join(CORPUS, "pcaps"), "/pcaps", "ro"),
            (ZEEK_SCRIPTS, "/scripts", "ro"),
            (out, "/out", None),
        ],
        f"set -u; {script} true",
    )

    observed = {}
    for n in names:
        logs, records = {}, {}
        d = os.path.join(out, n)
        for fname in sorted(os.listdir(d)) if os.path.isdir(d) else []:
            if not fname.endswith(".log") or fname in ("packet_filter.log", "reporter.log"):
                continue
            stem = fname[:-4]
            rows = []
            with open(os.path.join(d, fname)) as f:
                for line in f:
                    with contextlib.suppress(json.JSONDecodeError):
                        rows.append(json.loads(line))
            logs[stem] = len(rows)
            records[stem] = rows
        observed[n] = {"logs": logs, "records": records}
    return observed


# ── assertions ──────────────────────────────────────────────────────────


def check(entry, sur, zk, failures):
    name = entry["name"]
    exp = entry.get("expect", {}) or {}

    path = os.path.join(CORPUS, entry["file"])
    if not os.path.exists(path):
        failures.append(f"{name}: missing {entry['file']} — run gen_corpus.py")
        return
    if "sha256" in entry and sha256_file(path) != entry["sha256"]:
        failures.append(
            f"{name}: sha256 mismatch — corpus file changed, "
            f"re-pin the manifest if that was intentional"
        )
    if "packets" in exp:
        got = count_packets(path)
        if got != exp["packets"]:
            failures.append(f"{name}: packets {got} != expected {exp['packets']}")

    if sur is not None and "suricata" in exp:
        e, o = exp["suricata"], sur.get(name, {"sids": {}, "total": 0})
        for sid in e.get("sids", []) or []:
            if o["sids"].get(sid, 0) < 1:
                failures.append(
                    f"{name}: suricata sid {sid} did not fire "
                    f"(fired: {sorted(o['sids']) or 'nothing'})"
                )
        if "max_alerts" in e and o["total"] > e["max_alerts"]:
            failures.append(
                f"{name}: {o['total']} suricata alerts exceeds "
                f"max_alerts={e['max_alerts']} — false positive"
            )

    if zk is not None and "zeek" in exp:
        e, o = exp["zeek"], zk.get(name, {"logs": {}, "records": {}})
        for log, minimum in (e.get("min_lines") or {}).items():
            if o["logs"].get(log, 0) < minimum:
                failures.append(
                    f"{name}: zeek {log}.log has "
                    f"{o['logs'].get(log, 0)} rows, expected >= {minimum}"
                )
        for log, fields in (e.get("contains") or {}).items():
            rows = o["records"].get(log, [])
            for field, want in fields.items():
                if not any(str(r.get(field, "")).find(str(want)) >= 0 for r in rows):
                    failures.append(f"{name}: no {log}.log row with {field} containing {want!r}")


def report(entries, sur, zk):
    for e in entries:
        name = e["name"]
        path = os.path.join(CORPUS, e["file"])
        print(f"\n{name}:")
        if os.path.exists(path):
            print(f"    packets: {count_packets(path)}")
            print(f"    sha256: {sha256_file(path)}")
        if sur:
            o = sur.get(name, {})
            print(f"    suricata: total={o.get('total', 0)} sids={o.get('sids', {})}")
        if zk:
            o = zk.get(name, {})
            print(f"    zeek logs: {o.get('logs', {})}")
            for log in ("http", "ssl", "dns"):
                rows = o.get("records", {}).get(log, [])
                if rows:
                    keys = [
                        k
                        for k in ("host", "server_name", "query", "tls_client_fp", "qtype_name")
                        if k in rows[0]
                    ]
                    print(f"      {log}[0]: " + ", ".join(f"{k}={rows[0][k]}" for k in keys))


def main():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--sensor", choices=["all", "suricata", "zeek"], default="all")
    p.add_argument("--only", help="run a single corpus entry by name")
    p.add_argument(
        "--report", action="store_true", help="print observed results instead of asserting"
    )
    p.add_argument("--suricata-image", default=DEFAULT_SURICATA_IMAGE)
    p.add_argument(
        "--zeek-image",
        default=DEFAULT_ZEEK_IMAGE,
        help="pass the netSoldier zeek image to test the shipped build",
    )
    p.add_argument(
        "--docker-caps",
        action="store_true",
        help="grant net_raw/net_admin (needed by the netSoldier zeek image)",
    )
    p.add_argument("--manifest", default=os.path.join(CORPUS, "manifest.yaml"))
    p.add_argument(
        "--no-generate",
        action="store_true",
        help="use the pcaps already on disk instead of regenerating",
    )
    args = p.parse_args()

    # The captures are gitignored, not committed (see .gitignore) — they are
    # rebuilt from gen_corpus.py, and the sha256 pins in the manifest are the
    # determinism gate: a generator that is not byte-reproducible fails here.
    if not args.no_generate:
        subprocess.run(  # noqa: S603 — runs this repo's own generator
            [sys.executable, os.path.join(CORPUS, "gen_corpus.py")],
            check=True,
            stdout=subprocess.DEVNULL,
        )

    with open(args.manifest) as f:
        manifest = yaml.safe_load(f)

    entries = [e for e in manifest["corpus"] if e.get("source") == "generated"]
    if args.only:
        entries = [e for e in entries if e["name"] == args.only]
        if not entries:
            raise SystemExit(f"no generated corpus entry named {args.only!r}")
    args._entries = manifest["corpus"]  # datasets use every declared IoC
    names = [e["name"] for e in entries]

    print(
        f"corpus: {len(names)} generated captures "
        f"({len(manifest['corpus']) - len(names)} external entries skipped)"
    )

    with tempfile.TemporaryDirectory(prefix="pcap-corpus-") as workdir:
        sur = run_suricata(args, names, workdir) if args.sensor in ("all", "suricata") else None
        zk = run_zeek(args, names, workdir) if args.sensor in ("all", "zeek") else None

        if args.report:
            report(entries, sur, zk)
            return

        failures = []
        for e in entries:
            check(e, sur, zk, failures)

    if failures:
        print("\nFAILED:")
        for f in failures:
            print(f"  - {f}")
        raise SystemExit(1)
    print(f"\nOK — {len(names)} captures replayed, all expectations met")


if __name__ == "__main__":
    main()
