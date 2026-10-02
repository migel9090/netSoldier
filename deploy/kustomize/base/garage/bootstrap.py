#!/usr/bin/env python3
"""One-shot Garage cluster bootstrap, run by the garage-bucket-init Job.

A fresh Garage node serves no S3 traffic until a cluster layout is applied,
so this creates the layout, imports the S3 access key with fixed
credentials (so ClickHouse and the backup CronJob can be configured ahead
of time) and creates the buckets.

The garage image is built FROM scratch and has no shell, so this drives the
admin API over HTTP rather than running the garage CLI. Every step is
idempotent: re-applying the Job on a resync is a no-op.

Kept as a file rather than inline YAML so it stays readable and lintable,
and is loaded into the ConfigMap by kustomize's configMapGenerator.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

ADMIN = os.environ["GARAGE_ADMIN_URL"]
TOKEN = os.environ["GARAGE_ADMIN_TOKEN"]
KEY_ID = os.environ["S3_ACCESS_KEY"]
KEY_SECRET = os.environ["S3_SECRET_KEY"]
KEY_NAME = os.environ.get("S3_KEY_NAME", "netsoldier")
ZONE = os.environ.get("GARAGE_ZONE", "dc1")
CAPACITY = int(os.environ.get("GARAGE_CAPACITY_BYTES", "21474836480"))
BUCKETS = os.environ.get("S3_BUCKETS", "").split()


def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(ADMIN + path, data=data, method=method)
    req.add_header("Authorization", "Bearer " + TOKEN)
    if data:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=15) as resp:
        raw = resp.read()
        return json.loads(raw) if raw else None


def wait_for_admin():
    for attempt in range(1, 61):
        try:
            return call("GET", "/v2/GetClusterStatus")
        except Exception as exc:  # noqa: BLE001 - any failure means not up yet
            print(f"garage admin not ready ({attempt}/60): {exc}", flush=True)
            time.sleep(5)
    sys.exit("garage admin API never became reachable")


status = wait_for_admin()
nodes = status["nodes"]
if len(nodes) != 1:
    sys.exit(f"expected exactly one garage node, got {len(nodes)}")
node = nodes[0]

# Only stage a layout when this node has no role yet. Re-running against
# an already-configured cluster must not bump the layout version, which
# would trigger a needless rebalance.
if node.get("role") is None:
    print(f"assigning layout to node {node['id']}", flush=True)
    call("POST", "/v2/UpdateClusterLayout", {
        "roles": [{
            "id": node["id"],
            "zone": ZONE,
            "capacity": CAPACITY,
            "tags": [],
        }],
    })
    call("POST", "/v2/ApplyClusterLayout",
         {"version": status["layoutVersion"] + 1})
else:
    print("layout already assigned, leaving it alone", flush=True)

# ImportKey is not idempotent: it returns 409 once the key id exists.
# Look first so a re-run is a no-op rather than a failure. A key that is
# already present is left untouched, so rotating S3_SECRET_KEY means
# deleting the key before re-running this Job.
try:
    call("GET", f"/v2/GetKeyInfo?id={KEY_ID}")
    print(f"access key {KEY_ID} already present, leaving it alone",
          flush=True)
except urllib.error.HTTPError as exc:
    if exc.code != 404:
        raise
    print(f"importing access key {KEY_ID}", flush=True)
    call("POST", "/v2/ImportKey", {
        "accessKeyId": KEY_ID,
        "secretAccessKey": KEY_SECRET,
        "name": KEY_NAME,
    })

for bucket in BUCKETS:
    try:
        call("POST", "/v2/CreateBucket", {"globalAlias": bucket})
        print(f"created bucket {bucket}", flush=True)
    except urllib.error.HTTPError as exc:
        # 409 == the alias already exists, which is the expected path on
        # every run after the first.
        if exc.code != 409:
            raise
        print(f"bucket {bucket} already exists", flush=True)

    info = call("GET", f"/v2/GetBucketInfo?globalAlias={bucket}")
    call("POST", "/v2/AllowBucketKey", {
        "bucketId": info["id"],
        "accessKeyId": KEY_ID,
        "permissions": {"read": True, "write": True, "owner": True},
    })
    print(f"granted {KEY_ID} rw+owner on {bucket}", flush=True)

print("garage bootstrap complete", flush=True)
