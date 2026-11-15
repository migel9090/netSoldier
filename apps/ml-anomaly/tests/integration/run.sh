#!/usr/bin/env bash
# Integration tests for ml-anomaly against a throwaway ClickHouse 24.3.
#
#   apps/ml-anomaly/tests/integration/run.sh [pytest args]
#
# Starts clickhouse/clickhouse-server:24.3-alpine with no published ports
# (reached on its bridge IP), applies deploy/clickhouse/migrations/*.sql in
# order (025 adds zeek_conn.ingested_at, which the flow worker needs), then RITA's
# threat_mixtape, creates the two least-privilege worker accounts with random
# passwords, runs the tests marked `integration`, and removes the container.
#
# ML_IT_IMAGE=<ml-anomaly image> additionally starts both workers from that
# image against the server and checks each logs a completed cycle.
# PYTHON selects the interpreter (default: the app's .venv, else python3).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
app="$(cd "$here/../.." && pwd)"
repo="$(cd "$app/../.." && pwd)"
ch_image="${ML_IT_CLICKHOUSE_IMAGE:-clickhouse/clickhouse-server:24.3-alpine}"
python="${PYTHON:-$app/.venv/bin/python}"
[ -x "$python" ] || python=python3
name="ml-anomaly-it-$$"

pw() { "$python" -c 'import secrets; print(secrets.token_hex(16))'; }
admin_pw="$(pw)"
flow_pw="$(pw)"
beacon_pw="$(pw)"

cleanup() {
    docker rm -f "$name" "$name-beacon" "$name-flow" "$name-badpw" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run -d --name "$name" \
    -e CLICKHOUSE_USER=it_admin -e CLICKHOUSE_PASSWORD="$admin_pw" \
    -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 \
    -v "$here/clickhouse/storage.xml:/etc/clickhouse-server/config.d/it-storage.xml:ro" \
    "$ch_image" >/dev/null
ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$name")"
url="http://$ip:8123/"
for _ in $(seq 1 60); do
    if curl -fsS "${url}ping" >/dev/null 2>&1; then break; fi
    sleep 1
done
curl -fsS "${url}ping" >/dev/null

ch() {
    docker exec -i "$name" clickhouse-client --user it_admin --password "$admin_pw" --multiquery
}
for f in "$repo"/deploy/clickhouse/migrations/*.sql; do
    echo "applying $(basename "$f")"
    ch <"$f"
done
ch <"$here/sql/rita_threat_mixtape.sql"
# Exactly the grants the workers need (see README.md).
ch <<SQL
CREATE USER ml_flow IDENTIFIED WITH sha256_password BY '$flow_pw';
GRANT SELECT ON netsoldier.zeek_conn TO ml_flow;
GRANT SELECT, INSERT ON netsoldier.ml_anomalies TO ml_flow;
CREATE USER ml_beacon IDENTIFIED WITH sha256_password BY '$beacon_pw';
GRANT SELECT ON netsoldier_rita.threat_mixtape TO ml_beacon;
GRANT SELECT, INSERT ON netsoldier.ml_beacons TO ml_beacon;
SQL

export ML_IT_URL="$url"
export ML_IT_ADMIN_USER=it_admin ML_IT_ADMIN_PASSWORD="$admin_pw"
export ML_IT_FLOW_USER=ml_flow ML_IT_FLOW_PASSWORD="$flow_pw"
export ML_IT_BEACON_USER=ml_beacon ML_IT_BEACON_PASSWORD="$beacon_pw"

(cd "$app" && "$python" -m pytest tests/integration -m integration "$@")

if [ -n "${ML_IT_IMAGE:-}" ]; then
    # The workers share the server's network namespace (the bridge may not
    # allow container-to-container traffic, and nothing is published).
    key="$(pw)$(pw)"
    local_url="http://127.0.0.1:8123/"
    tmpfs="uid=65532,gid=65532,mode=0700"
    docker run -d --name "$name-beacon" --network "container:$name" --read-only \
        --tmpfs "/var/lib/ml-anomaly:$tmpfs" \
        -e CLICKHOUSE_URL="$local_url" -e CLICKHOUSE_USER=ml_beacon \
        -e CLICKHOUSE_PASSWORD="$beacon_pw" "$ML_IT_IMAGE" >/dev/null
    docker run -d --name "$name-flow" --network "container:$name" --read-only \
        --tmpfs "/var/lib/ml-anomaly:$tmpfs" --tmpfs "/models:$tmpfs" \
        -e CLICKHOUSE_URL="$local_url" -e CLICKHOUSE_USER=ml_flow \
        -e CLICKHOUSE_PASSWORD="$flow_pw" -e MODEL_SIGNING_KEY="$key" \
        --entrypoint python "$ML_IT_IMAGE" -m ml_anomaly.flowsync >/dev/null
    # wrong password: must say so on every cycle
    docker run -d --name "$name-badpw" --network "container:$name" --read-only \
        --tmpfs "/var/lib/ml-anomaly:$tmpfs" -e METRICS_PORT=9103 \
        -e BEACON_SYNC_INTERVAL_SECONDS=2 -e CLICKHOUSE_URL="$local_url" \
        -e CLICKHOUSE_USER=ml_beacon -e CLICKHOUSE_PASSWORD=wrong "$ML_IT_IMAGE" >/dev/null
    sleep 8
    for c in beacon flow; do
        echo "--- $c worker log"
        docker logs "$name-$c" 2>&1 | head -n 8
        docker exec "$name-$c" python -c \
            "import urllib.request,sys; p={'beacon':9101,'flow':9102}['$c']; b=urllib.request.urlopen(f'http://127.0.0.1:{p}/metrics').read().decode(); [print(l) for l in b.splitlines() if l.startswith(('ml_anomaly_cycles_total','ml_anomaly_clickhouse_up','ml_anomaly_last_success'))]"
    done
    docker logs "$name-beacon" 2>&1 | grep -q "beacon sync pass" \
        || { echo "beacon worker did not complete a cycle" >&2; exit 1; }
    docker logs "$name-flow" 2>&1 | grep -q "not enough history\|no verified healthy model" \
        || { echo "flow worker did not complete a cycle" >&2; exit 1; }
    echo "--- wrong-password worker log"
    docker logs "$name-badpw" 2>&1 | grep '"WARNING"' | head -n 2
    warned="$(docker logs "$name-badpw" 2>&1 | grep -c 'cycle failed reason=auth' || true)"
    [ "$warned" -ge 3 ] || { echo "wrong password not reported each cycle" >&2; exit 1; }
    echo "image smoke test passed"
fi
