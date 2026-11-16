# ml-anomaly

Two workers in one image, both writing rows that detection-engine tails:

| worker | command | reads | writes | signal |
|---|---|---|---|---|
| beacon-sync | `python -m ml_anomaly.sync` (image default) | `netsoldier_rita.threat_mixtape` (RITA v5) | `netsoldier.ml_beacons` | `beacon` |
| flow-anomaly | `python -m ml_anomaly.flowsync` | `netsoldier.zeek_conn` (Zeek `conn.log`) | `netsoldier.ml_anomalies` | `volumetric` (**experimental**) |

**The volumetric signal is experimental** until roadmap step 129. It runs end to end, but the
Isolation Forest is not calibrated on real traffic: its confidence stops below the approval-queue
threshold and its health gate only checks caricature attacks (audit ML-3, ML-7). Treat
`ml_anomalies` rows as hints for a human.

There is no HTTP API any more. The scoring API (step 115) had no caller, so it was removed with
FastAPI, uvicorn and the OpenTelemetry instrumentation.

## Configuration

Both workers refuse to start (exit 2, one `ERROR` line naming the variable) when required
settings are missing or invalid.

| variable | worker | default | notes |
|---|---|---|---|
| `CLICKHOUSE_URL` | both | `http://clickhouse.netsoldier.svc:8123` | contract v2 §6 |
| `CLICKHOUSE_USER` | both | required | `CLICKHOUSE_USERNAME` is not read |
| `CLICKHOUSE_PASSWORD` | both | required | |
| `CLICKHOUSE_DATABASE` | both | `netsoldier` | |
| `RITA_DATABASE` | beacon-sync | `netsoldier_rita` | |
| `STATE_DIR` | both | `/var/lib/ml-anomaly` | must be writable and persistent (see below) |
| `METRICS_PORT` | both | 9101 beacon-sync, 9102 flow-anomaly | path `/metrics` |
| `LOG_LEVEL` | both | `INFO` | JSON lines on stderr |
| `BEACON_SYNC_INTERVAL_SECONDS` | beacon-sync | 300 | |
| `BEACON_SCORE_THRESHOLD` | beacon-sync | 0.7 | RITA beacon score |
| `BEACON_RESCORE_DELTA` | beacon-sync | 0.1 | score rise that re-emits a known beacon |
| `BEACON_MAX_AGE_HOURS` | beacon-sync | 24 | older observations are ignored and forgotten |
| `MODEL_SIGNING_KEY_FILE` | flow-anomaly | required | file from a Secret, ≥ 32 bytes (`MODEL_SIGNING_KEY` inline also accepted) |
| `MODEL_DIR` | flow-anomaly | `/models` | |
| `FLOW_WINDOW_MINUTES` | flow-anomaly | 10 | must divide 1440 |
| `FLOW_LATENESS_MINUTES` | flow-anomaly | 10 | how long after a flow ends its row may still arrive |
| `FLOW_SYNC_INTERVAL_SECONDS` | flow-anomaly | 60 | a pass with nothing complete costs one `SELECT now()` |
| `FLOW_BASELINE_DAYS` | flow-anomaly | 7 | training look-back |
| `FLOW_SCORE_THRESHOLD` | flow-anomaly | 0.65 | |
| `FLOW_MAX_BACKLOG_HOURS` | flow-anomaly | 24 | windows older than this behind the cursor are skipped and counted |

ClickHouse grants, nothing more:

- beacon-sync: `SELECT ON netsoldier_rita.threat_mixtape`, `SELECT, INSERT ON netsoldier.ml_beacons`
- flow-anomaly: `SELECT ON netsoldier.zeek_conn`, `SELECT, INSERT ON netsoldier.ml_anomalies`

## Failure is visible

Every cycle that fails logs one `WARNING` with a reason and increments
`ml_anomaly_cycle_failures_total{reason}`: `auth` (wrong user or password), `access_denied`
(missing grant), `schema` (missing table or column), `unreachable`, `clickhouse` (other server
errors), `bad_response`, `state` (state directory not writable), `model_store`, `internal`.
`ml_anomaly_last_success_timestamp_seconds` only moves on a cycle that completed.

Metrics (all labelled `worker="beacon_sync"` or `worker="flow_anomaly"`; every series exists from
the first scrape):

| metric | type | meaning |
|---|---|---|
| `ml_anomaly_last_success_timestamp_seconds` | gauge | last completed cycle (0 = never) |
| `ml_anomaly_cycles_total{outcome}` | counter | `ok` / `failed` |
| `ml_anomaly_cycle_failures_total{reason}` | counter | see above |
| `ml_anomaly_cycle_duration_seconds` | histogram | wall time per cycle |
| `ml_anomaly_clickhouse_up` | gauge | 1 when ClickHouse answered and accepted the credentials |
| `ml_anomaly_rows_read_total{table}` | counter | `threat_mixtape` rows / `zeek_conn` device windows |
| `ml_anomaly_rows_written_total{table}` | counter | `ml_beacons` / `ml_anomalies` |
| `ml_anomaly_rows_rejected_total{reason}` | counter | unusable rows read |
| `ml_anomaly_beacons_emitted_total{reason}` | counter | beacon-sync: `new` / `changed` |
| `ml_anomaly_beacons_tracked` | gauge | beacon-sync: size of the emission state |
| `ml_anomaly_model_loaded` | gauge | flow: 1 when a verified healthy model is serving |
| `ml_anomaly_model_created_timestamp_seconds` | gauge | flow: training time of the serving model |
| `ml_anomaly_last_training_healthy` | gauge | flow: 1 if the last training was healthy |
| `ml_anomaly_last_training_timestamp_seconds` | gauge | flow: last training attempt |
| `ml_anomaly_next_training_timestamp_seconds` | gauge | flow: next attempt (backoff) |
| `ml_anomaly_trainings_total{outcome}` | counter | flow: `healthy` / `unhealthy` / `insufficient_data` / `failed` |
| `ml_anomaly_model_rejected_total{reason}` | counter | flow: stored models refused (tampering shows up here) |
| `ml_anomaly_flow_cursor_timestamp_seconds` | gauge | flow: end of the newest scored window |
| `ml_anomaly_flow_windows_scored_total` | counter | flow: device windows scored |
| `ml_anomaly_flow_windows_skipped_total{reason}` | counter | flow: `backlog` / `reconfigured` |
| `ml_anomaly_flow_late_rows_total` | counter | flow: rows that arrived later than the lateness |

## Flow scoring: arrival-driven windows

A `conn.log` row is written when the connection ends and carries its start time, so a 44-minute
upload is 44 minutes "old" when it arrives. The worker therefore places each row by

    eff = clamp(start + duration, ingested_at - lateness, ingested_at)

and scores window `[w, w + W)` once the ClickHouse clock passes `w + W + lateness + 60 s`. Every
row falls into exactly one window, a window is scored once and only when complete, and a backlog
flushed after an outage lands in the window it arrived in (tagged `late-arrivals`) instead of in
windows already scored. Training reads the same windows with the same rule. Features are per
originator: `bytes_out` = `orig_bytes`, `bytes_in` = `resp_bytes`.

The cursor (`STATE_DIR/flow-cursor.json`) is written after each pass's insert; a pass re-run
after a crash skips rows `ml_anomalies` already has. First start begins at the current edge.
`ml_anomalies.timestamp` is the end of the window (when the behaviour was observed).

### Schema dependency

The flow worker needs `zeek_conn.ingested_at`, the server-stamped arrival time added by
`deploy/clickhouse/migrations/025_zeek_conn_ingested_at.sql`. On a database without it,
flow-anomaly fails every cycle with `reason="schema"` and a message saying so.

## Beacon sync: emit on change

RITA's `threat_mixtape` is append-only and re-reports every pair on each import. The worker reads
the newest observation per (source, destination, name) and emits a row only when the beacon is
new or has materially changed (score up by `BEACON_RESCORE_DELTA` since the last emission, or a
higher severity). Rows carry RITA's `last_seen` as `timestamp`. SNI beacons (RITA `dst` = `::`)
are keyed by name and written with an empty `dst_ip`. State is in
`STATE_DIR/beacon-state.json` and is reconciled with `ml_beacons` at start.

## Model integrity

`joblib.load` unpickles, i.e. runs code, in the flow worker. The artifact digest is therefore
trusted only through an HMAC-SHA256 signature over the metadata, keyed by a Secret that is never
on the model volume. Refused: unsigned or digest-less metadata, a signature that does not verify,
a `latest` that is not `v` + 14 digits, symlinks, oversized files, unhealthy or incompatible
models. The artifact is read once and the same bytes are hashed and unpickled. `latest` moves only
when a model passed the health gate; artifacts are pruned (5 kept) after every training; failed
trainings back off from 1 h to 24 h.

Not covered: whoever can read the key (or the worker's memory) can sign; a writer of the volume
can delete models (the worker retrains) or point `latest` at an older signed healthy model.

## Dependencies and tests

`requirements.txt` (runtime) and `requirements-dev.txt` are generated from `pyproject.toml` with
pip-tools 7.7.0 in `python:3.13-slim`; the command is in each file's header. The image installs
`requirements.txt` with `--require-hashes`.

```sh
pip install --require-hashes -r requirements-dev.txt && pip install --no-deps -e .
pytest                          # hermetic
tests/integration/run.sh        # real ClickHouse 24.3 in Docker; ML_IT_IMAGE=<tag> also runs the image
```
