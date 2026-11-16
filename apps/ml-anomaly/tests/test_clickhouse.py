"""ClickHouse HTTP client: credentials, parsing, error classification (125.23).

Hermetic: a mock transport plays the server. The SQL itself runs against a
real ClickHouse in tests/integration.
"""

import json

import httpx
import pytest
from ml_anomaly.beacon import BeaconDetection
from ml_anomaly.clickhouse import ClickHouseClient, ClickHouseError, utc_epoch
from ml_anomaly.config import ConfigError, clickhouse_settings
from ml_anomaly.iforest import FlowAnomaly

PASSWORD = "pw"  # noqa: S105 — a mock transport; nothing real behind it


def _client(handler, **kw):
    return ClickHouseClient(
        "http://ch.test:8123",
        user="ml_beacon",
        password=PASSWORD,
        transport=httpx.MockTransport(handler),
        **kw,
    )


def _rows(*objs, raw_extra=b""):
    body = b"".join(json.dumps(o, ensure_ascii=False).encode() + b"\n" for o in objs)
    return httpx.Response(200, content=body + raw_extra)


def test_credentials_are_sent_in_clickhouse_headers():
    seen = {}

    def handler(request):
        seen.update(request.headers)
        return _rows({"t": 1_794_830_400})

    assert _client(handler).server_time() == 1_794_830_400
    assert seen["x-clickhouse-user"] == "ml_beacon"
    assert seen["x-clickhouse-key"] == "pw"


def test_settings_follow_contract_names():
    """ML-1: the workers read CLICKHOUSE_USERNAME and fell back to `default`
    with an empty password; contract v2 section 6 says CLICKHOUSE_USER."""
    s = clickhouse_settings(
        {"CLICKHOUSE_URL": "http://ch:8123", "CLICKHOUSE_USER": "u", "CLICKHOUSE_PASSWORD": "p"}
    )
    assert (s.url, s.user, s.password) == ("http://ch:8123", "u", "p")
    with pytest.raises(ConfigError, match="CLICKHOUSE_USERNAME is no longer read"):
        clickhouse_settings({"CLICKHOUSE_USERNAME": "u", "CLICKHOUSE_PASSWORD": "p"})
    with pytest.raises(ConfigError, match="CLICKHOUSE_PASSWORD"):
        clickhouse_settings({"CLICKHOUSE_USER": "u"})
    with pytest.raises(ConfigError, match="plain identifier"):
        clickhouse_settings(
            {"CLICKHOUSE_USER": "u", "CLICKHOUSE_PASSWORD": "p", "RITA_DATABASE": "x; DROP"}
        )


@pytest.mark.parametrize("sep", ["\u0085", "\u2028", "\u2029"])
def test_unicode_line_separators_inside_values_do_not_split_rows(sep):
    """ML-4: str.splitlines() split rows on U+0085 and friends, which
    ClickHouse emits unescaped inside strings, and aborted the whole pass."""
    name = f"a{sep}b.example"

    def handler(_request):
        return _rows(
            {
                "src_s": "::ffff:192.168.1.50",
                "dst_s": "::",
                "name": name,
                "btype": "sni",
                "score": 0.9,
                "conns": 9,
                "seen": 1_794_830_000,
            },
            {
                "src_s": "::ffff:192.168.1.51",
                "dst_s": "::",
                "name": "ok.example",
                "btype": "sni",
                "score": 0.8,
                "conns": "18446744073709551615",
                "seen": "1794830000",
            },
        )

    rows, rejected = _client(handler).fetch_beacons(0.7, since=0)
    assert rejected == 0
    assert [r.fqdn for r in rows] == [name, "ok.example"]
    assert rows[1].connection_count == 2**64 - 1  # quoted UInt64 accepted


def test_values_are_query_parameters_not_sql_text():
    captured = {}

    def handler(request):
        captured["params"] = dict(request.url.params)
        captured["sql"] = request.content.decode()
        return _rows()

    _client(handler, rita_database="netsoldier_rita").fetch_beacons(0.75, since=1234)
    assert captured["params"]["param_min_score"] == "0.75"
    assert captured["params"]["param_since"] == "1234"
    assert captured["params"]["param_rita"] == "netsoldier_rita"
    assert "0.75" not in captured["sql"]
    assert captured["params"]["output_format_json_validate_utf8"] == "1"


def test_flow_window_bounds_follow_the_placement_rule():
    captured = {}

    def handler(request):
        captured.update(request.url.params)
        return _rows(
            {
                "window_start": 1_794_829_800,
                "src_ip": "192.168.1.5",
                "conn_count": 2,
                "bytes_out": "5000000000",
                "bytes_in": 10,
                "dst_fanout": 1,
                "port_fanout": 1,
                "avg_duration_ms": 1.5,
                "late_rows": 0,
            }
        )

    (w,) = _client(handler).fetch_flow_windows(600, 600, 1_794_829_800, 1_794_830_400)
    assert captured["param_start"] == "1794829800"
    assert captured["param_end"] == "1794830400"
    assert captured["param_arr_end"] == str(1_794_830_400 + 600)
    assert w.window_start == "2026-11-16 11:50:00"
    assert w.bytes_out == 5_000_000_000


def _error(status, code, text):
    def handler(_request):
        return httpx.Response(
            status, headers={"X-ClickHouse-Exception-Code": str(code)}, text=text
        )

    return handler


@pytest.mark.parametrize(
    ("status", "code", "text", "reason"),
    [
        (403, 516, "Code: 516. DB::Exception: x: Authentication failed", "auth"),
        (500, 497, "Code: 497. DB::Exception: Not enough privileges", "access_denied"),
        (404, 60, "Code: 60. Unknown table expression identifier", "schema"),
        (500, 241, "Code: 241. Memory limit exceeded", "clickhouse"),
    ],
)
def test_errors_are_classified(status, code, text, reason):
    with pytest.raises(ClickHouseError) as exc:
        _client(_error(status, code, text)).server_time()
    assert exc.value.reason == reason
    assert exc.value.code == code


def test_auth_error_names_the_variables_to_check():
    with pytest.raises(ClickHouseError, match="CLICKHOUSE_USER and CLICKHOUSE_PASSWORD"):
        _client(_error(403, 516, "Code: 516. Authentication failed")).server_time()


def test_missing_ingested_at_gets_an_explicit_message():
    handler = _error(404, 47, "Code: 47. Unknown expression identifier 'ingested_at'")
    with pytest.raises(ClickHouseError, match="no ingested_at column") as exc:
        _client(handler).fetch_flow_windows(600, 600, 0, 600)
    assert exc.value.reason == "schema"


def test_unreachable_server():
    def handler(_request):
        raise httpx.ConnectError("connection refused")

    with pytest.raises(ClickHouseError) as exc:
        _client(handler).server_time()
    assert exc.value.reason == "unreachable"


def test_garbage_body_is_bad_response():
    def handler(_request):
        return httpx.Response(200, content=b"<html>proxy error</html>\n")

    with pytest.raises(ClickHouseError) as exc:
        _client(handler).server_time()
    assert exc.value.reason == "bad_response"


def test_malformed_beacon_rows_are_counted_not_fatal():
    def handler(_request):
        return _rows(
            {
                "src_s": "a",
                "dst_s": "b",
                "name": "",
                "btype": "ip",
                "score": None,
                "conns": 1,
                "seen": 1,
            },
            {"unexpected": True},
        )

    rows, rejected = _client(handler).fetch_beacons(0.7, since=0)
    assert rows == []
    assert rejected == 2


def test_inserts_carry_observation_times():
    bodies = []

    def handler(request):
        bodies.append((request.url.params["query"], request.content))
        return httpx.Response(200)

    c = _client(handler)
    det = BeaconDetection(
        "192.168.1.50",
        "",
        0.9,
        10,
        68,
        "high",
        "sni",
        "c2.example",
        ("beacon",),
        last_seen=1_794_830_000,
    )
    assert c.insert_beacons([det]) == 1
    anomaly = FlowAnomaly(
        "192.168.1.66",
        "2026-11-16 11:50:00",
        0.8,
        60,
        "medium",
        1,
        5_000_000_000,
        1,
        1,
        1,
        1.0,
        "v20261116120000",
        ("anomaly",),
    )
    assert c.insert_anomalies([anomaly], 600) == 1
    (q1, b1), (_, b2) = bodies
    assert "ml_beacons" not in q1  # table names travel as parameters
    beacon = json.loads(b1)
    assert beacon["timestamp"] == 1_794_830_000
    row = json.loads(b2)
    assert row["window_start"] == utc_epoch("2026-11-16 11:50:00")
    assert row["timestamp"] == row["window_start"] + 600
    assert c.insert_beacons([]) == 0
