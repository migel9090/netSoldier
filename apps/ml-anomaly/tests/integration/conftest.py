"""Fixtures for the ClickHouse integration tests (see run.sh)."""

import pytest

from tests.integration.helpers import URL, Admin


@pytest.fixture
def admin():
    if not URL:
        pytest.skip("ML_IT_URL not set; run tests/integration/run.sh")
    a = Admin()
    for table in (
        "netsoldier.zeek_conn",
        "netsoldier.ml_anomalies",
        "netsoldier.ml_beacons",
        "netsoldier_rita.threat_mixtape",
    ):
        a.run(f"TRUNCATE TABLE {table}")
    # count() without FINAL must see every inserted row: no merges during a test
    a.run("SYSTEM STOP MERGES netsoldier.ml_anomalies")
    a.run("SYSTEM STOP MERGES netsoldier.ml_beacons")
    yield a
    a.run("SYSTEM START MERGES netsoldier.ml_anomalies")
    a.run("SYSTEM START MERGES netsoldier.ml_beacons")
