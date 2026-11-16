"""Helpers for the ClickHouse integration tests (see run.sh).

Without ML_IT_URL every test marked with ``needs_clickhouse`` is skipped, so
plain `pytest` stays hermetic.
"""

import os

import httpx
import pytest
from ml_anomaly.clickhouse import ClickHouseClient

URL = os.environ.get("ML_IT_URL", "")

needs_clickhouse = [
    pytest.mark.integration,
    pytest.mark.skipif(not URL, reason="ML_IT_URL not set; run tests/integration/run.sh"),
]


class Admin:
    def __init__(self) -> None:
        self.http = httpx.Client(
            timeout=60,
            headers={
                "X-ClickHouse-User": os.environ.get("ML_IT_ADMIN_USER", ""),
                "X-ClickHouse-Key": os.environ.get("ML_IT_ADMIN_PASSWORD", ""),
            },
        )

    def run(self, sql: str, body: bytes | None = None) -> str:
        if body is None:
            r = self.http.post(URL, content=sql.encode())
        else:
            r = self.http.post(URL, params={"query": sql}, content=body)
        assert r.status_code == 200, r.text
        return r.text

    def scalar(self, sql: str) -> str:
        return self.run(sql).strip()


def worker_client(kind: str, **kw) -> ClickHouseClient:
    return ClickHouseClient(
        URL,
        user=os.environ.get(f"ML_IT_{kind.upper()}_USER", ""),
        password=os.environ.get(f"ML_IT_{kind.upper()}_PASSWORD", ""),
        **kw,
    )
