"""Environment configuration and logging shared by the two workers.

ClickHouse settings follow contract v2 section 6 exactly: ``CLICKHOUSE_URL``,
``CLICKHOUSE_USER`` and ``CLICKHOUSE_PASSWORD``, the same names the Go
services read. There is deliberately no fallback to the ``default`` account
or to an empty password: a worker that is not given credentials refuses to
start instead of running every cycle against an account that does not let it
in.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

DEFAULT_CLICKHOUSE_URL = "http://clickhouse.netsoldier.svc:8123"


class ConfigError(ValueError):
    """The environment does not describe a runnable worker."""


@dataclass(frozen=True)
class ClickHouseSettings:
    url: str
    user: str
    password: str
    database: str = "netsoldier"
    rita_database: str = "netsoldier_rita"


def clickhouse_settings(env: Mapping[str, str] | None = None) -> ClickHouseSettings:
    env = os.environ if env is None else env
    problems: list[str] = []
    user = env.get("CLICKHOUSE_USER", "").strip()
    password = env.get("CLICKHOUSE_PASSWORD", "")
    if not user:
        hint = ""
        if env.get("CLICKHOUSE_USERNAME"):
            hint = " (CLICKHOUSE_USERNAME is no longer read; rename it to CLICKHOUSE_USER)"
        problems.append("CLICKHOUSE_USER is not set" + hint)
    if not password:
        problems.append("CLICKHOUSE_PASSWORD is not set")
    url = env.get("CLICKHOUSE_URL", DEFAULT_CLICKHOUSE_URL).strip()
    if not url.startswith(("http://", "https://")):
        problems.append(f"CLICKHOUSE_URL must be an http(s) URL, got {url!r}")
    database = env.get("CLICKHOUSE_DATABASE", "netsoldier").strip()
    rita_database = env.get("RITA_DATABASE", "netsoldier_rita").strip()
    for name, value in (("CLICKHOUSE_DATABASE", database), ("RITA_DATABASE", rita_database)):
        # Database names are interpolated into SQL, so only plain identifiers.
        if not value or not value.replace("_", "").isalnum() or not value.isascii():
            problems.append(f"{name} must be a plain identifier, got {value!r}")
    if problems:
        raise ConfigError("; ".join(problems))
    return ClickHouseSettings(
        url=url, user=user, password=password, database=database, rita_database=rita_database
    )


def env_int(env: Mapping[str, str], name: str, default: int, lo: int, hi: int) -> int:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from None
    if not lo <= value <= hi:
        raise ConfigError(f"{name} must be between {lo} and {hi}, got {value}")
    return value


def env_float(env: Mapping[str, str], name: str, default: float, lo: float, hi: float) -> float:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = float(raw)
    except ValueError:
        raise ConfigError(f"{name} must be a number, got {raw!r}") from None
    # `not lo <= value <= hi` is also true for NaN.
    if not lo <= value <= hi:
        raise ConfigError(f"{name} must be between {lo} and {hi}, got {raw}")
    return value


class _JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "time": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False)


def setup_logging() -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_JSONFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    try:
        root.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())
    except ValueError:
        root.setLevel(logging.INFO)
    # one INFO line per HTTP request would drown the workers' own lines;
    # failures are logged by the workers with their reason
    for noisy in ("httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
