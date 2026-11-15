"""Small JSON state files that survive restarts (``STATE_DIR``).

Writes are atomic (temp file, fsync, rename, fsync of the directory), so a
crash leaves either the old or the new state, never a torn file. A file that
cannot be parsed is moved aside rather than silently overwritten, so the
evidence survives and the worker can start from a known point.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path

log = logging.getLogger("ml_anomaly.state")

DEFAULT_STATE_DIR = "/var/lib/ml-anomaly"
_MAX_STATE_BYTES = 16 << 20


class StateError(Exception):
    """The state directory cannot be read or written (a cycle failure)."""

    failure_reason = "state"


class StateFile:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def load(self) -> object | None:
        """Parsed JSON, or None when there is no (usable) state yet."""
        try:
            with self.path.open("rb") as fh:
                data = fh.read(_MAX_STATE_BYTES + 1)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise StateError(f"cannot read state file {self.path}: {exc}") from exc
        try:
            if len(data) > _MAX_STATE_BYTES:
                raise ValueError("state file too large")
            return json.loads(data)
        except ValueError as exc:
            aside = self.path.with_name(f"{self.path.name}.corrupt-{int(time.time())}")
            try:
                os.replace(self.path, aside)
            except OSError as move_exc:
                raise StateError(f"cannot move aside {self.path}: {move_exc}") from move_exc
            log.warning("state file %s is unreadable (%s); moved to %s", self.path, exc, aside)
            return None

    def save(self, obj: object) -> None:
        tmp = self.path.with_name(f".{self.path.name}.tmp")
        data = json.dumps(obj, sort_keys=True, ensure_ascii=False).encode()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with tmp.open("wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
            fsync_dir(self.path.parent)
        except OSError as exc:
            raise StateError(f"cannot write state file {self.path}: {exc}") from exc


def fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
