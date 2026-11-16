# ml-anomaly: RITA beacon sync + Isolation Forest flow worker (Python).
# amd64-only: runs on the proxmox-soc profile alongside RITA/ClickHouse.
# Build context is this directory (apps/ml-anomaly); see .dockerignore.
FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90 AS build

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Dependencies come only from requirements.txt: every package pinned and
# hashed by pip-compile (the command is in that file's header). With
# --require-hashes pip refuses anything unpinned, unhashed or missing from
# the lock; --only-binary keeps sdist build scripts out of the image build.
COPY requirements.txt /tmp/requirements.txt
RUN python -m venv /venv \
    && /venv/bin/pip install --require-hashes --only-binary=:all: -r /tmp/requirements.txt

FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

# Non-root, matches the distroless nonroot uid used across the fleet. The
# state and model directories exist so a misconfigured pod fails on a clear
# permission or read-only error rather than on a missing path.
RUN useradd --uid 65532 --create-home --shell /usr/sbin/nologin app \
    && install -d -o 65532 -g 65532 /var/lib/ml-anomaly /models
COPY --from=build /venv /venv
COPY src /app/src
RUN python -m compileall -q /app/src
ENV PATH="/venv/bin:$PATH" \
    PYTHONPATH=/app/src \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 65532:65532

# Metrics: beacon-sync 9101, flow-anomaly 9102 (METRICS_PORT overrides).
EXPOSE 9101 9102

# Default: the beacon sync worker. The flow worker runs the same image with
# `python -m ml_anomaly.flowsync`.
ENTRYPOINT ["python", "-m", "ml_anomaly.sync"]
