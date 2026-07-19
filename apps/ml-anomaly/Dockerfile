# ml-anomaly: RITA beacon consumer + Isolation Forest (Python).
# amd64-only — runs on the proxmox-soc profile alongside RITA/ClickHouse.
FROM python:3.12-slim AS build

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY pyproject.toml ./
COPY src ./src

# Build a wheel and install it plus runtime deps into a relocatable prefix.
RUN python -m venv /venv \
    && /venv/bin/pip install --no-cache-dir .

FROM python:3.12-slim

# Non-root, matches the distroless nonroot uid used across the fleet.
RUN useradd --uid 65532 --create-home --shell /usr/sbin/nologin app
COPY --from=build /venv /venv
ENV PATH="/venv/bin:$PATH"

USER 65532:65532

# Default entrypoint runs the beacon sync worker (step 112); the FastAPI
# scoring server (step 115) overrides the command.
ENTRYPOINT ["python", "-m", "ml_anomaly.sync"]
