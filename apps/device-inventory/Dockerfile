# Build context is the repository ROOT for consistency with the other Go
# images (see the `build-device-inventory` job in .github/workflows/ci.yml and
# /.dockerignore for what the context carries). This module has no `replace`
# directive onto libs/events, so unlike detection-engine and
# killswitch-controller it does not copy that module in — doing so would
# invalidate this image's dependency layer whenever the shared contract
# changed, for no reason.
FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

# Module graph first so dependency download caches independently of sources.
COPY apps/device-inventory/go.mod apps/device-inventory/go.sum apps/device-inventory/
WORKDIR /src/apps/device-inventory
RUN go mod download

COPY apps/device-inventory/ .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /device-inventory ./cmd/device-inventory

FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931

COPY --from=build /device-inventory /device-inventory

EXPOSE 8081

# device-inventory no longer captures: netagent does, and posts frames to the
# /agent/v1/frames endpoint (ADR-0004). It opens no raw socket, binds only the
# unprivileged API port, and needs NO Linux capability and no host network.
USER nonroot:nonroot

ENTRYPOINT ["/device-inventory"]
