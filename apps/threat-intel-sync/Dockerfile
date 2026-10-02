# Build context is the repository ROOT for consistency with the other Go
# images (see the `build-threat-intel-sync` job in .github/workflows/ci.yml and
# /.dockerignore for what the context carries). This module has no `replace`
# directive onto libs/events, so unlike detection-engine and
# killswitch-controller it does not copy that module in — doing so would
# invalidate this image's dependency layer whenever the shared contract
# changed, for no reason.
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

# Module graph first so dependency download caches independently of sources.
COPY apps/threat-intel-sync/go.mod apps/threat-intel-sync/go.sum apps/threat-intel-sync/
WORKDIR /src/apps/threat-intel-sync
RUN go mod download

COPY apps/threat-intel-sync/ .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /threat-intel-sync ./cmd/threat-intel-sync

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /threat-intel-sync /threat-intel-sync

EXPOSE 8083

USER nonroot:nonroot

ENTRYPOINT ["/threat-intel-sync"]
