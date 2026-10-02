# Build context is the repository ROOT for consistency with the other Go
# images (see the `build-device-inventory` job in .github/workflows/ci.yml and
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
COPY apps/device-inventory/go.mod apps/device-inventory/go.sum apps/device-inventory/
WORKDIR /src/apps/device-inventory
RUN go mod download

COPY apps/device-inventory/ .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /device-inventory ./cmd/device-inventory

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /device-inventory /device-inventory

EXPOSE 8081

# Discovery listens on mDNS/SSDP/LLDP; the deployment grants
# NET_BIND_SERVICE for the privileged ports rather than running as root.
USER nonroot:nonroot

ENTRYPOINT ["/device-inventory"]
