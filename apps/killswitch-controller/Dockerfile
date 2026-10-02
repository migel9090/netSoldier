# Build context is the repository ROOT, not this directory: go.mod replaces
# github.com/migel9090/netSoldier/libs/events with ../../libs/events, so the
# shared contract module has to be inside the context or `go mod download`
# cannot resolve the module graph. See /.dockerignore for what the context
# actually carries, and the `build-killswitch-controller` job in .github/workflows/ci.yml.
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

# Module graph first so dependency download caches independently of sources.
COPY libs/events/ libs/events/
COPY apps/killswitch-controller/go.mod apps/killswitch-controller/go.sum apps/killswitch-controller/
WORKDIR /src/apps/killswitch-controller
RUN go mod download

COPY apps/killswitch-controller/ .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /killswitch-controller ./cmd/killswitch-controller

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /killswitch-controller /killswitch-controller

EXPOSE 8084

USER nonroot:nonroot

ENTRYPOINT ["/killswitch-controller"]
