# Build context is the repository ROOT, not this directory: go.mod replaces
# github.com/migel9090/netSoldier/libs/events with ../../libs/events, so the
# shared contract module has to be inside the context or `go mod download`
# cannot resolve the module graph. See /.dockerignore for what the context
# actually carries, and the `build` job in .github/workflows/ci.yml.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build

ARG TARGETOS
ARG TARGETARCH

RUN apk add --no-cache ca-certificates

WORKDIR /src

# Module graph first so dependency download caches independently of sources.
COPY libs/events/ libs/events/
COPY apps/detection-engine/go.mod apps/detection-engine/go.sum apps/detection-engine/
WORKDIR /src/apps/detection-engine
RUN go mod download

COPY apps/detection-engine/ .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /detection-engine ./cmd/detection-engine

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /detection-engine /detection-engine

EXPOSE 8080
USER nonroot:nonroot

ENTRYPOINT ["/detection-engine"]
