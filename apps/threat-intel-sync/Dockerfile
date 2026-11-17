# Build context is the repository ROOT (see the `build-threat-intel-sync` job
# in .github/workflows/ci.yml and /.dockerignore for what the context
# carries). go.mod replaces libs/indicator and libs/events with the in-tree
# copies, so both modules have to be inside the context or `go mod download`
# cannot resolve the graph. libs/events supplies the operator-identity rules
# (X-Netsoldier-Actor) of the quarantine API, shared with the killswitch and
# the detection-engine.
FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

# Module graph first so dependency download caches independently of sources.
COPY libs/events/ libs/events/
COPY libs/indicator/ libs/indicator/
COPY apps/threat-intel-sync/go.mod apps/threat-intel-sync/go.sum apps/threat-intel-sync/
WORKDIR /src/apps/threat-intel-sync
RUN go mod download

COPY apps/threat-intel-sync/ .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /threat-intel-sync ./cmd/threat-intel-sync

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

COPY --from=build /threat-intel-sync /threat-intel-sync

EXPOSE 8083

USER nonroot:nonroot

ENTRYPOINT ["/threat-intel-sync"]
