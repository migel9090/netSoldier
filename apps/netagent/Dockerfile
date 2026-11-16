# netSoldier netagent: the only first-party image with raw network access
# (ADR-0004). Built from the repository ROOT like the other Go images (see
# /.dockerignore for what the context carries). This module has no `replace`
# directive onto libs/, so it copies nothing from there.
FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

# Module graph first so dependency download caches independently of sources.
COPY apps/netagent/go.mod apps/netagent/go.sum apps/netagent/
WORKDIR /src/apps/netagent
RUN go mod download

COPY apps/netagent/ .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /netagent ./cmd/netagent

# setcap stage: bake CAP_NET_RAW into the binary as a *file* capability. A
# non-root process gets a capability only from file caps that are also in the
# container's bounding set (securityContext.capabilities.add: [NET_RAW]) — a
# plain capabilities.add does nothing without them (audit DP-7/DI-4). File
# caps are honoured even with allowPrivilegeEscalation:false (no_new_privs),
# so no root init container and no runtime setcap are needed. This mirrors
# deploy/docker/zeek/Dockerfile. amd64/arm64 both support xattr file caps.
# The stage runs on the BUILD platform like the compile stage: setcap only
# writes an extended attribute, which does not depend on the binary's
# architecture, so the arm64 image needs no emulator (QEMU) on the amd64
# runner.
FROM --platform=$BUILDPLATFORM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS setcap
RUN apk add --no-cache libcap
COPY --from=build /netagent /netagent
RUN setcap cap_net_raw+ep /netagent && getcap /netagent

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

# COPY --from preserves the file capability xattr (BuildKit carries xattrs
# across stages). Nothing else is in the image.
COPY --from=setcap /netagent /netagent

# No EXPOSE: the agent never listens. It connects out to device-inventory and
# the killswitch, and reports its own health through a file and its heartbeat.
USER nonroot:nonroot

# The image has no shell, so the check is the agent's own `health` command:
# exit 0 when the health file the running agent rewrites every heartbeat is
# fresh, 1 otherwise (it opens no socket). Podman and Docker run this;
# Kubernetes ignores it and runs the same command as its exec probes
# (deploy/kustomize/base/netagent). It needs NETAGENT_HEALTH_FILE, which every
# deployment sets: without it the agent writes no file and is reported
# unhealthy, which is the truth.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["/netagent", "health"]

ENTRYPOINT ["/netagent"]
