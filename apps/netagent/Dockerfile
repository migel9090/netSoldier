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
FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f AS setcap
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

ENTRYPOINT ["/netagent"]
