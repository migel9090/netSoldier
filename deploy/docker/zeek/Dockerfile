# netSoldier Zeek sensor: upstream Zeek 9 (LTS) + passive TLS fingerprinting.
#
# Fingerprinting (pure Zeek script, no compiled plugin):
#   salesforce/ja3 (zkg)          -> ja3, ja3s on ssl.log; JA3 in the Intel
#                                    framework (BSD-3-Clause)
#   scripts/netsoldier-tlsfp.zeek -> tls_client_fp on ssl.log; first-party
#                                    clean-room impl of the BSD-licensed JA4
#                                    TLS-client fingerprint format ("JA4" is a
#                                    FoxIO trademark, referenced nominatively)
#
# No FoxIO code is included: the FoxIO-licensed JA4+ methods (JA4S, JA4H,
# JA4X, ...) are FoxIO License 1.1 / patent-pending — not monetizable without
# an OEM license — and are deliberately not implemented. See /NOTICE and
# docs/adr/0003-first-party-ja4.md. Tests: test/run.sh.
#
# Why three stages. The upstream image is a development image: it carries
# zkg, git, Python, Perl, the Spicy toolchain, headers and static libraries.
# A scan of it found 64 Critical and 465 High findings, nearly all in tools
# a running sensor never executes. So the upstream image is only a source:
#   upstream  the target platform's Zeek build (binaries are copied out of it)
#   packages  zkg installs the packages and the runtime tree is assembled;
#             git and zkg exist only here
#   runtime   Debian with the shared libraries the zeek binary links against
#             and nothing else Zeek-related but bin/zeek, its own libraries
#             and its scripts
#
# The runtime's Debian release must be the one the upstream image is built
# on (both trixie today): the zeek binary links Debian's libnode, libzmq and
# friends by soname. The build fails if a library is missing (ldd check
# below), so a Zeek bump onto a newer Debian cannot produce a broken image.
#
# Built for linux/amd64 by CI (Zeek runs on the proxmox-soc profile only);
# linux/arm64 builds too. Only the runtime stage runs on the target platform.

FROM zeek/zeek:9.0.1@sha256:524cb0ce29f26a6a954fb9c357a8f92b95812476d8240f0ece26617ace249dd0 AS upstream

# zkg packages are Zeek scripts, which do not depend on the CPU, so this
# stage runs on the build platform (no emulator for an arm64 image). A
# package with a compiled plugin would be built for the wrong architecture
# here: the build refuses one rather than ship it.
FROM --platform=$BUILDPLATFORM zeek/zeek:9.0.1@sha256:524cb0ce29f26a6a954fb9c357a8f92b95812476d8240f0ece26617ace249dd0 AS packages

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# libcap2-bin provides setcap (see below); git, zkg and Python come with the
# upstream image. Debian drops superseded patch versions between point
# releases, so the package is not pinned (scan-exceptions.toml, DL3008).
RUN apt-get update \
    && apt-get install -y --no-install-recommends libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

RUN zkg autoconfig --force \
    && zkg install --force --skiptests \
         https://github.com/salesforce/ja3 \
         --version 502cc6395811c54743b0561419d61900a6df3ff7 \
    && if [ -n "$(find /usr/local/zeek/lib/zeek/plugins -type f ! -name README -print -quit)" ]; then \
         echo "a zkg package installed a compiled plugin; build it in a target-platform stage" >&2; \
         exit 1; \
       fi

COPY scripts/ /usr/local/zeek/share/zeek/site/

# The runtime tree: the zeek binary and its shared libraries from the target
# platform's image, the scripts (Zeek's, the zkg packages', ours) from here.
# -L: zkg may link installed packages into site/packages.
COPY --from=upstream /usr/local/zeek/bin/zeek /rootfs/usr/local/zeek/bin/zeek
COPY --from=upstream /usr/local/zeek/lib/ /tmp/upstream-lib/
RUN mkdir -p /rootfs/usr/local/zeek/lib/zeek/plugins /rootfs/usr/local/zeek/share \
    && cp -a /tmp/upstream-lib/lib*.so* /rootfs/usr/local/zeek/lib/ \
    && cp -aL /usr/local/zeek/share/zeek /rootfs/usr/local/zeek/share/zeek \
    && install -d -o 65534 -g 65534 /rootfs/var/log/zeek /rootfs/var/spool/zeek

# Bake the capture capability into the binary as a *file capability*: a
# non-root process gets a capability only from file caps that are also in
# the container's bounding set (securityContext.capabilities.add); a plain
# capabilities.add does nothing for it (audit DP-7). With
# allowPrivilegeEscalation: false (no_new_privs) the kernel still grants
# it, but only to a binary the runtime executes directly: the container's
# command must be zeek itself, not a shell that starts it (test/run.sh
# shows both). AF_PACKET capture needs CAP_NET_RAW alone: promiscuous mode
# is a packet-socket membership, fanout a socket option, and hardware
# timestamping (the one AF_Packet option that would need CAP_NET_ADMIN) is
# off. setcap only writes an extended attribute, so it works on the target
# platform's binary here; COPY --from carries the attribute into the
# runtime image.
RUN setcap cap_net_raw+ep /rootfs/usr/local/zeek/bin/zeek \
    && getcap /rootfs/usr/local/zeek/bin/zeek

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

# Debian's security updates for the base packages, then the libraries
# `ldd /usr/local/zeek/bin/zeek` resolves outside Zeek's own lib/ (their
# dependencies come along). libnode is linked because Zeek's JavaScript
# support is built in; netSoldier loads no JavaScript. Not pinned, as above:
# the weekly rebuild takes Debian's security updates.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
         libkrb5-3 \
         libmaxminddb0 \
         libnode115 \
         libpcap0.8t64 \
         libssl3t64 \
         libuv1t64 \
         libzmq5 \
         zlib1g \
    && rm -rf /var/lib/apt/lists/*

COPY --from=packages /rootfs/ /

# Fail the build, not the sensor, when the upstream image links a library
# the list above does not install.
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN ldd /usr/local/zeek/bin/zeek | (! grep "not found")

ENV PATH=/usr/local/zeek/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

WORKDIR /var/log/zeek
USER 65534:65534

# The manifests set the command (zeek -i af_packet::<iface> <site policy>).
# It must stay zeek itself for the file capability to apply (see above).
ENTRYPOINT ["/usr/local/zeek/bin/zeek"]
