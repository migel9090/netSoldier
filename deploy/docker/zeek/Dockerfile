# netSoldier Zeek sensor: upstream Zeek 8 + passive TLS fingerprinting.
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
# docs/adr/0003-first-party-ja4.md. Golden test: test/run.sh.
#
# amd64 only: Zeek runs solely on the proxmox-soc (x86) profile.
FROM zeek/zeek:8.0.8

USER root

# git is required by zkg to clone packages; installed defensively in case
# the base image trims it. Pinning git's exact patch version across Debian
# point releases is brittle, so DL3008 is intentionally ignored.
# git: required by zkg to clone packages. libcap2-bin: provides setcap so we
# can bake the capture capabilities into the binary at build time (see below).
# Pinning exact patch versions across Debian point releases is brittle.
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends git libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && zkg autoconfig --force \
    && zkg install --force --skiptests \
         https://github.com/salesforce/ja3 \
         --version 502cc6395811c54743b0561419d61900a6df3ff7

COPY scripts/ /usr/local/zeek/share/zeek/site/

# Bake the capture capabilities into the binary as *file capabilities*. This
# lets the pod run fully non-root: at runtime the kernel grants a non-root
# process cap_net_raw/cap_net_admin on exec because they are file caps AND
# present in the container's bounding set (Pod securityContext capabilities:
# add). No root init container, no runtime setcap — even with
# allowPrivilegeEscalation:false (no_new_privs), file caps within the bounding
# set are honored. readOnlyRootFilesystem is fine: caps are read-only xattrs.
RUN setcap cap_net_raw,cap_net_admin+ep /usr/local/zeek/bin/zeek

USER 65534
