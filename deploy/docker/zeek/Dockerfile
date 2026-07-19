# netSoldier Zeek sensor: upstream Zeek 8 + passive TLS fingerprinting.
#
# Fingerprinting (pure Zeek script, no compiled plugin):
#   salesforce/ja3 (zkg)        -> ja3, ja3s on ssl.log; JA3 in the Intel
#                                  framework (BSD-3-Clause)
#   scripts/netsoldier-ja4.zeek -> ja4 on ssl.log; first-party clean-room
#                                  implementation of the BSD-licensed JA4 spec
#
# No FoxIO code is included: the JA4+ methods beyond JA4 itself (JA4S, JA4H,
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
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && zkg autoconfig --force \
    && zkg install --force --skiptests \
         https://github.com/salesforce/ja3 \
         --version 502cc6395811c54743b0561419d61900a6df3ff7

COPY scripts/ /usr/local/zeek/share/zeek/site/

# Default to non-root; the Pod securityContext still pins uid 65534 (and the
# init container overrides to 0 only to write the capability xattr). Packages
# live in the image filesystem, world-readable, read-only at runtime.
USER 65534
