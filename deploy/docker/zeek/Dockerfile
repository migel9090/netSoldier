# netSoldier Zeek sensor: upstream Zeek 8 + passive TLS/HTTP fingerprinting.
#
# Packages (pure Zeek script, no compiled plugin), loaded via `@load packages`:
#   salesforce/ja3  -> ja3, ja3s on ssl.log; JA3 in the Intel framework
#                      (BSD-3-Clause)
#   FoxIO-LLC/ja4   -> ja4 on ssl.log (BSD-3-Clause)
#                      ja4s on ssl.log, ja4h on http.log (FoxIO License 1.1)
#
# JA4+ (everything except JA4 itself) is FoxIO License 1.1: permissive for
# internal/defensive use, NOT for monetization without a FoxIO OEM license.
# See /NOTICE and docs/adr/0002-tls-fingerprinting.md.
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
    && zkg autoconfig \
    && zkg install --force --skiptests \
         https://github.com/salesforce/ja3 \
         --version 502cc6395811c54743b0561419d61900a6df3ff7 \
    && zkg install --force --skiptests \
         https://github.com/FoxIO-LLC/ja4 \
         --version v0.18.8

# Default to non-root; the Pod securityContext still pins uid 65534 (and the
# init container overrides to 0 only to write the capability xattr). Packages
# live in the image filesystem, world-readable, read-only at runtime.
USER 65534
