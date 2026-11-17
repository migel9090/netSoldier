# netSoldier Suricata sensor: Suricata 8 from Debian, run as a non-root user.
#
# Suricata and suricata-update come from Debian trixie-backports, which
# carries the current upstream 8.0 release (trixie itself has 7.0). Debian
# packages rather than a source build: the scanners see the Suricata version
# through dpkg, Debian's security tracker covers it, arm64 needs no
# cross-compiler, and the image builds in a minute. The base is the same
# Debian release as the zeek image's runtime, so the two sensors share one
# set of base packages to keep patched.
#
# One image for the three containers of the Suricata pod: the sensor
# (`suricata ... --af-packet`), the init container that seeds the datasets
# and runs suricata-update, and the rules updater (Python, suricata-update,
# suricatasc). Built for linux/amd64 by CI (Suricata runs on the proxmox-soc
# profile only); linux/arm64 builds too. Test: test/run.sh.

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Not pinned: Debian keeps only the current version of a package in its
# archive, so an exact pin breaks the build at the next security update
# (scan-exceptions.toml, DL3008). The weekly rebuild takes those updates,
# for the base packages too (apt-get upgrade); test/run.sh asserts the
# major version.
#
# The capture binary. Only the sensor container needs a capability, and a
# binary with file capabilities in the effective set cannot even be
# executed when its capabilities are missing from the container's bounding
# set: the init container and the updater (every capability dropped) run
# suricata-update, which executes `suricata --build-info` and `suricata -V`
# from the directory it lives in. So Debian's /usr/bin/suricata stays as
# packaged, and /usr/local/bin/suricata, a copy that is first on PATH and is
# the entrypoint, carries the one capability AF_PACKET capture needs:
# CAP_NET_RAW for the packet socket. Promiscuous mode is a packet-socket
# membership and fanout is a socket option, neither needs CAP_NET_ADMIN.
# Without it Suricata cannot change the NIC's offload settings (it warns and
# carries on); those belong to the host that sets up the mirror interface.
# No thread affinity or priorities are configured, so no CAP_SYS_NICE
# either. test/run.sh captures live with nothing but NET_RAW in the bounding
# set.
#
# A non-root process gets a capability only from file caps that are also in
# the bounding set (securityContext.capabilities.add); a plain
# capabilities.add does nothing for it (audit DP-7). With
# allowPrivilegeEscalation: false the kernel still grants it, but only to
# a binary the runtime executes directly: the container's command must be
# suricata itself, not a shell that starts it. libcap2-bin (setcap) is
# removed again in the same layer.
RUN echo 'deb http://deb.debian.org/debian trixie-backports main' \
         > /etc/apt/sources.list.d/backports.list \
    && apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends -t trixie-backports \
         suricata \
         suricata-update \
    && apt-get install -y --no-install-recommends libcap2-bin \
    && install -m 0755 /usr/bin/suricata /usr/local/bin/suricata \
    && setcap cap_net_raw+ep /usr/local/bin/suricata \
    && getcap /usr/local/bin/suricata \
    && apt-get purge -y --auto-remove libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -o 65534 -g 65534 /var/lib/suricata /var/log/suricata /run/suricata \
    && /usr/bin/suricata --build-info | grep -E '^This is Suricata version 8\.'

ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

USER 65534:65534

# The manifests set the command (suricata -c <config> --af-packet ...).
ENTRYPOINT ["/usr/local/bin/suricata"]
