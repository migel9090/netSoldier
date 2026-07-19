#!/bin/sh
# Golden test for the first-party JA4 implementation baked into the zeek
# image. Replays the test pcaps through `zeek -r ... netsoldier-ja4` (the
# same ZEEKPATH resolution the site policy uses) and diffs the ssl.log JA4
# values against expected.tsv.
#
# The expected values are cross-validated against Wireshark's independent
# JA4 implementation (tshark 4.6, field tls.handshake.ja4); regenerate the
# synthetic pcap with gen_synthetic.py.
#
# Usage: run.sh [IMAGE]   (default: ghcr.io/migel9090/zeek:main)
set -eu

IMAGE="${1:-ghcr.io/migel9090/zeek:main}"
DIR="$(cd "$(dirname "$0")" && pwd)"

# The zeek binary carries cap_net_raw,cap_net_admin as file capabilities
# (baked into the image so the pod runs non-root). Execing it requires those
# caps in the container bounding set even for offline pcap replay, which uses
# no interface — so grant them here (NET_RAW is a docker default, NET_ADMIN
# is not).
CAPS="--cap-add net_raw --cap-add net_admin"

got=$(docker run --rm $CAPS -v "$DIR:/t:ro" --entrypoint sh "$IMAGE" -c '
    set -eu
    cd /tmp
    for p in handshakes synthetic; do
        mkdir "$p"
        cd "$p"
        zeek -C -r "/t/pcaps/$p.pcap" netsoldier-ja4 LogAscii::use_json=T
        cat ssl.log
        cd /tmp
    done' \
    | sed -n 's/.*"id.orig_p":\([0-9]*\).*"ja4":"\([^"]*\)".*/\1\t\2/p' \
    | sort -n)

expected=$(sort -n "$DIR/expected.tsv")

if [ "$got" != "$expected" ]; then
    echo "JA4 golden test FAILED" >&2
    echo "--- expected ---" >&2
    echo "$expected" >&2
    echo "--- got ---" >&2
    echo "$got" >&2
    exit 1
fi

echo "JA4 golden test passed ($(echo "$got" | wc -l) fingerprints)"

# Phase 2: Intel framework — the intel/intel.dat fixture must produce hits
# for the first-party Intel::JA4 type plus the stock DOMAIN/ADDR seen paths.
intel_out=$(docker run --rm $CAPS -v "$DIR:/t:ro" --entrypoint sh "$IMAGE" -c '
    set -eu
    cd /tmp
    zeek -C -r /t/pcaps/handshakes.pcap /t/intel/site.zeek >/dev/null
    cat intel.log')

for want in Intel::JA4 Intel::DOMAIN Intel::ADDR; do
    if ! printf '%s' "$intel_out" | grep -q "\"seen.indicator_type\":\"$want\""; then
        echo "Intel golden test FAILED: no $want hit in intel.log" >&2
        printf '%s\n' "$intel_out" >&2
        exit 1
    fi
done

echo "Intel golden test passed (JA4/DOMAIN/ADDR hits present)"
