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

got=$(docker run --rm -v "$DIR:/t:ro" --entrypoint sh "$IMAGE" -c '
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
