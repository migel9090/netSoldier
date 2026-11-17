#!/bin/sh
# Tests for the zeek image, run against a built image before it is signed.
#
#   1. TLS client fingerprint (JA4-format) golden test: replays the test
#      pcaps through `zeek -r ... netsoldier-tlsfp` (the same ZEEKPATH
#      resolution the site policy uses) and diffs the ssl.log values against
#      expected.tsv. The expected values are cross-validated against
#      Wireshark's independent JA4 implementation (tshark 4.6, field
#      tls.handshake.ja4); regenerate the synthetic pcap with gen_synthetic.py.
#   2. Intel framework: the intel/intel.dat fixture produces TLSFP, DOMAIN and
#      ADDR hits.
#   3. zkg packages: `@load packages` (the site policy's first line) loads the
#      packages installed in the build stage, and ssl.log carries ja3.
#   4. Runtime contents: the package manager and the build toolchain stayed in
#      the build stage, the script tree holds no JavaScript (so ZeekJS never
#      starts Node.js), and the image runs as 65534.
#   5. File capability: zeek refuses to start unless the container's
#      bounding set holds NET_RAW, and starts when it does.
#   6. Live capture under the production security context (non-root,
#      no_new_privs, read-only root filesystem, every capability dropped but
#      NET_RAW): zeek opens AF_PACKET on the container's own interface and
#      sees a packet sent from inside the container. The packet goes to a
#      documentation address (192.0.2.1, RFC 5737) and never leaves the
#      Docker bridge. Started through a shell instead, zeek cannot open the
#      socket: under no_new_privs only a binary the runtime executes
#      directly gets its file capability, so a manifest must not wrap it.
#
# Usage: run.sh [IMAGE]   (default: ghcr.io/migel9090/zeek:main)
set -eu

IMAGE="${1:-ghcr.io/migel9090/zeek:main}"
DIR="$(cd "$(dirname "$0")" && pwd)"

# The zeek binary carries cap_net_raw as a file capability (baked into the
# image so the pod runs non-root). Executing it requires that capability in
# the container's bounding set even for offline pcap replay, which uses no
# interface. NET_RAW is in Docker's default set; it is named here so the
# tests do not depend on that default.
CAPS="--cap-add net_raw"

fail() {
    echo "$1" >&2
    shift
    for extra in "$@"; do printf '%s\n' "$extra" >&2; done
    exit 1
}

# ── 1. TLS client fingerprint golden test ────────────────────────────────────
got=$(docker run --rm $CAPS -v "$DIR:/t:ro" --entrypoint sh "$IMAGE" -c '
    set -eu
    cd /tmp
    for p in handshakes synthetic; do
        mkdir "$p"
        cd "$p"
        zeek -C -r "/t/pcaps/$p.pcap" netsoldier-tlsfp LogAscii::use_json=T
        cat ssl.log
        cd /tmp
    done' \
    | sed -n 's/.*"id.orig_p":\([0-9]*\).*"tls_client_fp":"\([^"]*\)".*/\1\t\2/p' \
    | sort -n)

expected=$(sort -n "$DIR/expected.tsv")

if [ "$got" != "$expected" ]; then
    fail "JA4 golden test FAILED" "--- expected ---" "$expected" "--- got ---" "$got"
fi

echo "JA4 golden test passed ($(echo "$got" | wc -l) fingerprints)"

# ── 2. Intel framework ───────────────────────────────────────────────────────
intel_out=$(docker run --rm $CAPS -v "$DIR:/t:ro" --entrypoint sh "$IMAGE" -c '
    set -eu
    cd /tmp
    zeek -C -r /t/pcaps/handshakes.pcap /t/intel/site.zeek >/dev/null
    cat intel.log')

for want in Intel::TLSFP Intel::DOMAIN Intel::ADDR; do
    if ! printf '%s' "$intel_out" | grep -q "\"seen.indicator_type\":\"$want\""; then
        fail "Intel golden test FAILED: no $want hit in intel.log" "$intel_out"
    fi
done

echo "Intel golden test passed (JA4/DOMAIN/ADDR hits present)"

# ── 3. zkg packages load at runtime ──────────────────────────────────────────
ssl_out=$(docker run --rm $CAPS -v "$DIR:/t:ro" --entrypoint sh "$IMAGE" -c '
    set -eu
    cd /tmp
    zeek -C -r /t/pcaps/handshakes.pcap packages LogAscii::use_json=T
    cat ssl.log')

rows=$(printf '%s\n' "$ssl_out" | grep -c '"uid"' || true)
ja3=$(printf '%s\n' "$ssl_out" | grep -c '"ja3":"[0-9a-f]\{32\}"' || true)
if [ "$rows" -eq 0 ] || [ "$ja3" -ne "$rows" ]; then
    fail "zkg package test FAILED: $ja3 of $rows ssl.log rows carry a ja3 hash" "$ssl_out"
fi

echo "zkg package test passed (ja3 on all $rows ssl.log rows)"

# ── 4. Runtime contents ──────────────────────────────────────────────────────
user=$(docker image inspect --format '{{.Config.User}}' "$IMAGE")
[ "$user" = "65534:65534" ] || fail "runtime test FAILED: image user is '$user', not 65534:65534"

docker run --rm --entrypoint sh "$IMAGE" -c '
    for tool in git zkg python3 spicyz zeek-config zeekctl; do
        if command -v "$tool" >/dev/null 2>&1; then
            echo "runtime test FAILED: the runtime image contains $tool" >&2
            exit 1
        fi
    done
    for path in /usr/local/zeek/include /usr/local/zeek/lib/libhilti-rt.a /usr/local/zeek/var/lib/zkg; do
        if [ -e "$path" ]; then
            echo "runtime test FAILED: the runtime image contains $path" >&2
            exit 1
        fi
    done
    # ZeekJS starts Node.js only when a .js/.cjs/.ts file is loaded; the
    # scan exception for the Node.js packages libnode pulls in rests on this.
    js=$(find /usr/local/zeek/share/zeek -name "*.js" -o -name "*.cjs" -o -name "*.ts")
    if [ -n "$js" ]; then
        echo "runtime test FAILED: JavaScript in the script tree: $js" >&2
        exit 1
    fi' || exit 1

echo "Runtime test passed (no package manager, toolchain or JavaScript; user 65534)"

# ── 5. File capability ───────────────────────────────────────────────────────
if docker run --rm --cap-drop ALL "$IMAGE" --version >/dev/null 2>&1; then
    fail "capability test FAILED: zeek starts with an empty bounding set, so the binary carries no file capability"
fi
docker run --rm --cap-drop ALL $CAPS "$IMAGE" --version >/dev/null ||
    fail "capability test FAILED: zeek does not start with $CAPS"

echo "Capability test passed (exec needs NET_RAW in the bounding set)"

# ── 6. Live capture under the production security context ───────────────────
LIVE="--user 65534:65534 --read-only --cap-drop ALL $CAPS --security-opt no-new-privileges"
LIVE="$LIVE --tmpfs /tmp --tmpfs /var/log/zeek:uid=65534,gid=65534"

# Through a shell: the socket is refused, and zeek exits at once (stopped
# after 15 s if it does not, which fails the check).
sid=$(docker run -d $LIVE -v "$DIR:/t:ro" --entrypoint sh "$IMAGE" \
    -c 'exec zeek -C -i af_packet::eth0 /t/live.zeek')
i=0
while [ "$(docker inspect --format '{{.State.Running}}' "$sid")" = true ] && [ "$i" -lt 15 ]; do
    sleep 1
    i=$((i + 1))
done
shell_out=$(docker logs "$sid" 2>&1)
docker rm -f "$sid" >/dev/null
if ! printf '%s\n' "$shell_out" | grep -q 'Operation not permitted'; then
    fail "live capture test FAILED: zeek started from a shell was expected to be refused the socket" "$shell_out"
fi

# Executed directly, as the manifests run it.
cid=$(docker run -d $LIVE -v "$DIR:/t:ro" "$IMAGE" -C -i af_packet::eth0 /t/live.zeek)
trap 'docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT

i=0
while [ "$(docker inspect --format '{{.State.Running}}' "$cid")" = true ] && [ "$i" -lt 30 ]; do
    docker exec "$cid" bash -c 'echo netsoldier-live-test >/dev/udp/192.0.2.1/9' 2>/dev/null || true
    sleep 1
    i=$((i + 1))
done

live_out=$(docker logs "$cid" 2>&1)
if ! printf '%s\n' "$live_out" | grep -q 'netsoldier live capture: ok'; then
    fail "live capture test FAILED: zeek saw no packet on eth0 within 30 s" "$live_out"
fi

echo "Live capture test passed (AF_PACKET as 65534 with NET_RAW only, no_new_privs, read-only root; refused through a shell)"
