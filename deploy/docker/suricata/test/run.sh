#!/bin/sh
# Tests for the suricata image, run against a built image before it is
# signed (modelled on deploy/docker/zeek/test/run.sh).
#
#   1. Offline: a pcap replayed through the image raises an alert in eve.json
#      from a rule shaped like the production IoC rules (tls.sni against an
#      ndjson dataset). The pcap is the zeek test's TLS capture.
#   2. suricata-update, with every capability dropped and no_new_privs as the
#      init container and the rules updater run it, finds Suricata 8 (it
#      executes the capability-free /usr/bin/suricata) and writes a ruleset.
#   3. Runtime: Suricata 8, user 65534, no setcap left behind.
#   4. File capability: the sensor binary refuses to start unless the
#      container's bounding set holds NET_RAW, and starts with NET_RAW alone.
#   5. Live capture under the production security context (non-root,
#      no_new_privs, read-only root filesystem, every capability dropped but
#      NET_RAW, production af-packet settings): Suricata opens AF_PACKET on
#      the container's own interface and alerts on a packet sent from inside
#      the container. The packet goes to a documentation address (192.0.2.1,
#      RFC 5737) and never leaves the Docker bridge. Started through a shell
#      instead, Suricata is refused the socket: under no_new_privs only a
#      binary the runtime executes directly gets its file capability.
#
# Usage: run.sh [IMAGE]   (default: ghcr.io/migel9090/suricata:main)
set -eu

IMAGE="${1:-ghcr.io/migel9090/suricata:main}"
DIR="$(cd "$(dirname "$0")" && pwd)"
PCAPS="$(cd "$DIR/../../zeek/test/pcaps" && pwd)"

# The sensor binary carries cap_net_raw as a file capability. NET_RAW is in
# Docker's default set; it is named here so the tests do not depend on that.
CAPS="--cap-add net_raw"

fail() {
    echo "$1" >&2
    shift
    for extra in "$@"; do printf '%s\n' "$extra" >&2; done
    exit 1
}

# ── 1. Offline replay ────────────────────────────────────────────────────────
eve=$(docker run --rm $CAPS -v "$DIR:/t:ro" -v "$PCAPS:/pcaps:ro" \
    -v "$DIR/data:/var/lib/suricata/data:ro" --entrypoint sh "$IMAGE" -c '
    set -eu
    mkdir /tmp/out
    # The configuration runs workers, a live-capture mode; a file takes single.
    if ! suricata -c /t/suricata.yaml --runmode single -r /pcaps/handshakes.pcap \
            -l /tmp/out >/tmp/out/run.log 2>&1; then
        cat /tmp/out/run.log >&2
        exit 1
    fi
    cat /tmp/out/eve.json')

if ! printf '%s\n' "$eve" | grep '"event_type":"alert"' | grep -q '"signature_id":9900001'; then
    fail "offline test FAILED: no alert 9900001 (TLS SNI in dataset) in eve.json" "$eve"
fi

echo "Offline test passed (dataset rule alert in eve.json)"

# ── 2. suricata-update without capabilities ──────────────────────────────────
# The test's own rule file is the only source (a file: URL), so nothing is
# downloaded; the run then checks that the rule landed in the output.
upd=$(docker run --rm --user 65534:65534 --read-only --cap-drop ALL \
    --security-opt no-new-privileges --tmpfs /tmp -v "$DIR:/t:ro" \
    --entrypoint sh "$IMAGE" -c '
    set -eu
    suricata-update --no-test --no-reload --url file:///t/rules/test.rules \
        -D /tmp/data -o /tmp/rules 2>&1
    grep -c "sid:9900001;" /tmp/rules/suricata.rules') ||
    fail "suricata-update test FAILED: it exited non-zero with every capability dropped" "$upd"

if ! printf '%s\n' "$upd" | grep -q 'Found Suricata version 8\.'; then
    fail "suricata-update test FAILED: it did not find Suricata 8" "$upd"
fi

echo "suricata-update test passed (no capabilities, found Suricata 8, ruleset written)"

# ── 3. Runtime ───────────────────────────────────────────────────────────────
user=$(docker image inspect --format '{{.Config.User}}' "$IMAGE")
[ "$user" = "65534:65534" ] || fail "runtime test FAILED: image user is '$user', not 65534:65534"

version=$(docker run --rm $CAPS "$IMAGE" -V)
printf '%s\n' "$version" | grep -q 'Suricata version 8\.' ||
    fail "runtime test FAILED: not Suricata 8" "$version"

docker run --rm --entrypoint sh "$IMAGE" -c '
    if command -v setcap >/dev/null 2>&1; then
        echo "runtime test FAILED: setcap is still installed" >&2
        exit 1
    fi' || exit 1

echo "Runtime test passed ($version, user 65534)"

# ── 4. File capability ───────────────────────────────────────────────────────
if docker run --rm --cap-drop ALL "$IMAGE" -V >/dev/null 2>&1; then
    fail "capability test FAILED: suricata starts with an empty bounding set, so the binary carries no file capability"
fi
docker run --rm --cap-drop ALL $CAPS "$IMAGE" -V >/dev/null ||
    fail "capability test FAILED: suricata does not start with $CAPS"

echo "Capability test passed (exec needs NET_RAW in the bounding set)"

# ── 5. Live capture under the production security context ───────────────────
LIVE="--user 65534:65534 --read-only --cap-drop ALL $CAPS --security-opt no-new-privileges"
LIVE="$LIVE --tmpfs /tmp --tmpfs /var/log/suricata:uid=65534,gid=65534"
LIVE="$LIVE --tmpfs /run/suricata:uid=65534,gid=65534"

cleanup() {
    for c in ${sid:-} ${cid:-}; do docker rm -f "$c" >/dev/null 2>&1 || true; done
}
trap cleanup EXIT

# Through a shell: the socket is refused (Suricata keeps retrying, so the
# container is stopped after the refusal is logged or after 30 s).
sid=$(docker run -d $LIVE -v "$DIR:/t:ro" -v "$DIR/data:/var/lib/suricata/data:ro" \
    --entrypoint sh "$IMAGE" \
    -c 'exec suricata -c /t/suricata.yaml --af-packet=eth0')
i=0
while [ "$i" -lt 30 ] && ! docker logs "$sid" 2>&1 | grep -q 'Operation not permitted'; do
    sleep 1
    i=$((i + 1))
done
shell_out=$(docker logs "$sid" 2>&1)
docker rm -f "$sid" >/dev/null
sid=
if ! printf '%s\n' "$shell_out" | grep -q 'Operation not permitted'; then
    fail "live capture test FAILED: suricata started from a shell was expected to be refused the socket" "$shell_out"
fi

# Executed directly, as the manifests run it.
cid=$(docker run -d $LIVE -v "$DIR:/t:ro" -v "$DIR/data:/var/lib/suricata/data:ro" \
    "$IMAGE" -c /t/suricata.yaml --af-packet=eth0)
seen=no
i=0
while [ "$(docker inspect --format '{{.State.Running}}' "$cid")" = true ] && [ "$i" -lt 60 ]; do
    docker exec "$cid" bash -c 'echo netsoldier-live-test >/dev/udp/192.0.2.1/9' 2>/dev/null || true
    if docker exec "$cid" grep -q '"signature_id":9900002' /var/log/suricata/eve.json 2>/dev/null; then
        seen=yes
        break
    fi
    sleep 1
    i=$((i + 1))
done

if [ "$seen" != yes ]; then
    fail "live capture test FAILED: no alert 9900002 within 60 s" "$(docker logs "$cid" 2>&1 | tail -40)"
fi

echo "Live capture test passed (AF_PACKET as 65534 with NET_RAW only, no_new_privs, read-only root; refused through a shell)"
