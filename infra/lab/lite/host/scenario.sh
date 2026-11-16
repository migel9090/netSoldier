#!/usr/bin/env bash
# The lite smoke scenario, run on the lab host (as root) after
# `netsoldier-lite install` with netsoldier.lab.conf and lan.sh up.
#
#   scenario.sh            steps 1-10 (phase A: shipped policy, automatic
#                          blocking off, this host and the router protected;
#                          phase B: AUTO_BLOCK=on arranged, then the
#                          restarts; last, an analyst's verdict across a
#                          restart)
#   KEEP_GOING=1 scenario.sh   do not stop at the first failure
#
# Every check prints PASS/FAIL with the evidence it rests on. The profile is
# left installed with netsoldier.lab.conf (automatic blocking off).
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LAN=$HERE/lan.sh
LAB_CONF=$HERE/../netsoldier.lab.conf
NL=/usr/local/sbin/netsoldier-lite
CONF=/etc/netsoldier/netsoldier.conf
IOC=/etc/netsoldier/local-indicators.txt

KS=http://10.231.47.14:8084
DI=http://10.231.47.13:8081
DE=http://10.231.47.12:8080
AG=http://10.231.47.10:3000
UI=http://192.168.77.2:3000
HOST_IP=192.168.77.2
# The MAC of LAN_INTERFACE (nslab0, lan.sh): protected with HOST_IP.
HOST_MAC=02:00:5e:77:00:02
GW_IP=192.168.77.1
GW_MAC=02:00:5e:77:00:01
VICTIM_MAC=02:00:5e:77:00:50
VICTIM_NAME=victim-laptop
ACTOR=lab-operator
TTL=240

# Known-bad for the lab (/etc/netsoldier/local-indicators.txt). Real,
# resolvable names, so "resolves again" means an answer from upstream.
D_PENDING=example.com
D_GW=example.net
D_AUTO=example.org

AUTO_OFF_REASON="auto-block disabled: POLICY_AUTO_BLOCK=off"

FAILED=0
RESULTS=()
say() { printf '%(%H:%M:%S)T %s\n' -1 "$*"; }
pass() { say "PASS $*"; RESULTS+=("PASS $*"); }
fail() {
  say "FAIL $*"
  RESULTS+=("FAIL $*")
  FAILED=1
  [[ ${KEEP_GOING:-0} == 1 ]] || finish
}
finish() {
  echo
  echo "=== summary"
  printf '%s\n' "${RESULTS[@]}"
  exit "$FAILED"
}

# wait_for TIMEOUT CMD...: retry CMD every 2 s; WAITED = seconds it took.
wait_for() {
  local timeout=$1 start=$SECONDS
  shift
  until "$@"; do
    ((SECONDS - start < timeout)) || { WAITED=$((SECONDS - start)); return 1; }
    sleep 2
  done
  WAITED=$((SECONDS - start))
}

OPER=$($NL secret killswitch-operator-token)
INGEST=$($NL secret killswitch-ingest-token)
WSECRET=$($NL secret webhook-secret)
DEVKEY=$($NL secret device-api-key)
DETKEY=$($NL secret detection-api-key)
AGPASS=$($NL secret adguard-password)
UIPASS=$($NL password)

ks() { curl -sS -m 10 -H "Authorization: Bearer $OPER" "$@"; }
di() { curl -sS -m 10 -H "Authorization: Bearer $DEVKEY" "$@"; }
ag_rules() { curl -sS -m 10 -u "netsoldier:$AGPASS" "$AG/control/filtering/status" | jq -r '.user_rules[]?'; }
lookup() { "$LAN" dig "$1" "$2"; }

# sign BODY: the X-Webhook-Signature value for BODY (contract v2, section 2).
sign() {
  python3 -c 'import hmac, hashlib, sys, time
t = str(int(time.time()))
print("t=%s,v1=%s" % (t, hmac.new(sys.argv[1].encode(), (t + "." + sys.argv[2]).encode(), hashlib.sha256).hexdigest()))' \
    "$WSECRET" "$1"
}
# evaluate BODY: POST a signed event with the ingest token, print the response.
evaluate() {
  curl -sS -m 15 -H "Authorization: Bearer $INGEST" -H 'Content-Type: application/json' \
    -H "X-Webhook-Signature: $(sign "$1")" --data-binary "$1" "$KS/evaluate"
}
# event ID CLIENT_IP CLIENT_MAC TARGET_TYPE TARGET_VALUE: a v2 event, critical, 99.
event() {
  jq -cn --arg id "$1" --arg ip "$2" --arg mac "$3" --arg tt "$4" --arg tv "$5" \
    --arg ts "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)" '{schema_version: "2.0", id: $id, timestamp: $ts,
      summary: "lab: synthetic detection", client_ip: $ip, severity: "critical", confidence: 99,
      source: "lab", signal_class: "ioc",
      signals: [{class: "ioc", confidence: 99, indicator: $tv, indicator_type: $tt, source: "lab"}],
      target: {type: $tt, value: $tv}}
      + (if $mac == "" then {} else {client_mac: $mac} end)
      + (if $tt == "domain" then {domain: $tv, matched_ioc: $tv, ioc_type: "domain"} else {} end)'
}

# action_for DETECTION_ID: the action created from that detection, if any.
action_for() {
  local id
  for list in pending active history failed; do
    id=$(ks "$KS/actions/$list" | jq -r --arg d "$1" '.[] | select(.detection_id == $d) | .id' | head -n1)
    [[ -n $id ]] && { echo "$id"; return 0; }
  done
  return 1
}
# alert_for DOMAIN CLIENT_IP [SINCE] -> sets ALERT (JSON).
# SINCE (epoch seconds): only an alert of a lookup made at or after it
# counts. A step that has just made a lookup must pass it: the history also
# holds alerts of earlier lookups, and one recorded under a suppression never
# reaches the killswitch, so waiting for its action would wait for ever.
alert_for() {
  ALERT=$(curl -sS -m 10 "$DE/alerts?limit=200" |
    jq -c --arg d "$1" --arg ip "$2" --argjson since "${3:-0}" \
      '[.[] | select(.domain == $d and .client_ip == $ip and .suppressed != true
                     and ((.timestamp | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) >= $since))]
       | first // empty')
  [[ -n $ALERT ]]
}
state_of() { ks "$KS/actions/$1" | jq -r .state; }
outbox_empty() { curl -s "$DE/metrics" | grep -qx 'detection_engine_outbox_backlog 0'; }
deliveries() {
  curl -s "$DE/metrics" | awk '$1 == "detection_engine_webhook_deliveries_total{result=\"success\"}" {print $2 + 0; f = 1} END {if (!f) print 0}'
}
# de_post PATH JSON: an authenticated POST to detection-engine as $ACTOR.
de_post() {
  curl -sS -m 10 -H "Authorization: Bearer $DETKEY" -H "X-Netsoldier-Actor: $ACTOR" \
    -H 'Content-Type: application/json' -d "$2" "$DE$1"
}
# suppression IOC CLIENT_IP: prints the suppression in force for that pair;
# fails when there is none.
suppression() {
  curl -sS -m 10 "$DE/feedback" |
    jq -ce --arg i "$1" --arg ip "$2" \
      '[.[] | select(.matched_ioc == $i and (.client_ip // "") == $ip and .verdict == "false_positive")] | first // empty'
}
suppressed_total() {
  curl -s "$DE/metrics" | awk '$1 == "detection_engine_alerts_suppressed_total" {print $2 + 0; f = 1} END {if (!f) print 0}'
}
withheld_off() { # killswitch_auto_block_withheld_total{reason="auto_block_off"}
  curl -s "$KS/metrics" | awk '$1 == "killswitch_auto_block_withheld_total{reason=\"auto_block_off\"}" {print $2 + 0; f = 1} END {if (!f) print "absent"}'
}
policy() { ks "$KS/policy" | jq -c '{auto_block, auto_block_allowed, auto_block_disabled_reason, allowlist_entries, auto_min_confidence, auto_min_severity}'; }
# netagent's container health (its unit's HealthCmd, `/netagent health`).
netagent_health() { podman inspect --format '{{.State.Health.Status}}' netsoldier-netagent 2>/dev/null || true; }
netagent_health_output() {
  { podman inspect --format '{{range .State.Health.Log}}{{.Output}}{{end}}' netsoldier-netagent 2>/dev/null || true; } |
    sed '/^$/d' | tail -n1
}
rule_present() { ag_rules | grep -qxF "||$1^"; }
rule_absent() { ! rule_present "$1"; }
sinkholed() { [[ $(lookup victim "$1") == "NOERROR 0.0.0.0" ]]; }
resolves() { local r; r=$(lookup victim "$1"); [[ $r == NOERROR\ * && $r != *0.0.0.0* ]]; }
all_healthy() {
  local u
  for u in "$KS/healthz" "$DE/healthz" "$DI/readyz" "http://10.231.47.11:8083/healthz"; do
    [[ $(curl -s -o /dev/null -m 3 -w '%{http_code}' "$u") == 200 ]] || return 1
  done
  [[ $(curl -s -o /dev/null -m 3 -w '%{http_code}' "$AG/") =~ ^(200|302)$ ]] || return 1
  # From the LAN (the router's namespace: it has an address from the start).
  ip netns exec nslab-gw curl -s -o /dev/null -m 3 -w '%{http_code}' "$UI/healthz" | grep -qx 200 || return 1
  [[ $(netagent_health) == healthy ]]
}

# ── 1. Installed on a clean host ───────────────────────────────────────────
step1() {
  say "=== 1. install (done by lite.sh: uninstall, clean-host check, install)"
  local u bad=0
  for u in adguard threat-intel-sync device-inventory killswitch detection-engine netagent web-ui; do
    [[ $(systemctl is-active "netsoldier-$u.service") == active ]] || { bad=1; say "  netsoldier-$u not active"; }
  done
  if ((bad == 0)) && wait_for 120 all_healthy; then
    pass "1 install: 7 units active, every /healthz (device-inventory /readyz) 200, netagent container healthy"
  else
    fail "1 install: not every service is healthy"
  fi
  # netagent's health is its container's health check now; nothing of it
  # is on the host any more.
  local hc mounts
  hc=$(podman inspect --format '{{json .Config.Healthcheck.Test}} interval={{.Config.Healthcheck.Interval}} retries={{.Config.Healthcheck.Retries}} on-failure={{.Config.HealthcheckOnFailureAction}}' netsoldier-netagent 2>&1 || true)
  mounts=$(podman inspect --format '{{range .Mounts}}{{.Type}}:{{.Destination}} {{end}}' netsoldier-netagent || true)
  say "  netagent health check: $hc; status $(netagent_health): $(netagent_health_output); mounts: ${mounts:-none}; tmpfs: $(podman inspect --format '{{json .HostConfig.Tmpfs}}' netsoldier-netagent)"
  if [[ $(netagent_health) == healthy && $hc == '["CMD","/netagent","health"]'* && ! -e /run/netsoldier/netagent && $mounts != *bind* ]]; then
    pass "1 netagent: healthy by its own health check ($(netagent_health_output)); no host mount, no /run/netsoldier/netagent"
  else
    fail "1 netagent health: status=$(netagent_health) check=$hc mounts=${mounts:-none} host dir: $(ls -d /run/netsoldier/netagent 2>/dev/null || echo none)"
  fi
  say "  container       networks                          user        caps(eff)          ro    ports                        mem limit"
  local n
  for n in $(podman ps --format '{{.Names}}' --filter label=app=netsoldier | sort); do
    local nets caps ro ports mem user pid capeff
    nets=$(podman inspect --format '{{if eq .HostConfig.NetworkMode "host"}}host{{else}}{{range $k, $v := .NetworkSettings.Networks}}{{$k}}={{$v.IPAddress}} {{end}}{{end}}' "$n")
    caps=$(podman inspect --format '{{.EffectiveCaps}}' "$n")
    ro=$(podman inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$n")
    ports=$(podman port "$n" | tr '\n' ' ')
    mem=$(podman inspect --format '{{.HostConfig.Memory}}' "$n")
    pid=$(podman inspect --format '{{.State.Pid}}' "$n")
    user=$(awk '/^Uid:/ {print $2}' "/proc/$pid/status")
    capeff=$(awk '/^CapEff:/ {print $2}' "/proc/$pid/status")
    printf '  %-28s %-46s uid=%-6s %-12s CapEff=%s ro=%s %-28s %sMiB\n' "$n" "${nets% }" "$user" "${caps:-[]}" \
      "$capeff" "$ro" "${ports:--}" $((mem / 1048576))
  done
  # Nothing but DNS and the UI faces the LAN, and nothing at all faces eth0.
  local real_ip
  real_ip=$(ip -4 -o addr show dev eth0 | awk '{split($4, a, "/"); print a[1]; exit}')
  say "  host listeners: $(ss -H -lntu | awk '{print $1 "/" $5}' | sort -u | tr '\n' ' ')"
  local reach=""
  for port in 3000 8080 8081 8083 8084 9464 53; do
    curl -s -o /dev/null -m 2 "http://$real_ip:$port/" && reach+=" $port"
  done
  ip netns exec nslab-gw ip route add 10.231.47.0/24 via "$HOST_IP"
  local lan_reach
  lan_reach=$(ip netns exec nslab-gw curl -s -o /dev/null -m 3 -w '%{http_code}' "$DI/healthz" || true)
  ip netns exec nslab-gw ip route del 10.231.47.0/24 via "$HOST_IP"
  if [[ -z $reach && $lan_reach == 000 ]]; then
    pass "1 exposure: nothing answers on eth0 ($real_ip: 53/3000/808x/9464 refused); the router routing 10.231.47.0/24 via $HOST_IP cannot reach device-inventory (curl code $lan_reach)"
  else
    fail "1 exposure: eth0 answers on:$reach; LAN reach to the internal network: $lan_reach"
  fi
  # Even on the internal network, every API but the probes wants its key
  # (audit DP-10: POST /feedback was open on Podman).
  local codes
  codes="feedback=$(curl -s -o /dev/null -m 3 -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{}' "$DE/feedback")"
  codes+=" devices=$(curl -s -o /dev/null -m 3 -w '%{http_code}' "$DI/devices")"
  codes+=" pending=$(curl -s -o /dev/null -m 3 -w '%{http_code}' "$KS/actions/pending")"
  codes+=" evaluate=$(curl -s -o /dev/null -m 3 -w '%{http_code}' -X POST -H "Authorization: Bearer $OPER" -d '{}' "$KS/evaluate")"
  codes+=" adguard=$(curl -s -o /dev/null -m 3 -w '%{http_code}' "$AG/control/status")"
  codes+=" adguard-wizard=$(curl -s -o /dev/null -m 3 -w '%{http_code}' "$AG/control/install/get_addresses")"
  if [[ $codes == "feedback=401 devices=401 pending=401 evaluate=401 adguard=403 adguard-wizard=403" ]]; then
    pass "1 keys enforced without credentials (operator token on /evaluate counts as none): $codes"
  else
    fail "1 unauthenticated calls: $codes"
  fi
}

# ── 2. DHCP lease -> device-inventory via netagent ─────────────────────────
victim_in_inventory() {
  DEVICE=$(di "$DI/devices" | jq -c --arg m "$VICTIM_MAC" '.[] | select(.mac == $m)')
  [[ $(jq -r .ip <<<"$DEVICE") == "$VICTIM_IP" && $(jq -r .hostname <<<"$DEVICE") == "$VICTIM_NAME" ]]
}
step2() {
  say "=== 2. DHCP lease -> device-inventory"
  local before after
  before=$(curl -s "$DI/metrics" | awk '/^device_inventory_frames_received_total|^frames_received_total/ {s += $2} END {print s + 0}')
  VICTIM_IP=$("$LAN" dhcp | tail -n1)
  say "  victim leased $VICTIM_IP"
  if wait_for 60 victim_in_inventory; then
    after=$(curl -s "$DI/metrics" | awk '/^device_inventory_frames_received_total|^frames_received_total/ {s += $2} END {print s + 0}')
    pass "2 inventory after ${WAITED}s: $(jq -c '{mac, ip, ip_source, hostname, hostname_source}' <<<"$DEVICE"); frames received $before -> $after"
  else
    fail "2 inventory: victim not listed with ip+hostname within 60s: ${DEVICE:-none}"
  fi
  local capeff
  capeff=$(awk '/^CapEff:/ {print $2}' "/proc/$(podman inspect --format '{{.State.Pid}}' netsoldier-device-inventory)/status")
  [[ $capeff == 0000000000000000 ]] && pass "2 device-inventory holds no capability (CapEff=$capeff, internal network only)" ||
    fail "2 device-inventory CapEff=$capeff"
}

# ── 3. Known-bad lookup -> alert with MAC -> pending action ────────────────
step3() {
  say "=== 3. victim resolves $D_PENDING (listed in $IOC)"
  local r since
  since=$(($(date +%s) - 1))
  r=$(lookup victim "$D_PENDING")
  say "  victim: dig $D_PENDING @$HOST_IP -> $r"
  if wait_for 60 alert_for "$D_PENDING" "$VICTIM_IP" "$since"; then
    local mac
    mac=$(jq -r .client_mac <<<"$ALERT")
    [[ $mac == "$VICTIM_MAC" ]] && pass "3 alert after ${WAITED}s: $(jq -c '{id, domain, client_ip, client_mac, client_name, severity, confidence, source}' <<<"$ALERT")" ||
      fail "3 alert without the victim's MAC: $ALERT"
  else
    fail "3 no alert for $D_PENDING from $VICTIM_IP within 60s"
  fi
  DET_ID=$(jq -r .id <<<"$ALERT")
  if wait_for 60 action_for "$DET_ID" >/dev/null; then
    ACTION_ID=$(action_for "$DET_ID")
    local a
    a=$(ks "$KS/actions/$ACTION_ID")
    [[ $(jq -r .state <<<"$a") == pending && $(jq -r .auto_approved <<<"$a") == false ]] &&
      pass "3 action after ${WAITED}s: $(jq -c '{id, state, action_type, target_mac, target_ip, blocked_domain, auto_approved, policy_rule}' <<<"$a")" ||
      fail "3 action is not pending: $a"
  else
    fail "3 no killswitch action for $DET_ID within 60s"
  fi
  # As shipped: the host and the router are protected (so the allowlist is
  # not empty) and AUTO_BLOCK=off; automation is off for that reason alone.
  local pol allow
  pol=$(policy)
  allow=$(ks "$KS/allowlist" | jq -c .)
  if [[ $(jq -r .auto_block <<<"$pol") == off && $(jq -r .auto_block_allowed <<<"$pol") == false &&
    $(jq -r .auto_block_disabled_reason <<<"$pol") == "$AUTO_OFF_REASON" &&
    $(jq -r --arg ip "$HOST_IP" '.ips | index($ip) != null' <<<"$allow") == true &&
    $(jq -r --arg m "$HOST_MAC" '.macs | index($m) != null' <<<"$allow") == true ]]; then
    pass "3 as shipped: $pol; allowlist (this host): $allow"
  else
    fail "3 automation not off as shipped, or the host not protected: $pol; allowlist: $allow"
  fi
  # The local list's 80/high is below the default auto thresholds, so the
  # lookup above stays pending either way. A detection that clears every
  # other auto-block condition (attested, 99, critical, the victim) shows
  # that the switch is what holds it back.
  local w0 w1 resp id
  w0=$(withheld_off)
  resp=$(evaluate "$(event "DET-lab-$(date +%s)0" "$VICTIM_IP" "$VICTIM_MAC" domain auto-off.example)")
  w1=$(withheld_off)
  id=$(jq -r '.action.id // empty' <<<"$resp")
  say "  signed detection for the victim (attested, 99, critical): $(jq -c '{action: .decision.Action, withheld: .decision.Withheld, reason: .decision.Reason, state: .action.state}' <<<"$resp")"
  if [[ $(jq -r .decision.Action <<<"$resp") == pending && $(jq -r .action.state <<<"$resp") == pending &&
    $(jq -r .decision.Reason <<<"$resp") == *"$AUTO_OFF_REASON; every other auto-block condition held"* &&
    $w0 != absent && $w1 != absent ]] && ((w1 > w0)); then
    pass "3 an otherwise auto-blockable detection is queued for a human, withheld as auto_block_off ($w0 -> $w1)"
  else
    fail "3 auto-blockable detection with AUTO_BLOCK=off: $resp; withheld $w0 -> $w1"
  fi
  [[ -z $id ]] || say "  $id rejected -> $(ks -X POST -H "X-Netsoldier-Actor: $ACTOR" -H 'Content-Type: application/json' \
    -d '{"reason":"lab scenario: automation-off check"}' "$KS/actions/$id/reject" | jq -c '{state, rejected_by}')"
}

# ── 4. Operator approves -> rule in AdGuard -> sinkholed ────────────────────
step4() {
  say "=== 4. approve $ACTION_ID"
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' -m 10 -X POST -H "Authorization: Bearer $INGEST" \
    -H "X-Netsoldier-Actor: $ACTOR" "$KS/actions/$ACTION_ID/approve")
  [[ $code == 401 ]] && pass "4 the ingest token cannot approve (HTTP $code)" || fail "4 ingest token on approve: HTTP $code"
  local resp
  resp=$(ks -X POST -H "X-Netsoldier-Actor: $ACTOR" -H 'Content-Type: application/json' \
    -d '{"action_type":"dns_sinkhole"}' -w '\n%{http_code}' "$KS/actions/$ACTION_ID/approve")
  say "  approve -> HTTP ${resp##*$'\n'}: $(head -n1 <<<"$resp" | jq -c '{state, approved_by, activated_at, expires_at}')"
  if wait_for 20 eval '[[ $(state_of "$ACTION_ID") == active ]]'; then
    pass "4 action active, approved_by=$(ks "$KS/actions/$ACTION_ID" | jq -r .approved_by)"
  else
    fail "4 action not active: $(ks "$KS/actions/$ACTION_ID" | jq -c .)"
  fi
  if rule_present "$D_PENDING"; then pass "4 AdGuard user_rules: $(ag_rules | grep -xF "||$D_PENDING^")"; else fail "4 no AdGuard rule for $D_PENDING"; fi
  if wait_for 15 sinkholed "$D_PENDING"; then pass "4 victim: dig $D_PENDING -> $(lookup victim "$D_PENDING") (sinkholed)"; else
    fail "4 victim lookup not sinkholed: $(lookup victim "$D_PENDING")"; fi
}

# ── 5. TTL -> rule gone -> resolves ─────────────────────────────────────────
step5() {
  say "=== 5. wait for the TTL ($TTL s from activation)"
  local a
  if wait_for $((TTL + 60)) eval '[[ $(state_of "$ACTION_ID") == reverted ]]'; then
    a=$(ks "$KS/actions/$ACTION_ID")
    pass "5 reverted: $(jq -c '{state, reverted_by, activated_at, expires_at, reverted_at}' <<<"$a")"
  else
    fail "5 not reverted after TTL: $(ks "$KS/actions/$ACTION_ID" | jq -c .)"
  fi
  if rule_absent "$D_PENDING"; then pass "5 AdGuard rule for $D_PENDING gone"; else fail "5 AdGuard rule still present"; fi
  if wait_for 15 resolves "$D_PENDING"; then pass "5 victim: dig $D_PENDING -> $(lookup victim "$D_PENDING")"; else
    fail "5 does not resolve again: $(lookup victim "$D_PENDING")"; fi
}

# ── 6. Audit log ────────────────────────────────────────────────────────────
step6() {
  say "=== 6. GET /audit?action_id=$ACTION_ID"
  local audit
  audit=$(ks "$KS/audit?action_id=$ACTION_ID")
  jq -r '.[] | "  seq=\(.seq) \(.from_state // "-") -> \(.to_state) actor=\(.actor) \(.reason // "" | .[0:70])"' <<<"$audit" | sort -t= -k2 -n
  local chain
  chain=$(jq -r 'sort_by(.seq) | map("\(.to_state):\(.actor)") | join(" ")' <<<"$audit")
  if [[ $chain == *"pending:"* ]] && [[ $chain == *"active:$ACTOR"* || $chain == *"approved:$ACTOR"* ]] &&
    [[ $chain == *"reverted:ttl"* ]]; then
    pass "6 audit: $chain"
  else
    fail "6 audit chain incomplete: $chain"
  fi
}

# ── 7. The gateway is never enforced ────────────────────────────────────────
step7() {
  say "=== 7. detections that name the gateway"
  local r s0 since
  s0=$(deliveries)
  since=$(($(date +%s) - 1))
  r=$(lookup gw "$D_GW")
  say "  router: dig $D_GW @$HOST_IP -> $r"
  if wait_for 60 alert_for "$D_GW" "$GW_IP" "$since"; then
    local det
    det=$(jq -r .id <<<"$ALERT")
    say "  alert: $(jq -c '{id, domain, client_ip, client_mac}' <<<"$ALERT")"
    # The killswitch answers an ignored detection with 200 and records
    # nothing, so: wait until detection-engine has delivered it, then look
    # for an action.
    if wait_for 30 eval '(($(deliveries) > s0)) && outbox_empty'; then
      say "  delivered to the killswitch (deliveries ok: $s0 -> $(deliveries), outbox backlog 0)"
      if action_for "$det" >/dev/null; then
        fail "7a an action exists for the router's detection $det"
      else
        pass "7a router ($GW_IP, $GW_MAC) resolved $D_GW: alert $det delivered, no killswitch action"
      fi
    else
      fail "7a the router's detection was not delivered (deliveries ok: $s0 -> $(deliveries))"
    fi
  else
    fail "7a no alert for the router's lookup"
  fi
  local resp
  resp=$(evaluate "$(event "DET-lab-$(date +%s)1" 192.168.77.123 "$GW_MAC" domain "$D_GW")")
  [[ $(jq -r '.decision.Action' <<<"$resp") == ignore && $(jq -r .action <<<"$resp") == null ]] &&
    pass "7b gateway MAC behind another address, critical/99: $(jq -c '{action: .decision.Action, reason: .decision.Reason}' <<<"$resp")" ||
    fail "7b $resp"
  resp=$(evaluate "$(event "DET-lab-$(date +%s)2" "$GW_IP" "" domain "$D_GW")")
  [[ $(jq -r '.decision.Action' <<<"$resp") == ignore && $(jq -r .action <<<"$resp") == null ]] &&
    pass "7c gateway IP without a MAC, critical/99: $(jq -c '{action: .decision.Action, reason: .decision.Reason}' <<<"$resp")" ||
    fail "7c $resp"
  resp=$(evaluate "$(event "DET-lab-$(date +%s)3" "$VICTIM_IP" "$VICTIM_MAC" ip "$GW_IP")")
  local id
  id=$(jq -r '.action.id // empty' <<<"$resp")
  say "  target = the gateway's address: $(jq -c '{action: .decision.Action, reason: .decision.Reason}' <<<"$resp")"
  if [[ -n $id ]]; then
    resp=$(ks -X POST -H "X-Netsoldier-Actor: $ACTOR" -w '\n%{http_code}' "$KS/actions/$id/approve")
    sleep 2
    local st
    st=$(state_of "$id")
    if [[ $st != active ]] && ! ag_rules | grep -q "$GW_IP"; then
      pass "7d a human approving a block of $GW_IP gets state=$st ($(ks "$KS/actions/$id" | jq -r '.failure_reason // .reason' | cut -c1-90)); no AdGuard rule"
    else
      fail "7d gateway target enforced: state=$st"
    fi
  else
    pass "7d target = gateway address: no action created"
  fi
  # This host is protected by the installer whatever PROTECTED_* says: by
  # its LAN address, and by the MAC of LAN_INTERFACE behind another address.
  host_ignored 7e "$HOST_IP" ""
  host_ignored 7f 192.168.77.124 "$HOST_MAC"
}

# host_ignored LABEL CLIENT_IP CLIENT_MAC: a signed critical/99 detection
# naming this host is ignored as a protected device, with no action.
host_ignored() {
  local resp
  resp=$(evaluate "$(event "DET-lab-$(date +%s%N | cut -c1-16)" "$2" "$3" domain "$D_GW")")
  if [[ $(jq -r '.decision.Action' <<<"$resp") == ignore && $(jq -r .action <<<"$resp") == null &&
    $(jq -r '.decision.Reason' <<<"$resp") == "allowlisted device "* ]]; then
    pass "$1 this host (${2}${3:+ / $3}), critical/99, AUTO_BLOCK=$(ks "$KS/policy" | jq -r .auto_block): $(jq -c '{action: .decision.Action, reason: .decision.Reason}' <<<"$resp")"
  else
    fail "$1 a detection naming this host (${2}${3:+ / $3}): $resp"
  fi
}

# ── 8. Web UI ───────────────────────────────────────────────────────────────
step8() {
  say "=== 8. web UI at $UI (from the victim, i.e. the LAN)"
  local in=(ip netns exec nslab-victim)
  local h l jar=/run/nslab/ui.cookies hdr=/run/nslab/ui.headers code
  h=$("${in[@]}" curl -sS -m 5 -w ' %{http_code}' "$UI/healthz")
  [[ $h == *' 200' ]] && pass "8 GET /healthz -> $h" || fail "8 /healthz -> $h"
  l=$("${in[@]}" curl -sS -m 5 -w '%{http_code}' -o /run/nslab/login.html "$UI/login")
  [[ $l == 200 ]] && grep -q 'type="password"' /run/nslab/login.html &&
    pass "8 GET /login -> $l, sign-in form with a password field ($(grep -o '<title>[^<]*' /run/nslab/login.html | head -n1 | sed 's/<title>//'))" ||
    fail "8 /login -> $l"
  code=$("${in[@]}" curl -sS -m 5 -o /dev/null -w '%{http_code}' -H "Origin: $UI" -H 'Content-Type: application/json' \
    -d "$(jq -cn --arg a "$ACTOR" '{password: "wrong-password-123", actor: $a}')" "$UI/api/login")
  [[ $code == 401 ]] && pass "8 wrong password -> $code" || fail "8 wrong password -> $code"
  rm -f "$jar"
  code=$("${in[@]}" curl -sS -m 5 -o /dev/null -D "$hdr" -c "$jar" -w '%{http_code}' -H "Origin: $UI" \
    -H 'Content-Type: application/json' -d "$(jq -cn --arg p "$UIPASS" --arg a "$ACTOR" '{password: $p, actor: $a}')" \
    "$UI/api/login")
  local cookies
  cookies=$(grep -i '^set-cookie:' "$hdr" | sed -E 's/^[Ss]et-[Cc]ookie: ([^=]+)=[^;]*(.*)/\1\2/' | tr -d '\r' | paste -sd'|')
  if [[ $code == 200 && $cookies == *netsoldier_session* && $cookies == *netsoldier_csrf* ]]; then
    pass "8 sign-in with the generated password -> $code, cookies: $cookies"
  else
    fail "8 sign-in -> $code, cookies: $cookies"
  fi
  # The counters are not on the UI port (404 there, from the LAN as from
  # anywhere), and in this profile the metrics listener is not started
  # (METRICS_ADDR=off): 9464 answers neither on HOST_IP nor on the internal
  # network.
  local m_ui m_lan m_int
  m_ui=$("${in[@]}" curl -sS -m 5 -o /dev/null -w '%{http_code}' "$UI/metrics" || true)
  m_lan=$("${in[@]}" curl -s -m 3 -o /dev/null -w '%{http_code}' "http://$HOST_IP:9464/metrics" || true)
  m_int=$(curl -s -m 3 -o /dev/null -w '%{http_code}' http://10.231.47.15:9464/metrics || true)
  if [[ $m_ui == 404 && $m_lan == 000 && $m_int == 000 ]]; then
    pass "8 victim: GET $UI/metrics -> $m_ui; :9464 on $HOST_IP -> $m_lan, on the internal 10.231.47.15 -> $m_int (000 = no answer)"
  else
    fail "8 metrics exposure: $UI/metrics -> $m_ui, $HOST_IP:9464 -> $m_lan, 10.231.47.15:9464 -> $m_int"
  fi
  local p
  for p in killswitch/history devices alerts; do
    code=$("${in[@]}" curl -sS -m 10 -b "$jar" -o /run/nslab/ui.json -w '%{http_code}' "$UI/api/$p")
    [[ $code == 200 ]] && pass "8 signed in: GET /api/$p -> $code, $(jq 'length' /run/nslab/ui.json) entries" ||
      fail "8 GET /api/$p -> $code $(head -c 200 /run/nslab/ui.json)"
  done
}

# ── Phase B: automatic block, then restarts (9) ────────────────────────────
phase_b() {
  say "=== auto-block arranged: AUTO_BLOCK=on, no PROTECTED_* (only this host and the router protected), auto thresholds = local list's 80/high"
  sed -e 's/^AUTO_BLOCK=.*/AUTO_BLOCK=on/' "$LAB_CONF" >"$CONF"
  printf 'POLICY_AUTO_CONFIDENCE=80\nPOLICY_AUTO_SEVERITY=high\n' >>"$CONF"
  local out
  out=$($NL install 2>&1) || fail "B re-install failed: $(tail -n3 <<<"$out")"
  sed 's/^/  /' <<<"$out"
  # The installer says plainly what AUTO_BLOCK=on without PROTECTED_* means.
  if grep -q "AUTO_BLOCK=on with no PROTECTED_MACS/PROTECTED_IPS: only this host ($HOST_IP, $HOST_MAC) and the router ($GW_IP, $GW_MAC) are protected" <<<"$out"; then
    pass "B installer: $(grep -o 'AUTO_BLOCK=on with no.*' <<<"$out" | cut -c1-160)"
  else
    fail "B the installer did not say that only this host and the router are protected"
  fi
  wait_for 120 all_healthy || fail "B: not healthy after re-install"
  local pol
  pol=$(policy)
  if [[ $(jq -r .auto_block <<<"$pol") == on && $(jq -r .auto_block_allowed <<<"$pol") == true ]]; then
    pass "B policy: $pol"
  else
    fail "B AUTO_BLOCK=on did not switch automation on: $pol"
  fi
  local r since
  since=$(($(date +%s) - 1))
  r=$(lookup victim "$D_AUTO")
  say "  victim: dig $D_AUTO -> $r"
  if wait_for 60 alert_for "$D_AUTO" "$VICTIM_IP" "$since"; then
    # shellcheck disable=SC2034 # read by the eval'd condition below
    DET_B=$(jq -r .id <<<"$ALERT")
  else
    fail "B no alert for $D_AUTO"
  fi
  if wait_for 60 eval 'AUTO_ID=$(action_for "$DET_B") && [[ $(state_of "$AUTO_ID") == active ]]'; then
    pass "B auto-blocked after ${WAITED}s: $(ks "$KS/actions/$AUTO_ID" | jq -c '{id, state, auto_approved, approved_by, blocked_domain, policy_rule}')"
  else
    fail "B no active auto-block for $D_AUTO: $(ks "$KS/actions/active" | jq -c .)"
  fi
  rule_present "$D_AUTO" && wait_for 15 sinkholed "$D_AUTO" &&
    pass "B AdGuard rule ||$D_AUTO^ present, victim lookup -> $(lookup victim "$D_AUTO")" ||
    fail "B rule/sinkhole missing for $D_AUTO"
  # With automation on and nothing in PROTECTED_*, this host is still never
  # acted against.
  host_ignored "B host" "$HOST_IP" ""
}

still_blocked() {
  [[ $(state_of "$AUTO_ID") == active ]] && rule_present "$D_AUTO"
}

step9() {
  say "=== 9. restart every service while $AUTO_ID blocks $D_AUTO"
  local u
  for u in adguard threat-intel-sync device-inventory killswitch detection-engine netagent web-ui; do
    systemctl restart "netsoldier-$u.service"
    if wait_for 90 all_healthy && wait_for 30 still_blocked; then
      pass "9 restarted netsoldier-$u: healthy, $AUTO_ID still active, rule present"
    else
      fail "9 after restarting netsoldier-$u: state=$(state_of "$AUTO_ID"), rule: $(rule_present "$D_AUTO" && echo yes || echo no)"
    fi
  done
  systemctl restart netsoldier.target
  if wait_for 120 all_healthy && wait_for 30 still_blocked; then
    pass "9 restarted netsoldier.target (all 7 at once): $AUTO_ID still active, victim lookup -> $(lookup victim "$D_AUTO")"
  else
    fail "9 after restarting the target: state=$(state_of "$AUTO_ID")"
  fi
  # As close to a reboot as the lab allows (rebooting the LXC itself is not
  # an option here): everything stopped, /run/netsoldier gone as after a
  # boot, tmpfiles re-created, and the target started the way
  # multi-user.target starts it.
  # `systemctl stop netsoldier.target` returns before the units it takes
  # down have finished stopping (PartOf= only queues their stop jobs), so
  # stop them by name: that waits for Podman's network teardown. Touching
  # /run/netsoldier before it is done leaves stale DNAT rules behind.
  systemctl stop netsoldier.target netsoldier-{web-ui,netagent,detection-engine,killswitch,device-inventory,threat-intel-sync,adguard}.service
  local still
  still=$(podman ps -a --format '{{.Names}}' --filter label=app=netsoldier | tr '\n' ' ')
  if [[ -z $still ]]; then
    findmnt -rn -o TARGET | { grep '^/run/netsoldier/' || true; } | sort -ru | xargs -r -n1 umount -l 2>/dev/null || true
    rm -rf /run/netsoldier
    systemd-tmpfiles --create /etc/tmpfiles.d/netsoldier.conf
  fi
  say "  cold start: stopped (containers left: ${still:-none}); enabled: $(systemctl is-enabled netsoldier.target), wanted by: $(systemctl show -p WantedBy --value netsoldier.target)"
  systemctl start netsoldier.target
  if [[ -z $still ]] && wait_for 120 all_healthy && wait_for 30 still_blocked; then
    pass "9 cold start of every unit (stop all, empty /run/netsoldier, start): $AUTO_ID still active, victim lookup -> $(lookup victim "$D_AUTO"); inventory kept: $(di "$DI/devices" | jq -c --arg m "$VICTIM_MAC" '.[] | select(.mac == $m) | {mac, ip, hostname}'), alerts kept: $(curl -s "$DE/alerts" | jq length)"
  else
    fail "9 after the cold start: containers left before start: ${still:-none}, state=$(state_of "$AUTO_ID")"
  fi
  local a exp
  a=$(ks "$KS/actions/$AUTO_ID")
  exp=$(jq -r .expires_at <<<"$a")
  say "  waiting for expires_at=$exp"
  if wait_for $((TTL + 90)) eval '[[ $(state_of "$AUTO_ID") == reverted ]]'; then
    a=$(ks "$KS/actions/$AUTO_ID")
    pass "9 lifted at its TTL: $(jq -c '{state, reverted_by, activated_at, expires_at, reverted_at}' <<<"$a")"
  else
    fail "9 not lifted: $(ks "$KS/actions/$AUTO_ID" | jq -c .)"
  fi
  rule_absent "$D_AUTO" && wait_for 15 resolves "$D_AUTO" &&
    pass "9 rule gone, victim: dig $D_AUTO -> $(lookup victim "$D_AUTO")" || fail "9 rule or resolution after TTL"
  say "  audit: $(ks "$KS/audit?action_id=$AUTO_ID" | jq -r 'sort_by(.seq) | map("\(.from_state // "-")->\(.to_state):\(.actor)") | join(" ")')"
}

# The lite profile has no ClickHouse: detection-engine's own store is the
# only copy of an analyst's verdict. Before that store held verdicts, a
# false-positive suppression was gone after any restart while the API had
# answered "persisted": true.
step10() {
  say "=== 10. a false-positive verdict outlives a restart of detection-engine"
  # Run on its own (scenario.sh step10), the victim's address comes from the
  # inventory instead of step 2's lease.
  : "${VICTIM_IP:=$(di "$DI/devices" | jq -r --arg m "$VICTIM_MAC" '.[] | select(.mac == $m) | .ip')}"
  if ! alert_for "$D_PENDING" "$VICTIM_IP"; then
    fail "10 no alert for $D_PENDING from $VICTIM_IP to give a verdict on"
    return 0
  fi
  local ioc class r s newest
  ioc=$(jq -r .matched_ioc <<<"$ALERT")
  r=$(de_post /feedback "$(jq -cn --arg a "$(jq -r .id <<<"$ALERT")" --arg i "$ioc" --arg ip "$VICTIM_IP" \
    '{alert_id: $a, matched_ioc: $i, client_ip: $ip, verdict: "false_positive", reason: "lab scenario"}')")
  if [[ $(jq -r .persisted <<<"$r") == true ]] && s=$(suppression "$ioc" "$VICTIM_IP"); then
    pass "10 verdict recorded: $r; in force: $(jq -c '{matched_ioc, client_ip, signal_class, analyst, expires_at}' <<<"$s")"
  else
    fail "10 verdict not recorded durably: $r; GET /feedback: $(curl -sS -m 10 "$DE/feedback")"
    return 0
  fi
  class=$(jq -r .signal_class <<<"$s")

  systemctl restart netsoldier-detection-engine.service
  if wait_for 90 all_healthy && s=$(suppression "$ioc" "$VICTIM_IP"); then
    pass "10 restarted detection-engine: suppression still in force, expires $(jq -r .expires_at <<<"$s")"
  else
    fail "10 suppression gone after the restart: $(curl -sS -m 10 "$DE/feedback")"
  fi
  # A suppressed detection is still written to the alert history, marked
  # "suppressed": true; what the verdict stops is the response. So the
  # evidence is: the counter (0 in the new process) moved, the lookup's
  # alert exists and says so, and the killswitch never heard of it.
  lookup victim "$D_PENDING" >/dev/null
  if wait_for 90 eval '(($(suppressed_total) >= 1))'; then
    local alert
    alert=$(curl -sS -m 10 "$DE/alerts?limit=200" | jq -c --arg d "$D_PENDING" --arg ip "$VICTIM_IP" \
      '[.[] | select(.domain == $d and .client_ip == $ip)] | sort_by(.timestamp) | last')
    newest=$(jq -r .id <<<"$alert")
    if r=$(action_for "$newest"); then
      fail "10 lookup of $D_PENDING counted as suppressed, yet $newest reached the killswitch as $r"
    elif [[ $(jq -r .suppressed <<<"$alert") != true ]]; then
      fail "10 the suppressed lookup's alert does not say so: $(jq -c '{id, timestamp, suppressed}' <<<"$alert")"
    else
      pass "10 the victim's next lookup of $D_PENDING was suppressed after ${WAITED}s: in the history as $(jq -c '{id, suppressed}' <<<"$alert"), no action for it, deliveries since the restart: $(deliveries)"
    fi
  else
    fail "10 lookup of $D_PENDING not suppressed: suppressed_total=$(suppressed_total)"
  fi

  r=$(de_post /feedback/lift "$(jq -cn --arg i "$ioc" --arg ip "$VICTIM_IP" --arg c "$class" \
    '{matched_ioc: $i, client_ip: $ip, signal_class: $c, reason: "lab scenario done"}')")
  systemctl restart netsoldier-detection-engine.service
  if [[ $(jq -r .status <<<"$r") == lifted ]] && wait_for 90 all_healthy && ! suppression "$ioc" "$VICTIM_IP" >/dev/null; then
    pass "10 lifted ($r), and still lifted after another restart"
  else
    fail "10 lift: $r; GET /feedback after the restart: $(curl -sS -m 10 "$DE/feedback")"
  fi
}

restore() {
  say "=== restore the shipped lab configuration (automatic blocking off)"
  cp "$LAB_CONF" "$CONF"
  $NL install | sed 's/^/  /'
  local pol
  pol=$(policy)
  if [[ $(jq -r .auto_block <<<"$pol") == off && $(jq -r .auto_block_disabled_reason <<<"$pol") == "$AUTO_OFF_REASON" ]]; then
    pass "restore: shipped configuration back, $pol"
  else
    fail "restore: automation not off after restoring netsoldier.lab.conf: $pol"
  fi
}

say "lite scenario on $(hostname), $(cat /opt/netsoldier/src/.lab-revision 2>/dev/null)"
# The whole scenario is written for a fresh installation: detection-engine
# folds a repeated detection into the one it delivered in the last ten
# minutes, so on a used installation step 3 would wait for an action that is
# never created. Say so instead of failing there (lite.sh e2e reinstalls).
if ((!$#)) && [[ ${ALLOW_USED:-0} != 1 ]]; then
  seen=$(curl -sS -m 10 "$DE/alerts?limit=200" |
    jq --arg a "$D_PENDING" --arg b "$D_GW" --arg c "$D_AUTO" '[.[] | select(.domain == $a or .domain == $b or .domain == $c)] | length')
  if ((seen > 0)); then
    say "this installation already holds $seen alerts for the scenario's names: run the scenario on a fresh installation (lite.sh e2e), or single steps (scenario.sh stepN), or set ALLOW_USED=1"
    exit 2
  fi
fi
if (($#)); then # scenario.sh step1 step2 ...: only those, in that order
  for s in "$@"; do "$s"; done
  finish
fi
step1
step2
step3
step4
step5
step6
step7
step8
phase_b
step9
step10
restore
finish
