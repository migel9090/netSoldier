#!/usr/bin/env bash
# End-to-end scenario on the lab (task lab:scenario), against the stack
# deploy.sh put there and the simulated home LAN of roles/lab_lan:
#
#   1  the stack runs with freshly generated, distinct credentials; AdGuard
#      refuses its stock admin/changeme
#   2  a victim takes a DHCP lease and appears in device-inventory (MAC, IP,
#      hostname) within 60 s, learned through netagent
#   3  the victim resolves a lab indicator through AdGuard: an alert with its
#      MAC within 60 s, and a pending action in the killswitch
#   3a as shipped (POLICY_AUTO_BLOCK=off, allowlist not empty) GET /policy
#      says automation is off and why, step 3's action stays pending, and a
#      signed detection that meets every other auto-block condition is
#      queued for a human (withheld as auto_block_off)
#   4  the operator approves (operator token + actor header): the block rule
#      is in AdGuard and the name is sinkholed
#   5  after the TTL the rule is gone and the name resolves again
#   3b with an auto-block policy (POLICY_AUTO_BLOCK=on, thresholds lowered
#      to the lab list's 80/high), a second victim's lookup is blocked
#      without a human (attested indicator at or above the policy's bar)
#   7  a detection naming the gateway (by IP, or by MAC) is never enforced,
#      auto-block on; then the shipped policy is restored
#   6  the audit trail (GET /audit and ClickHouse audit_log) holds every
#      transition with the right actor
#   8  the web UI answers /healthz and /login from the LAN, a sign-in with
#      the generated password returns the session cookies, /metrics on the
#      published port is 404 and the metrics port is not reachable from the
#      LAN, and nothing is published on the node's real address
#   P  the NetworkPolicies admit the core edges and refuse the others; the
#      web UI's metrics port answers the scraper's identity only while a
#      policy admits it
#
# Prints PASS/FAIL per step with the line that decides it; exits 1 if any
# step failed. Credentials are read from the cluster and travel only through
# pipes (ssh stdin), never through argv or files.
set -uo pipefail
# shellcheck source=infra/lab/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

KUBECTL=${KUBECTL:-$LAB_VENV/bin/kubectl}
export KUBECONFIG=$LAB_KUBECONFIG
NS=netsoldier
SITE_ENV=$REPO_DIR/deploy/kustomize/sites/lab/site/site.env
HTTP=/usr/local/libexec/netsoldier-lab-http

site() { sed -n "s/^$1=//p" "$SITE_ENV"; }
NODE_LAN_IP=$(site NODE_LAN_IP)
GATEWAY_IP=$(site GATEWAY_IP)
GATEWAY_MAC=$(site GATEWAY_MAC)
ORIGIN=$(site WEB_UI_ORIGIN)
# The victims and the lab zone of roles/lab_lan (defaults/main.yml).
V1=nsv1 V1_MAC=02:4e:53:00:01:01 V1_NAME=lab-victim-1
V2=nsv2 V2_MAC=02:4e:53:00:01:02 V2_NAME=lab-victim-2
GW_NS=nsgw
ZONE_ADDR=10.77.0.250
# Indicators of the lab site (sites/lab/kustomization.yaml).
D_PENDING=pending-c2.netsoldier.test
D_AUTO=auto-c2.netsoldier.test
D_GW=gateway-c2.netsoldier.test
ACTOR=lab-operator

k() { "$KUBECTL" "$@"; }
say() { printf '      %s\n' "$*"; }
declare -A RESULT
pass() { RESULT[$1]=PASS; printf 'PASS  step %s: %s\n' "$1" "$2"; }
fail() { RESULT[$1]=FAIL; printf 'FAIL  step %s: %s\n' "$1" "$2"; }
now() { date +%s; }

secret() { k -n "$1" get secret "$2" -o "jsonpath={.data.$3}" | base64 -d; }
svc() { k -n "$1" get svc "$2" -o jsonpath='{.spec.clusterIP}'; }

# http WHERE METHOD URL [BODY] [HEADER...]: one request from the node
# (WHERE=node, as the operator on the host) or from a LAN namespace
# (WHERE=nsv1 ...). Prints the helper's JSON.
http() {
  local where=$1 method=$2 url=$3 body=${4:-} spec
  shift 4 2>/dev/null || shift $#
  spec=$(jq -cn --arg m "$method" --arg u "$url" --arg b "$body" \
    '{method: $m, url: $u, headers: {}, body: (if $b == "" then null else $b end)}')
  local h
  for h in "$@"; do
    spec=$(jq -c --arg k "${h%%: *}" --arg v "${h#*: }" '.headers[$k] = $v' <<<"$spec")
  done
  if [[ $where == node ]]; then
    lab_ssh "$HTTP" <<<"$spec"
  else
    lab_ssh sudo ip netns exec "$where" "$HTTP" <<<"$spec"
  fi
}
status() { jq -r '.status // ("error: " + .error)'; }
body() { jq -r '.body'; }

resolve() { # NS NAME: the A answers through AdGuard on the node's LAN address
  lab_ssh sudo ip netns exec "$1" dig +short +time=3 +tries=1 "@$NODE_LAN_IP" "$2" A | tr '\n' ' ' | sed 's/ $//'
}

retry() { # SECONDS CMD...: until CMD succeeds, every 3 s
  local until=$(($(now) + $1)) ; shift
  while :; do
    "$@" && return 0
    (($(now) >= until)) && return 1
    sleep 3
  done
}

# ── credentials and addresses ────────────────────────────────────────────
OPERATOR=$(secret "$NS" killswitch-credentials api-key)
INGEST=$(secret "$NS" killswitch-credentials ingest-token)
WEBHOOK_SECRET=$(secret "$NS" killswitch-credentials webhook-secret)
AGENT_KS=$(secret "$NS" netagent-credentials killswitch-token)
AGENT_INV=$(secret "$NS" netagent-credentials inventory-token)
DEVICE_KEY=$(secret "$NS" device-inventory-credentials api-key)
DETECTION_KEY=$(secret "$NS" detection-engine-credentials api-key)
AG_USER=$(secret "$NS" adguard-credentials username)
AG_PASS=$(secret "$NS" adguard-credentials password)
UI_PASS=$(secret "$NS" web-ui-credentials password)
CH_DEFAULT=$(secret "$NS" clickhouse-credentials default-password)

KS=http://$(svc "$NS" killswitch-controller):8084
INV=http://$(svc "$NS" device-inventory):8081
DET=http://$(svc "$NS" detection-engine):8080
AG=http://$(svc dns adguard-web):3000
AG_AUTH="Authorization: Basic $(printf '%s:%s' "$AG_USER" "$AG_PASS" | base64 -w0)"

ks() { http node "$1" "$KS$2" "${3:-}" "Authorization: Bearer $OPERATOR" "X-Netsoldier-Actor: $ACTOR"; }
inv() { http node GET "$INV$1" "" "Authorization: Bearer $DEVICE_KEY"; }
alerts() { http node GET "$DET/alerts?limit=200" | body; }
ag_rules() { http node GET "$AG/control/filtering/status" "" "$AG_AUTH" | body | jq -r '.user_rules[]?'; }
ch() { # SQL: as the localhost-only break-glass account, inside the pod
  k -n "$NS" exec -i clickhouse-0 -c clickhouse -- sh -c \
    'read -r p; CLICKHOUSE_PASSWORD=$p exec clickhouse-client --user default --query "$1"' _ "$1" <<<"$CH_DEFAULT"
}

lease() { # NS: take a lease; prints the address
  lab_ssh sudo netsoldier-lab-lan dhcp "$1" >/dev/null 2>&1
  lab_ssh sudo ip netns exec "$1" ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1
}

device_seen_since() { # IP MAC NAME T: device-inventory holds it, seen at or after T
  local r
  r=$(inv "/devices/by-ip/$1")
  [[ $(status <<<"$r") == 200 ]] || return 1
  DEVICE=$(body <<<"$r")
  jq -e --arg m "$2" --arg n "$3" --argjson t "$4" \
    '.mac == $m and .hostname == $n and ((.last_seen | sub("\\.[0-9]+";"") | fromdateiso8601) >= $t - 2)' \
    <<<"$DEVICE" >/dev/null
}

alert_for() { # DOMAIN CLIENT_IP: sets ALERT to the newest alert for both
  ALERT=$(alerts | jq -c --arg d "$1" --arg c "$2" '[.[] | select(.domain == $d and .client_ip == $c)][0] // empty')
  [[ -n $ALERT ]]
}

action_for() { # LIST DOMAIN: sets ACTION to the action in /actions/LIST for DOMAIN
  ACTION=$(ks GET "/actions/$1" | body | jq -c --arg d "$2" '[.[] | select(.blocked_domain == $d)][0] // empty')
  [[ -n $ACTION ]]
}

action_state() { # ID STATE: sets ACTION, true once the action is in STATE
  ACTION=$(ks GET "/actions/$1" | body)
  [[ $(jq -r .state <<<"$ACTION") == "$2" ]]
}

rule_present() { ag_rules | grep -qF "$1"; }
rule_absent() { ! rule_present "$1"; }
resolves_to() { [[ $(resolve "$1" "$2") == "$3" ]]; }

echo "scenario on $(k config current-context): $(k get nodes -o jsonpath='{.items[0].metadata.name}'), images $(k -n "$NS" get deploy detection-engine -o jsonpath='{.spec.template.spec.containers[0].image}' | sed 's/.*://')"

# ── 1. deployed with fresh secrets ──────────────────────────────────────
step1() {
  local notready distinct ag_default ag_ok created
  notready=$(k get pods -n "$NS" -o json | jq -r '.items[] | select(.status.phase != "Succeeded")
    | select([.status.containerStatuses[]?.ready] | all | not) | .metadata.name')
  notready+=$(k get pods -n dns -o json | jq -r '.items[] | select([.status.containerStatuses[]?.ready] | all | not) | .metadata.name')
  distinct=$(printf '%s\n' "$OPERATOR" "$INGEST" "$WEBHOOK_SECRET" "$AGENT_KS" "$AGENT_INV" \
    "$DEVICE_KEY" "$DETECTION_KEY" "$AG_PASS" "$UI_PASS" | sort -u | wc -l)
  local ch_hashes ch_distinct
  ch_hashes=$(k -n "$NS" get secret clickhouse-credentials -o json | jq -r '.data | to_entries[] | select(.key | endswith("-sha256")) | .value')
  ch_distinct=$(sort -u <<<"$ch_hashes" | wc -l)
  ag_default=$(http node GET "$AG/control/status" "" "Authorization: Basic $(printf admin:changeme | base64 -w0)" | status)
  ag_ok=$(http node GET "$AG/control/status" "" "$AG_AUTH" | status)
  created=$(k -n "$NS" get secret killswitch-credentials -o jsonpath='{.metadata.creationTimestamp}')
  say "not ready: ${notready:-none}; 9 role credentials, $distinct distinct; $(wc -l <<<"$ch_hashes") ClickHouse accounts, $ch_distinct distinct hashes; secrets created $created"
  say "AdGuard API: admin/changeme -> $ag_default, generated account -> $ag_ok"
  if [[ -z $notready && $distinct == 9 && $ch_distinct == "$(wc -l <<<"$ch_hashes")" && $ag_ok == 200 && $ag_default =~ ^40[13]$ ]]; then
    pass 1 "stack ready, credentials generated and distinct, stock admin/changeme refused ($ag_default)"
  else
    fail 1 "stack or credentials not as required"
  fi
}

# ── 2. DHCP -> device-inventory through netagent ────────────────────────
step2() {
  local t0 sec ip spec
  lab_ssh sudo netsoldier-lab-lan release "$V1" >/dev/null
  t0=$(now)
  V1_IP=$(lease "$V1")
  say "$V1 ($V1_MAC, hostname $V1_NAME) leased ${V1_IP:-nothing}"
  if [[ -n $V1_IP ]] && retry 60 device_seen_since "$V1_IP" "$V1_MAC" "$V1_NAME" "$t0"; then
    sec=$(($(now) - t0))
    spec=$(k -n "$NS" get pod -l app.kubernetes.io/name=device-inventory -o json | jq -r '.items[0].spec
      | "runtimeClassName=\(.runtimeClassName) hostNetwork=\(.hostNetwork // false) caps_add=\([.containers[].securityContext.capabilities.add // []] | flatten)"')
    say "device: $(jq -c '{mac, ip, ip_source, hostname, hostname_source, last_seen}' <<<"$DEVICE")"
    say "device-inventory pod: $spec"
    say "frames from netagent: $(http node GET "$INV/metrics" | body | grep -E '^device_inventory_(frames_received_total|sightings_total)\{[^}]*(dhcp|arp)' | tr '\n' ' ')"
    pass 2 "$V1_IP $V1_MAC $V1_NAME in device-inventory after ${sec}s"
  else
    fail 2 "$V1 not in device-inventory within 60 s"
  fi
}

# ── 3. pending action from a lookup through AdGuard ────────────────────
step3() {
  local t0 ans
  t0=$(now)
  ans=$(resolve "$V1" "$D_PENDING")
  say "$V1 resolves $D_PENDING via $NODE_LAN_IP -> ${ans:-nothing}"
  if ! retry 60 alert_for "$D_PENDING" "$V1_IP"; then
    fail 3 "no alert for $D_PENDING from $V1_IP within 60 s"; return
  fi
  say "alert after $(($(now) - t0))s: $(jq -c '{id, client_ip, client_mac, client_name, matched_ioc, confidence, severity}' <<<"$ALERT")"
  if ! retry $((60 - ($(now) - t0))) action_for pending "$D_PENDING"; then
    fail 3 "no pending action for $D_PENDING within 60 s"; return
  fi
  PENDING_ID=$(jq -r .id <<<"$ACTION")
  say "action after $(($(now) - t0))s: $(jq -c '{id, state, detection_id, target_mac, target_ip, blocked_domain, policy_rule}' <<<"$ACTION")"
  if [[ $(jq -r .client_mac <<<"$ALERT") == "$V1_MAC" && $(jq -r .target_mac <<<"$ACTION") == "$V1_MAC" ]]; then
    pass 3 "alert carries $V1_MAC; action $PENDING_ID pending, $(($(now) - t0))s after the lookup"
  else
    fail 3 "alert or action without the victim's MAC"
  fi
}

# ── 3a. automatic blocking is off as shipped ───────────────────────────
AUTO_OFF_REASON="auto-block disabled: POLICY_AUTO_BLOCK=off"

ks_metric() { # SERIES: its value in the killswitch's /metrics, or "absent"
  http node GET "$KS/metrics" | body | awk -v m="$1" '$1 == m {print $2; f = 1} END {if (!f) print "absent"}'
}
gt() { awk -v a="$1" -v b="$2" 'BEGIN {exit !(a + 0 > b + 0)}'; }

step3a() {
  local pol ok=1 w0 w1 r id withheld='killswitch_auto_block_withheld_total{reason="auto_block_off"}'
  # A non-empty allowlist used to switch automation on by itself; now only
  # POLICY_AUTO_BLOCK=on does, and the lab site ships it off.
  pol=$(ks GET /policy | body | jq -c '{auto_block, auto_block_allowed, auto_block_disabled_reason, allowlist_entries, auto_min_confidence, auto_min_severity}')
  say "site.env POLICY_AUTO_BLOCK=$(site POLICY_AUTO_BLOCK), ALLOWLIST_IPS=$(site ALLOWLIST_IPS), ALLOWLIST_MACS=$(site ALLOWLIST_MACS)"
  say "GET /policy: $pol"
  say "gauges: auto_block_configured=$(ks_metric killswitch_auto_block_configured) auto_block_enabled=$(ks_metric killswitch_auto_block_enabled) (the held-back alert needs 1 and 0)"
  [[ $(jq -r .auto_block <<<"$pol") == off && $(jq -r .auto_block_allowed <<<"$pol") == false &&
    $(jq -r .auto_block_disabled_reason <<<"$pol") == "$AUTO_OFF_REASON" && $(jq -r .allowlist_entries <<<"$pol") -gt 0 ]] || ok=0
  if [[ -n ${PENDING_ID:-} ]]; then
    ACTION=$(ks GET "/actions/$PENDING_ID" | body)
    say "step 3's action now: $(jq -c '{id, state, auto_approved, policy_rule}' <<<"$ACTION")"
    [[ $(jq -r .state <<<"$ACTION") == pending && $(jq -r .auto_approved <<<"$ACTION") == false ]] || ok=0
  else
    say "no action from step 3 to look at"; ok=0
  fi
  # The lab's indicators sit below the default auto thresholds, so step 3
  # alone would stay pending either way. A detection that clears every other
  # auto-block condition (attested, confidence 95, critical, an unprotected
  # device) shows that the switch is what holds it back.
  w0=$(ks_metric "$withheld")
  r=$(evaluate_signed "${V1_IP:-10.77.0.123}" "$V1_MAC" auto-off.netsoldier.test | body)
  w1=$(ks_metric "$withheld")
  id=$(jq -r '.action.id // empty' <<<"$r")
  say "signed detection for $V1 (attested, 95, critical) -> $(jq -c '{decision: .decision.Action, withheld: .decision.Withheld, reason: .decision.Reason, state: .action.state}' <<<"$r")"
  say "auto_block_withheld_total{reason=auto_block_off}: $w0 -> $w1"
  [[ $(jq -r .decision.Action <<<"$r") == pending && $(jq -r .action.state <<<"$r") == pending &&
    $(jq -r .decision.Reason <<<"$r") == *"$AUTO_OFF_REASON; every other auto-block condition held"* ]] || ok=0
  [[ $w0 != absent && $w1 != absent ]] && gt "$w1" "$w0" || ok=0
  if [[ -n $id ]]; then
    say "$id rejected -> $(ks POST "/actions/$id/reject" '{"reason":"lab scenario: automation-off check"}' | body | jq -c '{state, rejected_by}')"
  fi
  if ((ok)); then
    pass 3a "as shipped: auto_block=off ($AUTO_OFF_REASON) with $(jq -r .allowlist_entries <<<"$pol") allowlist entries; step 3 pending; an otherwise auto-blockable detection queued and counted as withheld"
  else
    fail 3a "automation is not off as shipped, or not reported as such"
  fi
}

# ── 4. operator approval -> rule in AdGuard, name sinkholed ────────────
step4() {
  local wrong r code
  [[ -n ${PENDING_ID:-} ]] || { fail 4 "no pending action to approve"; return; }
  wrong=$(http node POST "$KS/actions/$PENDING_ID/approve" '{"action_type":"dns_sinkhole"}' \
    "Authorization: Bearer $INGEST" "X-Netsoldier-Actor: $ACTOR" | status)
  say "approve with the ingest token -> $wrong"
  r=$(ks POST "/actions/$PENDING_ID/approve" '{"action_type":"dns_sinkhole"}')
  code=$(status <<<"$r")
  say "approve with the operator token as $ACTOR -> $code $(body <<<"$r" | jq -c '{state, approved_by, action_type, activated_at, expires_at}')"
  retry 20 action_state "$PENDING_ID" active || true
  if [[ $(jq -r .state <<<"$ACTION") == active ]] && retry 15 rule_present "$D_PENDING" &&
    retry 15 resolves_to "$V1" "$D_PENDING" 0.0.0.0; then
    say "AdGuard rule: $(ag_rules | grep -F "$D_PENDING")"
    pass 4 "active, approved_by=$(jq -r .approved_by <<<"$ACTION"); $V1 now gets $D_PENDING -> $(resolve "$V1" "$D_PENDING")"
  else
    fail 4 "state $(jq -r .state <<<"$ACTION"), rules: $(ag_rules | tr '\n' ' '), answer $(resolve "$V1" "$D_PENDING")"
  fi
}

# ── 5. TTL -> rule gone, name resolves again ───────────────────────────
step5() {
  local ttl
  [[ -n ${PENDING_ID:-} ]] || { fail 5 "no action"; return; }
  ttl=$(jq -r .ttl_seconds <<<"$ACTION")
  say "waiting for the TTL (${ttl}s from activation, expires $(jq -r .expires_at <<<"$ACTION"))"
  if retry $((ttl + 90)) action_state "$PENDING_ID" reverted && retry 20 rule_absent "$D_PENDING" &&
    retry 20 resolves_to "$V1" "$D_PENDING" "$ZONE_ADDR"; then
    pass 5 "reverted_by=$(jq -r .reverted_by <<<"$ACTION") at $(jq -r .reverted_at <<<"$ACTION"); no rule; $D_PENDING -> $(resolve "$V1" "$D_PENDING")"
    # Resolving a listed name again is a new detection, hence a new pending
    # action. Reject it, so the auto-block policy of 3b does not pick it up.
    if retry 60 action_for pending "$D_PENDING"; then
      REJECTED_ID=$(jq -r .id <<<"$ACTION")
      say "the lookups after the revert were detected again: $REJECTED_ID pending; rejected -> $(ks POST "/actions/$REJECTED_ID/reject" \
        '{"reason":"lab scenario: the TTL check looked the name up again"}' | body | jq -c '{state, rejected_by}')"
    fi
  else
    fail 5 "state $(jq -r .state <<<"$ACTION"), rules: $(ag_rules | tr '\n' ' ')"
  fi
}

# ── 3b. auto-block of an attested indicator ────────────────────────────
# The auto variant switches automation on (POLICY_AUTO_BLOCK=on) and lowers
# the thresholds to the lab list's 80/high; `auto_policy off` puts back
# exactly the POLICY_AUTO_BLOCK entry that was deployed (the site's
# configMapKeyRef) and drops the thresholds. Not called in a subshell: it
# keeps what it saved in AUTO_ENV_SAVED.
AUTO_POLICY=shipped
AUTO_ENV_SAVED=
KS_AUTO_ENV='[.spec.template.spec.containers[] | select(.name == "killswitch-controller") | .env[]? | select(.name == "POLICY_AUTO_BLOCK")][0]'

auto_policy() { # on|off
  local env patch
  case $1 in
    on)
      [[ $AUTO_POLICY == on ]] && return 0
      AUTO_ENV_SAVED=$(k -n "$NS" get deploy/killswitch-controller -o json |
        jq -c "$KS_AUTO_ENV"' // {name: "POLICY_AUTO_BLOCK", "$patch": "delete"}')
      env='[{"name":"POLICY_AUTO_BLOCK","value":"on","valueFrom":null},{"name":"POLICY_AUTO_CONFIDENCE","value":"80"},{"name":"POLICY_AUTO_SEVERITY","value":"high"}]'
      ;;
    off)
      [[ $AUTO_POLICY == on ]] || return 0
      env=$(jq -c '[if has("$patch") then . elif has("valueFrom") then . + {value: null} else . + {valueFrom: null} end,
        {name: "POLICY_AUTO_CONFIDENCE", "$patch": "delete"}, {name: "POLICY_AUTO_SEVERITY", "$patch": "delete"}]' <<<"$AUTO_ENV_SAVED")
      ;;
  esac
  patch=$(jq -cn --argjson e "$env" '{spec: {template: {spec: {containers: [{name: "killswitch-controller", env: $e}]}}}}')
  k -n "$NS" patch deploy/killswitch-controller --type=strategic -p "$patch" >/dev/null ||
    { say "could not switch the killswitch policy $1"; return 1; }
  k -n "$NS" rollout status deploy/killswitch-controller --timeout=180s >/dev/null
  AUTO_POLICY=$1
  say "killswitch policy $1: $(k -n "$NS" logs deploy/killswitch-controller | jq -r 'select(.msg == "policy loaded") |
    "auto_block=\(.auto_block) auto_block_allowed=\(.auto_block_allowed) auto_confidence=\(.auto_confidence) auto_severity=\(.auto_severity) allowlist_entries=\(.allowlist_entries)"' | tail -1)"
  say "POLICY_AUTO_BLOCK in the Deployment: $(k -n "$NS" get deploy/killswitch-controller -o json | jq -c "$KS_AUTO_ENV")"
}

step3b() {
  local t0 t1 pol
  auto_policy on
  pol=$(ks GET /policy | body | jq -c '{auto_block, auto_block_allowed, auto_block_disabled_reason}')
  say "GET /policy: $pol; gauges: auto_block_configured=$(ks_metric killswitch_auto_block_configured) auto_block_enabled=$(ks_metric killswitch_auto_block_enabled)"
  lab_ssh sudo netsoldier-lab-lan release "$V2" >/dev/null
  t1=$(now)
  V2_IP=$(lease "$V2")
  retry 60 device_seen_since "$V2_IP" "$V2_MAC" "$V2_NAME" "$t1" || say "$V2 not (yet) in device-inventory"
  t0=$(now)
  say "$V2 ($V2_IP) resolves $D_AUTO -> $(resolve "$V2" "$D_AUTO")"
  if retry 60 alert_for "$D_AUTO" "$V2_IP" && retry 60 action_for active "$D_AUTO"; then
    AUTO_ID=$(jq -r .id <<<"$ACTION")
    say "action after $(($(now) - t0))s: $(jq -c '{id, state, auto_approved, approved_by, target_mac, policy_rule}' <<<"$ACTION")"
    if [[ $(jq -r .auto_approved <<<"$ACTION") == true && $(jq -r .target_mac <<<"$ACTION") == "$V2_MAC" ]] &&
      retry 15 resolves_to "$V2" "$D_AUTO" 0.0.0.0; then
      pass 3b "POLICY_AUTO_BLOCK=on: auto-blocked without approval ($(jq -r .approved_by <<<"$ACTION")); $V2 now gets $D_AUTO -> 0.0.0.0"
    else
      fail 3b "action not auto-approved or name not sinkholed"
    fi
  else
    fail 3b "no auto-blocked action for $D_AUTO within 60 s"
  fi
}

# ── 7. the gateway is never enforced against ───────────────────────────
evaluate_signed() { # CLIENT_IP CLIENT_MAC DOMAIN: POST /evaluate as the detection-engine would
  local id body t sig
  id="DET-labscenario-$(date +%s%N | cut -c1-15)"
  body=$(jq -cn --arg id "$id" --arg ts "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)" --arg ip "$1" --arg mac "$2" --arg d "$3" '{
    schema_version: "2.0", id: $id, timestamp: $ts,
    summary: ("lab scenario: query for " + $d + " (attested, confidence 95)"),
    domain: $d, matched_ioc: $d, ioc_type: "domain", client_ip: $ip, client_mac: $mac,
    severity: "critical", confidence: 95, source: "lab", signal_class: "ioc", tags: [],
    signals: [{class: "ioc", confidence: 95, indicator: $d, indicator_type: "domain", source: "lab"}],
    target: {type: "domain", value: $d}}')
  t=$(date +%s)
  sig=$(printf '%s.%s' "$t" "$body" | WEBHOOK_SECRET=$WEBHOOK_SECRET "$LAB_VENV/bin/python" -I -c '
import hashlib, hmac, os, sys
print(hmac.new(os.environ["WEBHOOK_SECRET"].encode(), sys.stdin.buffer.read(), hashlib.sha256).hexdigest())')
  http node POST "$KS/evaluate" "$body" "Authorization: Bearer $INGEST" "X-Webhook-Signature: t=$t,v1=$sig" "Content-Type: application/json"
}

step7() {
  local t0 by_ip by_mac nothing ok=1 pol
  auto_policy on # still on after 3b; switched on here when 7 runs without it
  t0=$(now)
  say "the gateway ($GATEWAY_IP) resolves $D_GW -> $(resolve "$GW_NS" "$D_GW") (auto policy on)"
  if retry 60 alert_for "$D_GW" "$GATEWAY_IP"; then
    say "alert: $(jq -c '{id, client_ip, client_mac, confidence}' <<<"$ALERT")"
    sleep 15 # the outbox delivers within seconds; give it more
    nothing=$(for l in pending active failed history; do ks GET "/actions/$l" | body; done |
      jq -s --arg d "$D_GW" '[.[][] | select(.blocked_domain == $d)] | length')
    say "actions for $D_GW: $nothing; AdGuard rule: $(ag_rules | grep -cF "$D_GW"); gateway still gets $(resolve "$GW_NS" "$D_GW")"
    [[ $nothing == 0 ]] && rule_absent "$D_GW" || ok=0
  else
    say "no alert for the gateway's lookup"; ok=0
  fi
  by_ip=$(evaluate_signed "$GATEWAY_IP" "" gw-direct.netsoldier.test | body | jq -c '{decision: .decision.Action, reason: .decision.Reason, action}')
  by_mac=$(evaluate_signed 10.77.0.123 "$GATEWAY_MAC" gw-direct-mac.netsoldier.test | body | jq -c '{decision: .decision.Action, reason: .decision.Reason, action}')
  say "signed event naming the gateway's IP  -> $by_ip"
  say "signed event naming the gateway's MAC -> $by_mac"
  [[ $(jq -r .decision <<<"$by_ip") == ignore && $(jq -r .action <<<"$by_ip") == null ]] || ok=0
  [[ $(jq -r .decision <<<"$by_mac") == ignore && $(jq -r .action <<<"$by_mac") == null ]] || ok=0
  auto_policy off
  pol=$(ks GET /policy | body | jq -c '{auto_block, auto_block_allowed, auto_block_disabled_reason}')
  say "restored: GET /policy $pol"
  if [[ $(jq -r .auto_block <<<"$pol") != off || $(jq -r .auto_block_disabled_reason <<<"$pol") != "$AUTO_OFF_REASON" ]]; then
    say "the shipped policy (POLICY_AUTO_BLOCK=off) is not back"; ok=0
  fi
  if ((ok)); then
    pass 7 "gateway detections (lookup, by IP, by MAC; confidence 95, auto-block on) -> ignore, no action; shipped policy restored"
  else
    fail 7 "a detection naming the gateway produced an action or was not seen, or the shipped policy is not back"
  fi
}

# ── 6. audit trail ─────────────────────────────────────────────────────
audit_line() { jq -r 'sort_by(.seq) | map("\(.from_state // "")->\(.to_state) by \(.actor)") | join(", ")'; }
ch_line() { ch "SELECT arrayStringConcat(groupArray(concat(from_state, '->', to_state, ' by ', actor)), ', ')
  FROM (SELECT * FROM netsoldier.audit_log WHERE action_id = '$1' ORDER BY timestamp)"; }

ch_complete() { # ID N: ClickHouse holds N entries for ID
  [[ $(ch "SELECT count() FROM netsoldier.audit_log WHERE action_id = '$1'") -ge $2 ]]
}

step6() {
  local id entries api chl ok=1 want
  for id in ${PENDING_ID:-} ${AUTO_ID:-} ${REJECTED_ID:-}; do
    entries=$(ks GET "/audit?action_id=$id&limit=100" | body)
    api=$(audit_line <<<"$entries")
    # The forwarder ships the local audit to ClickHouse in the background.
    retry 60 ch_complete "$id" "$(jq length <<<"$entries")" || true
    chl=$(ch_line "$id")
    say "$id  GET /audit:  $api"
    say "$id  audit_log:   $chl"
    # Created by the policy; approved (and applied) by the operator named
    # in the header, or by the policy for the auto variant; lifted by the
    # TTL reaper.
    if [[ $id == "${PENDING_ID:-}" ]]; then
      want="->pending by auto-policy|pending->approved by $ACTOR|approved->active by $ACTOR|active->reverted by ttl"
    elif [[ $id == "${REJECTED_ID:-}" ]]; then
      want="->pending by auto-policy|pending->rejected by $ACTOR"
    else
      # An auto-block is created approved, by the policy.
      want="->approved by auto-policy|approved->active by auto-policy"
    fi
    local w
    IFS='|' read -ra parts <<<"$want"
    for w in "${parts[@]}"; do
      grep -qF -- "$w" <<<"$api" || { say "GET /audit lacks '$w'"; ok=0; }
    done
    # Same entries (rows of one millisecond may sort either way in ClickHouse).
    [[ -n $chl && $(tr ',' '\n' <<<"$chl" | sed 's/^ //' | sort) == $(tr ',' '\n' <<<"$api" | sed 's/^ //' | sort) ]] ||
      { say "audit_log differs from GET /audit"; ok=0; }
  done
  [[ -n ${PENDING_ID:-} ]] || ok=0
  if ((ok)); then pass 6 "every transition in GET /audit and in ClickHouse audit_log, same actors"; else fail 6 "audit incomplete"; fi
}

dns_answers() { # HOST: does anything answer a DNS query on HOST:53/udp?
  "$LAB_VENV/bin/python" -I -c '
import socket, sys
q = bytes.fromhex("12340100000100000000000007657861 6d706c650474657374 0000010001".replace(" ", ""))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(q, (sys.argv[1], 53))
try:
    s.recv(512)
    print("answered")
except OSError:
    print("no answer")' "$1"
}

# ── 8. web UI from the LAN ─────────────────────────────────────────────
step8() {
  local hz login bad good cookies ok=1 real
  hz=$(http "$V1" GET "$ORIGIN/healthz")
  login=$(http "$V1" GET "$ORIGIN/login")
  bad=$(http "$V1" POST "$ORIGIN/api/login" '{"password":"not-the-password","actor":"lab-operator"}' \
    "Origin: $ORIGIN" "Content-Type: application/json" | status)
  good=$(http "$V1" POST "$ORIGIN/api/login" "$(jq -cn --arg p "$UI_PASS" --arg a "$ACTOR" '{password: $p, actor: $a}')" \
    "Origin: $ORIGIN" "Content-Type: application/json")
  cookies=$(jq -r '[.headers[] | select(.[0] | ascii_downcase == "set-cookie") | .[1] | split(";") |
    (.[0] | split("=")[0]) + " (" + ([.[1:][] | ltrimstr(" ") | select(test("^(Path|HttpOnly|SameSite|Max-Age|Secure)"))] | join("; ")) + ")"] | join(", ")' <<<"$good")
  say "$V1 -> GET $ORIGIN/healthz: $(status <<<"$hz") $(body <<<"$hz")"
  say "$V1 -> GET $ORIGIN/login: $(status <<<"$login"), sign-in form: $(body <<<"$login" | grep -c 'type="password"')"
  say "$V1 -> POST /api/login wrong password: $bad; generated password: $(status <<<"$good") $(body <<<"$good")"
  say "cookies: $cookies"
  [[ $(status <<<"$hz") == 200 && $(status <<<"$login") == 200 && $bad == 401 && $(status <<<"$good") == 200 ]] || ok=0
  [[ $cookies == *netsoldier_session* && $cookies == *netsoldier_csrf* ]] || ok=0
  # The counters are on the metrics listener (9464), which has no hostPort:
  # the published UI port answers /metrics with 404, and the node's LAN
  # address has nothing on 9464.
  local m_ui m_port
  m_ui=$(http "$V1" GET "$ORIGIN/metrics" | status)
  m_port=$(lab_ssh sudo ip netns exec "$V1" "$HTTP" <<<"{\"method\": \"GET\", \"url\": \"http://$NODE_LAN_IP:9464/metrics\", \"timeout\": 5}" | status)
  say "$V1 -> GET $ORIGIN/metrics: $m_ui; GET http://$NODE_LAN_IP:9464/metrics: $m_port"
  [[ $m_ui == 404 && $m_port == error:* ]] || ok=0
  # Nothing on the node's real address: the published ports are bound to
  # the lab LAN address only.
  real=$(curl -s -o /dev/null -m 4 -w '%{http_code}' "http://$(lab_target | awk '{print $2}'):3000/healthz" || true)
  say "from this workstation (real LAN) -> http://<node>:3000/healthz: ${real:-000} (000 = no answer)"
  [[ ${real:-000} == 000 ]] || ok=0
  real=$(curl -s -o /dev/null -m 4 -w '%{http_code}' "http://$(lab_target | awk '{print $2}'):9464/metrics" || true)
  say "from this workstation (real LAN) -> http://<node>:9464/metrics: ${real:-000}"
  [[ ${real:-000} == 000 ]] || ok=0
  local dns
  dns=$(dns_answers "$(lab_target | awk '{print $2}')")
  say "from this workstation (real LAN) -> DNS query to <node>:53: $dns"
  [[ $dns == "no answer" ]] || ok=0
  if ((ok)); then pass 8 "UI on $ORIGIN: /healthz 200, /login 200, sign-in 200 with session+csrf cookies, /metrics 404, :9464 unreachable from the LAN; not on the real LAN"; else fail 8 "web UI check failed"; fi
}

# ── P. NetworkPolicies admit the real edges and nothing else ───────────
# Throw-away pods wearing a workload's name label (but not part-of, so no
# Service picks them up) try each port; the policies select by that label.
# The scraper's stand-in is a pod labelled like Prometheus in the
# observability namespace: the identity the scrape policy admits.
PROBE_NS=observability
SCRAPE_POLICY=allow-core-metrics-scrape
probe_pod() { # NAMESPACE NAME LABEL|-
  local labels='{}'
  [[ $3 != - ]] && labels=$(jq -cn --arg n "$3" '{"app.kubernetes.io/name": $n}')
  k -n "$1" run "$2" --image=docker.io/library/busybox:1.37.0 --restart=Never \
    --labels="$(jq -r 'to_entries | map("\(.key)=\(.value)") | join(",")' <<<"$labels")" \
    --overrides='{"spec":{"automountServiceAccountToken":false,"securityContext":{"runAsNonRoot":true,"runAsUser":65534,"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"'"$2"'","image":"docker.io/library/busybox:1.37.0","command":["sleep","300"],"securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}}]}}' >/dev/null
}
# reach POD IP PORT: POD is NAME (namespace netsoldier) or NAMESPACE/NAME.
reach() {
  local ns=$NS pod=$1
  [[ $pod == */* ]] && ns=${pod%%/*} pod=${pod#*/}
  k -n "$ns" exec "$pod" -- nc -z -w 3 "$2" "$3" >/dev/null 2>&1 && echo open || echo closed
}
reach_open() { [[ $(reach "$@") == open ]]; }
# probe_table: "pod name ip port want" lines on stdin; appends to LINE and
# clears OK on any surprise. An `open` is retried for a few seconds: a
# policy applied a moment ago may not be enforced yet.
probe_table() {
  local pod name ip port want got
  while read -r pod name ip port want; do
    got=$(reach "$pod" "$ip" "$port")
    if [[ $got != "$want" && $want == open ]] && retry 15 reach_open "$pod" "$ip" "$port"; then
      got=open
    fi
    LINE+="$pod->$name:$port=$got "
    PROBES=$((PROBES + 1))
    [[ $got == "$want" ]] || { OK=0; say "UNEXPECTED $pod -> $name:$port $got (want $want)"; }
  done
}
# The scrape policy exactly as the profiles that run Prometheus ship it
# (base/network-policies/extras), in the netsoldier namespace.
scrape_policy() {
  "$LAB_VENV/bin/python" -I -c '
import sys, yaml
for d in yaml.safe_load_all(open(sys.argv[1])):
    if d and d["kind"] == "NetworkPolicy" and d["metadata"]["name"] == sys.argv[2]:
        d["metadata"]["namespace"] = sys.argv[3]
        d["metadata"].setdefault("labels", {})["netsoldier.io/lab-scenario"] = "probe"
        yaml.safe_dump(d, sys.stdout)' \
    "$REPO_DIR/deploy/kustomize/base/network-policies/extras/core-edges.yaml" "$SCRAPE_POLICY" "$NS"
}

step_policies() {
  local ch ks inv det ti ag ui made_ns=0 metrics
  LINE="" OK=1 PROBES=0
  ch=$(svc "$NS" clickhouse) ks=$(svc "$NS" killswitch-controller) inv=$(svc "$NS" device-inventory)
  det=$(svc "$NS" detection-engine) ti=$(svc "$NS" threat-intel-sync) ag=$(svc dns adguard-web)
  ui=$(svc "$NS" web-ui)
  if ! k get namespace "$PROBE_NS" >/dev/null 2>&1; then
    k create namespace "$PROBE_NS" >/dev/null && made_ns=1
    k label namespace "$PROBE_NS" netsoldier.io/lab-scenario=probe \
      pod-security.kubernetes.io/enforce=restricted >/dev/null
  fi
  probe_pod "$NS" probe-web-ui web-ui
  probe_pod "$NS" probe-detection detection-engine
  probe_pod "$NS" probe-nobody -
  probe_pod "$PROBE_NS" probe-scraper prometheus
  k -n "$NS" wait --for=condition=Ready pod/probe-web-ui pod/probe-detection pod/probe-nobody --timeout=120s >/dev/null
  k -n "$PROBE_NS" wait --for=condition=Ready pod/probe-scraper --timeout=120s >/dev/null
  # pod target ip port expected
  probe_table <<EOF
probe-web-ui killswitch $ks 8084 open
probe-web-ui device-inventory $inv 8081 open
probe-web-ui detection-engine $det 8080 open
probe-web-ui clickhouse $ch 8123 closed
probe-web-ui adguard-api $ag 3000 closed
probe-web-ui threat-intel $ti 8083 closed
probe-web-ui web-ui-metrics $ui 9464 closed
probe-detection clickhouse $ch 8123 open
probe-detection clickhouse-native $ch 9000 closed
probe-detection adguard-api $ag 3000 open
probe-detection threat-intel $ti 8083 open
probe-detection killswitch $ks 8084 open
probe-detection web-ui-metrics $ui 9464 closed
probe-nobody killswitch $ks 8084 closed
probe-nobody device-inventory $inv 8081 closed
probe-nobody clickhouse $ch 8123 closed
probe-nobody adguard-api $ag 3000 closed
probe-nobody web-ui-metrics $ui 9464 closed
$PROBE_NS/probe-scraper web-ui-metrics $ui 9464 closed
$PROBE_NS/probe-scraper web-ui $ui 3000 closed
EOF
  say "$LINE"
  # The core profile runs no Prometheus, so nothing admits the scraper
  # above. With the scrape policy the observability profiles ship, the same
  # pod reaches the metrics port, and still not the UI port.
  LINE=""
  if scrape_policy | k apply -f - >/dev/null; then
    say "applied $SCRAPE_POLICY from base/network-policies/extras/core-edges.yaml, ports $(k -n "$NS" get networkpolicy "$SCRAPE_POLICY" -o json | jq -c '[.spec.ingress[].ports[].port]')"
    probe_table <<EOF
$PROBE_NS/probe-scraper web-ui-metrics $ui 9464 open
$PROBE_NS/probe-scraper web-ui $ui 3000 closed
probe-nobody web-ui-metrics $ui 9464 closed
probe-web-ui web-ui-metrics $ui 9464 closed
EOF
    say "$LINE"
    metrics=$(k -n "$PROBE_NS" exec probe-scraper -- wget -q -T 5 -O - "http://$ui:9464/metrics" 2>&1)
    say "scraper -> GET http://web-ui:9464/metrics: $(grep -c '^# TYPE' <<<"$metrics") metric families ($(grep '^# TYPE' <<<"$metrics" | awk '{print $3}' | head -n 3 | paste -sd, -), ...)"
    grep -q '^# TYPE netsoldier_webui_' <<<"$metrics" || { OK=0; say "the metrics port did not answer with the web UI's counters"; }
    k -n "$NS" delete networkpolicy "$SCRAPE_POLICY" --ignore-not-found >/dev/null
  else
    OK=0; say "could not apply $SCRAPE_POLICY"
  fi
  k -n "$NS" delete pod probe-web-ui probe-detection probe-nobody --wait=false >/dev/null
  k -n "$PROBE_NS" delete pod probe-scraper --wait=false >/dev/null
  ((made_ns)) && k delete namespace "$PROBE_NS" --wait=false >/dev/null
  if ((OK)); then
    pass P "$PROBES probes: every allowed edge open, every other one closed; the metrics port answers the scraper only while the scrape policy admits it"
  else
    fail P "a NetworkPolicy admits too much or too little"
  fi
}

memory() {
  echo "node memory:"
  k top node 2>/dev/null | sed 's/^/      /'
  lab_ssh free -m | sed 's/^/      /'
}

# `scenario.sh` runs everything in order; `scenario.sh P 8` only those steps
# (the ones that need an earlier step's action cannot run alone).
STEPS=("$@")
((${#STEPS[@]})) || STEPS=(1 2 3 3a 4 5 3b 7 6 8 P)
for s in "${STEPS[@]}"; do
  case $s in
    P) step_policies ;;
    1 | 2 | 3 | 3a | 4 | 5 | 3b | 6 | 7 | 8) "step$s" ;;
    *) lab_die "unknown step $s" ;;
  esac
done
# A run that switched automatic blocking on and stopped short of step 7
# (`scenario.sh 3b`, say) still leaves the shipped policy behind.
auto_policy off
memory

echo
failed=0
for s in "${STEPS[@]}"; do
  printf '%s:%s  ' "$s" "${RESULT[$s]:-SKIP}"
  [[ ${RESULT[$s]:-} == PASS ]] || failed=1
done
echo
exit $failed
