#!/usr/bin/env bash
# Simulated home LAN inside the lab host, for the lite profile.
#
#   lan.sh up | down | status | dhcp | dig CLIENT NAME
#
# The lab host itself sits on a real home network (eth0), so nothing
# adversarial happens there. Instead the "home LAN" is a bridge with no
# uplink, living in its own network namespace (the switch), with three ports:
#
#   nslab0         in the host's own namespace: the netSoldier box's LAN NIC
#                  (192.168.77.2/24, static), where netagent captures and
#                  where DNS and the web UI are published
#   gw0            in namespace nslab-gw: the router (192.168.77.1) running
#                  a DHCP server (dnsmasq, bound to gw0 only) that hands out
#                  .100-.150 with DNS = 192.168.77.2
#   eth0           in namespace nslab-victim: a laptop that asks for a lease
#                  with host name "victim-laptop"
#
# No route connects this LAN to eth0: the router has no uplink and the host
# does not route for it. DHCP, ARP and every lookup the scenario makes stay
# on this bridge.
set -euo pipefail

NS_SW=nslab-sw
NS_GW=nslab-gw
NS_VIC=nslab-victim
HOST_IF=nslab0
NET=192.168.77
GW_MAC=02:00:5e:77:00:01
HOST_MAC=02:00:5e:77:00:02
VICTIM_MAC=02:00:5e:77:00:50
VICTIM_NAME=victim-laptop
STATE=/run/nslab

in_ns() { local ns=$1; shift; ip netns exec "$ns" "$@"; }

up() {
  if ip netns list | grep -qw "$NS_SW"; then
    echo "lan: already up"
    return 0
  fi
  command -v dnsmasq >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -q dnsmasq-base >/dev/null
  command -v dhclient >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -q isc-dhcp-client >/dev/null
  mkdir -p "$STATE"
  ip netns add "$NS_SW"
  ip netns add "$NS_GW"
  ip netns add "$NS_VIC"
  for ns in "$NS_SW" "$NS_GW" "$NS_VIC"; do in_ns "$ns" ip link set lo up; done

  # The switch.
  in_ns "$NS_SW" ip link add br0 type bridge stp_state 0
  in_ns "$NS_SW" ip link set br0 up

  # The netSoldier box's NIC.
  ip link add "$HOST_IF" address "$HOST_MAC" type veth peer name sw-host netns "$NS_SW"
  ip addr add "$NET.2/24" dev "$HOST_IF"
  # The router.
  in_ns "$NS_GW" ip link add gw0 address "$GW_MAC" type veth peer name sw-gw netns "$NS_SW"
  in_ns "$NS_GW" ip addr add "$NET.1/24" dev gw0
  # The laptop.
  in_ns "$NS_VIC" ip link add eth0 address "$VICTIM_MAC" type veth peer name sw-victim netns "$NS_SW"

  for port in sw-host sw-gw sw-victim; do
    in_ns "$NS_SW" ip link set "$port" master br0
    in_ns "$NS_SW" ip link set "$port" up
  done
  ip link set "$HOST_IF" up
  in_ns "$NS_GW" ip link set gw0 up
  in_ns "$NS_VIC" ip link set eth0 up

  # DHCP on the router, on gw0 and nothing else (the namespace has no other
  # interface anyway). No DNS from dnsmasq: port 0.
  in_ns "$NS_GW" dnsmasq --conf-file=/dev/null --port=0 --interface=gw0 --bind-interfaces \
    --dhcp-range="$NET.100,$NET.150,255.255.255.0,10m" --dhcp-authoritative \
    --dhcp-option=option:router,"$NET.1" --dhcp-option=option:dns-server,"$NET.2" \
    --dhcp-leasefile="$STATE/dnsmasq.leases" --pid-file="$STATE/dnsmasq.pid" \
    --log-dhcp --log-facility="$STATE/dnsmasq.log"
  echo "lan: up ($HOST_IF $NET.2, router $NET.1 $GW_MAC, victim $VICTIM_MAC)"
}

# dhcp: the laptop asks for a lease (DISCOVER/REQUEST carry its host name).
dhcp() {
  cat >"$STATE/dhclient.conf" <<EOF
send host-name "$VICTIM_NAME";
request subnet-mask, broadcast-address, routers, domain-name-servers;
EOF
  # Our own script: configure the address in the victim namespace and
  # nothing else (the stock dhclient-script would rewrite the HOST's
  # /etc/resolv.conf).
  cat >"$STATE/dhclient-script" <<'EOF'
#!/bin/sh
case "$reason" in
  BOUND|RENEW|REBIND|REBOOT)
    ip addr flush dev "$interface" scope global
    ip addr add "$new_ip_address/$new_subnet_mask" dev "$interface"
    [ -n "$new_routers" ] && ip route replace default via "${new_routers%% *}" dev "$interface"
    echo "$new_ip_address" >/run/nslab/victim.ip
    ;;
  EXPIRE|FAIL|RELEASE|STOP)
    ip addr flush dev "$interface" scope global
    ;;
esac
exit 0
EOF
  chmod 0755 "$STATE/dhclient-script"
  in_ns "$NS_VIC" dhclient -4 -1 -v -cf "$STATE/dhclient.conf" -sf "$STATE/dhclient-script" \
    -lf "$STATE/dhclient.leases" -pf "$STATE/dhclient.pid" eth0 2>&1 | grep -E 'DHCPACK|bound to' || true
  cat "$STATE/victim.ip"
}

down() {
  local pid
  for f in dhclient.pid dnsmasq.pid; do
    [[ -s $STATE/$f ]] && pid=$(cat "$STATE/$f") && kill "$pid" 2>/dev/null || true
  done
  for ns in "$NS_VIC" "$NS_GW" "$NS_SW"; do ip netns del "$ns" 2>/dev/null || true; done
  ip link del "$HOST_IF" 2>/dev/null || true
  rm -rf "$STATE"
  echo "lan: down"
}

status() {
  ip -br addr show dev "$HOST_IF" 2>/dev/null || echo "lan: down"
  for ns in "$NS_GW" "$NS_VIC"; do
    if ip netns list | grep -qw "$ns"; then
      printf '%s: %s\n' "$ns" "$(in_ns "$ns" ip -br -4 addr | { grep -v '^lo' || true; } | tr '\n' ' ')"
    fi
  done
}

# dig CLIENT NAME: resolve NAME through the netSoldier box from the router
# (gw) or the laptop (victim); prints the A records, or the status.
lookup() {
  local ns
  case $1 in gw) ns=$NS_GW ;; victim) ns=$NS_VIC ;; *) echo "client: gw or victim" >&2; exit 2 ;; esac
  in_ns "$ns" dig +time=3 +tries=1 +noall +answer +comments "@$NET.2" "$2" A |
    awk '/status:/ {for (i=1;i<=NF;i++) if ($i=="status:") s=$(i+1)} $4=="A" {a=a" "$5} END {gsub(",","",s); print s a}'
}

case ${1:-} in
  up) up ;;
  down) down ;;
  status) status ;;
  dhcp) dhcp ;;
  dig) lookup "$2" "$3" ;;
  *) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
