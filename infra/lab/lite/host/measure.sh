#!/usr/bin/env bash
# Memory of the lite profile's containers, from their cgroups.
#
#   measure.sh              one table now
#   measure.sh sample FILE  append one sample per container to FILE every 2 s
#                           until killed
#   measure.sh peaks FILE   per-container maximum of the samples in FILE
#
# Columns: rss = sum of VmRSS of the container's processes (resident
# memory); anon = the cgroup's anonymous memory (what cannot be reclaimed
# without swap); current = memory.current, which also counts page cache and
# is what the limit (max) is enforced against.
set -euo pipefail

# One line per running netsoldier container: name rss anon current max
sample() {
  local name pid cg rss anon cur max p
  # A container that is being restarted vanishes between the listing and the
  # reads; it is skipped for this sample.
  for name in $(podman ps --format '{{.Names}}' --filter label=app=netsoldier | sort); do
    pid=$(podman inspect --format '{{.State.Pid}}' "$name" 2>/dev/null) || continue
    cg=/sys/fs/cgroup$(awk -F: '$1 == "0" {print $3}' "/proc/$pid/cgroup" 2>/dev/null) || continue
    [[ -r $cg/memory.current ]] || continue
    rss=0
    for p in $(cat "$cg/cgroup.procs" 2>/dev/null); do
      rss=$((rss + $(awk '/^VmRSS:/ {print $2 * 1024}' "/proc/$p/status" 2>/dev/null || echo 0)))
    done
    anon=$(awk '$1 == "anon" {print $2}' "$cg/memory.stat" 2>/dev/null) || continue
    cur=$(cat "$cg/memory.current" 2>/dev/null) || continue
    max=$(cat "$cg/memory.max" 2>/dev/null) || continue
    printf '%s %s %s %s %s\n' "${name#netsoldier-}" "$rss" "${anon:-0}" "$cur" "$max"
  done
}

table() { # reads "name rss anon current max" lines
  awk 'function m(b) {return sprintf("%.1f", b / 1048576)}
    BEGIN {printf "%-20s %9s %9s %9s %9s\n", "container", "rss MiB", "anon MiB", "cur MiB", "max MiB"}
    {lim = "none"; if ($5 != "max") lim = m($5)
     printf "%-20s %9s %9s %9s %9s\n", $1, m($2), m($3), m($4), lim
     r += $2; a += $3; c += $4; if ($5 != "max") x += $5}
    END {printf "%-20s %9s %9s %9s %9s\n", "TOTAL", m(r), m(a), m(c), m(x)}'
}

case ${1:-} in
  "") sample | table ;;
  sample)
    set +e
    while :; do sample | sed "s/^/$(date +%s) /" >>"$2"; sleep 2; done ;;
  peaks)
    awk '{n = $2; if ($3 > r[n]) r[n] = $3; if ($4 > a[n]) a[n] = $4; if ($5 > c[n]) c[n] = $5; x[n] = $6}
      END {for (n in r) print n, r[n], a[n], c[n], x[n]}' "$2" | sort | table ;;
  *) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
