#!/usr/bin/env bash
# Smoke check for the lab node (task lab:smoke):
#   1. the node is Ready and the `gvisor` RuntimeClass exists;
#   2. a pod with runtimeClassName: gvisor runs inside gVisor (the kernel it
#      sees is gVisor's: uname and /proc/version), and the same image without
#      it sees the node's kernel;
#   3. detection-engine, one of the project's Go services, runs under runsc
#      and answers /healthz over the cluster network.
# Uses the fetched kubeconfig through the node's firewall, plus SSH for the
# containerd view of the pods. Leaves nothing behind unless KEEP=1.
set -euo pipefail
# shellcheck source=infra/lab/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

KUBECTL=${KUBECTL:-$LAB_VENV/bin/kubectl}
export KUBECONFIG=$LAB_KUBECONFIG
[[ -x $KUBECTL ]] || lab_die "no kubectl at $KUBECTL (run: task lab:tools)"
[[ -f $KUBECONFIG ]] || lab_die "no kubeconfig at $KUBECONFIG (run: task lab:kubeconfig)"

ns=netsoldier-smoke
failed=0
k() { "$KUBECTL" "$@"; }
pass() { echo "PASS  $*"; }
fail() {
  echo "FAIL  $*"
  failed=1
}
cleanup() {
  [[ ${KEEP:-0} == 1 ]] || k delete namespace "$ns" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ── 1. node and RuntimeClass ──────────────────────────────────────
if k wait --for=condition=Ready node --all --timeout=180s >/dev/null; then
  pass "node Ready: $(k get nodes -o jsonpath='{range .items[*]}{.metadata.name} kubelet={.status.nodeInfo.kubeletVersion} runtime={.status.nodeInfo.containerRuntimeVersion}{"\n"}{end}')"
else
  fail "node not Ready"
fi
node_kernel=$(k get nodes -o jsonpath='{.items[0].status.nodeInfo.kernelVersion}')

handler=$(k get runtimeclass gvisor -o jsonpath='{.handler}' 2>/dev/null || true)
if [[ $handler == runsc ]]; then
  pass "RuntimeClass gvisor -> handler runsc"
else
  fail "RuntimeClass gvisor missing or wrong handler (got '${handler}')"
fi

# ── 2. inside gVisor vs. on the default runtime ───────────────────
k delete namespace "$ns" --ignore-not-found --wait=true >/dev/null
k apply -f "$LAB_DIR/smoke.yaml" >/dev/null

k -n "$ns" wait --for=jsonpath='{.status.phase}'=Succeeded \
  pod/kernel-gvisor pod/kernel-runc --timeout=240s >/dev/null || true

# The pods are "restricted" (no CAP_SYSLOG), so dmesg is refused on both
# runtimes; the kernel identifies itself through uname and /proc/version.
gv=$(k -n "$ns" logs kernel-gvisor 2>/dev/null || true)
rc=$(k -n "$ns" logs kernel-runc 2>/dev/null || true)
field() { sed -n "s/^$1: //p" <<<"$2"; }
gv_kernel=$(field uname-r "$gv")
rc_kernel=$(field uname-r "$rc")
echo "      node kernel:   $node_kernel"
echo "      kernel-gvisor: $(field proc-version "$gv") | $(field seccomp "$gv") | dmesg: $(field dmesg "$gv")"
echo "      kernel-runc:   $(field proc-version "$rc" | cut -c1-70)... | $(field seccomp "$rc") | dmesg: $(field dmesg "$rc")"

if [[ $(field proc-version "$gv") == *gvisor* && -n $gv_kernel && $gv_kernel != "$node_kernel" ]]; then
  pass "runtimeClassName: gvisor runs in gVisor: its kernel reports itself as $gv_kernel, not the node's $node_kernel"
else
  fail "the gvisor pod does not look sandboxed"
fi
if [[ $rc_kernel == "$node_kernel" && $(field proc-version "$rc") != *gvisor* ]]; then
  pass "the same image without the RuntimeClass runs on the node's kernel ($rc_kernel), not in gVisor"
else
  fail "the default-runtime pod looks wrong"
fi

# ── 3. detection-engine under runsc ───────────────────────────────
if k -n "$ns" wait --for=condition=Ready pod/detection-engine --timeout=300s >/dev/null; then
  pass "detection-engine Ready (readiness probe GET /healthz) in gVisor, image $(k -n "$ns" get pod detection-engine -o jsonpath='{.status.containerStatuses[0].imageID}')"
else
  fail "detection-engine not Ready"
fi
k -n "$ns" wait --for=jsonpath='{.status.phase}'=Succeeded pod/healthz-client --timeout=180s >/dev/null || true
hz=$(k -n "$ns" logs healthz-client 2>/dev/null || true)
if grep -q '"status":"ok"' <<<"$hz"; then
  pass "GET http://detection-engine.$ns.svc:8080/healthz from a gVisor pod -> $(sed -n 's/^healthz: //p' <<<"$hz")"
else
  fail "no /healthz answer from detection-engine ($hz)"
fi
echo "      detection-engine log (first lines):"
k -n "$ns" logs detection-engine 2>/dev/null | head -n 4 | cut -c1-160 | sed 's/^/        /'

# containerd's own view: which runtime handler started the pod sandbox.
pod_id=$(lab_ssh sudo k3s crictl pods --namespace "$ns" --name detection-engine --latest -q 2>/dev/null || true)
if [[ -n $pod_id ]]; then
  rt=$(lab_ssh sudo k3s crictl inspectp "$pod_id" | jq -r '.status.runtimeHandler // .info.runtimeHandler // empty')
  if [[ $rt == runsc ]]; then
    pass "containerd started the detection-engine sandbox with handler '$rt' ($(lab_ssh sudo runsc --version | head -n1))"
  else
    fail "containerd reports handler '$rt' for the detection-engine sandbox"
  fi
else
  fail "could not find the detection-engine sandbox through crictl"
fi

if [[ $failed == 0 ]]; then
  echo "smoke: all checks passed"
else
  echo "smoke: FAILED (KEEP=1 task lab:smoke leaves namespace $ns for inspection)"
fi
exit "$failed"
