# ADR-0004: Runtime isolation and network privilege separation

- **Date:** 2026-11-16
- **Status:** Accepted
- **Deciders:** magiccactus42 (project owner)
- **Amends:** ADR-0001 (decisions 13, 16 and 17 — how enforcement drivers and services run)

## Context and problem

netSoldier's services parse data that any device on the LAN controls: DNS names, DHCP
options, mDNS and SSDP payloads, ARP and LLDP frames, threat-feed contents. Two of them also
hold the ability to act on the network: `device-inventory` listens with raw sockets, and
`killswitch-controller` carries a driver that sends forged ARP replies.

The November 2026 audit found that this power was badly distributed:

- `device-inventory` ran as one process with `hostNetwork`, raw sockets, an HTTP API, the
  SQLite store and every hand-written packet parser. Because it sat on the host network, its
  API was reachable from the whole LAN and no NetworkPolicy could select it.
- The capabilities it needed were added through `securityContext.capabilities.add`, which
  has no effect for a non-root process without file capabilities — so the listeners could not
  open their sockets at all, while `/healthz` stayed green.
- The ARP isolation driver accepted broadcast and multicast target MACs and trusted a gateway
  MAC learned from a neighbour table any LAN device can forge. One malformed target would have
  poisoned every host on the segment.

The owner's requirement is stricter than "fix those bugs": **a compromised netSoldier
container must not be able to interfere with the network, unless the function it performs
needs that.** A monitor that can be turned into a LAN attack tool is worse than no monitor.

## Decision

We will separate *who can touch the network* from *who handles untrusted data*, and sandbox
everything that does not need the host kernel.

1. **No first-party application pod uses `hostNetwork` or holds a Linux capability.** All
   capabilities dropped, non-root, read-only root filesystem, `RuntimeDefault` seccomp, and a
   default-deny NetworkPolicy with an explicit allow-list per pod. A pod's network namespace
   is created and owned by the runtime's sandbox ("pause") container and wired up by the CNI;
   the application containers inherit it and, without `NET_ADMIN` or `NET_RAW`, cannot change
   it or craft frames in it.

2. **First-party application pods run under gVisor** (`runtimeClassName: gvisor`) in the k3s
   profile. Inside the sandbox a process talks to gVisor's user-space kernel and its own
   network stack rather than to the host kernel, so a code-execution bug in a service does
   not reach the node's network stack or the other pods' kernel surface. This applies to
   `detection-engine`, `device-inventory`, `killswitch-controller`, `threat-intel-sync`,
   `ml-anomaly` and `web-ui`.

3. **Raw network access is confined to one component, `netagent`.** It is the smallest
   binary we can write, and the only first-party workload with `hostNetwork` and `NET_RAW`:
   - It **does not parse**. It opens capture sockets with a kernel BPF filter per protocol
     (ARP, DHCP, mDNS, SSDP, LLDP), checks lengths, and forwards the raw frames with their
     interface and timestamp to `device-inventory`, which does all parsing inside its
     sandbox.
   - It **does not listen**. It opens one authenticated outbound connection to
     `device-inventory` and receives its commands over the same connection, so it exposes no
     port to the LAN.
   - It **cannot send arbitrary frames**. It builds exactly two kinds itself, from validated
     structured commands: ARP probes for active discovery, and — only when started with an
     explicit flag — ARP isolation frames. The guard that refuses the gateway, the sensor's
     own addresses, protected devices, and any broadcast, multicast or off-subnet target
     lives inside the agent, with the gateway MAC pinned from configuration and rate limits
     on both commands. A compromised service can ask; it cannot make the agent comply.

4. **Third-party sensors (Suricata, Zeek) are sniff-only** on a dedicated mirror interface
   that carries no IP address. They keep capture capabilities and run on the default runtime
   because gVisor does not offer the packet-ring capture they depend on. The target state is
   that the mirror interface is moved into the sensor pod's own network namespace by a
   privileged set-up helper, so a sensor shares neither the host's nor the cluster's network;
   until that lands, their host-network position is a recorded residual risk.

5. **ClickHouse runs on the default runtime** with no capabilities. Its workload is
   I/O-bound and sandbox overhead buys little: it parses nothing that comes straight off the
   LAN and is reachable only through NetworkPolicy by authenticated service accounts.

6. **The Podman profile follows the same split**: `netagent` on the host network with
   `NET_RAW` only; every other container on an internal Podman network with all capabilities
   dropped. gVisor is optional there and off by default — a 1 GB Raspberry Pi does not have
   the headroom.

7. **Admission enforces it.** A Kyverno policy requires `runtimeClassName: gvisor` and forbids
   `hostNetwork` and added capabilities for workloads in the `netsoldier` namespace, with
   exceptions granted only to explicitly labelled workloads (`netagent`, the sensors).

This ADR does not decide how sensors get an isolated capture namespace (point 4, a later
step), nor does it change the enforcement tiers of ADR-0001: DNS sinkhole stays the only
automatic action.

## Alternatives considered

| Option | Why not |
|---|---|
| Keep `hostNetwork` on `device-inventory` and bake file capabilities into its image | Makes the listeners work, but leaves the parsers, the API and the raw sockets in one process on the host network: the API stays exposed to the LAN and outside NetworkPolicy, and a single bug yields raw LAN access. |
| A capture sidecar inside the `device-inventory` pod | Containers in a pod share one network namespace. To see the LAN the whole pod would need `hostNetwork`, which puts the application container back on the host network. |
| Sharing another pod's network namespace (the "VPN sidecar" pattern from Compose) | Kubernetes has no cross-pod namespace sharing. Within a pod the sandbox container already plays that role; what was missing was dropping capabilities for real and moving raw access out. |
| A secondary LAN interface in the pod via Multus/macvlan | Works, but adds a second CNI layer that every installer would have to understand, and the application container could still open ordinary sockets on the LAN interface. |
| Parsing in the privileged agent and sending structured events | Smaller protocol, but it puts the hand-written parsers of attacker-controlled bytes back in the one process that has raw access. |
| Kata Containers instead of gVisor | Needs nested virtualisation and a VM per pod; too heavy for an 8 GB budget and unavailable on the Pi. |

## Consequences

- **Positive:** a compromised application container has no raw sockets, no host network, no
  capabilities and no host kernel surface. `device-inventory`'s API leaves the LAN and comes
  under NetworkPolicy. The capability problem disappears instead of being patched. The ARP
  guard moves next to the only code that can send the frames, so it cannot be bypassed by
  whoever compromises the caller.
- **Negative / accepted trade-offs:** one more component and one more internal protocol to
  test and version. gVisor costs syscall and network throughput and needs compatibility
  testing for every image (Go, Node, Python with scikit-learn). The k3s lab needs a real VM;
  an unprivileged LXC cannot host it. Sensors remain privileged until the capture-namespace
  work is done. The Pi profile is not sandboxed by default.
- **Follow-ups:** roadmap step 125.6 (k3s node with gVisor as code), 125.9 (`netagent` and
  the frame protocol; ARP driver moved behind it), 125.12 (RuntimeClass on every first-party
  pod, Kyverno policy), 125.24 (the same split under Podman). Measure gVisor overhead as
  part of the performance baseline, and revisit point 5 if ClickHouse ever ingests data
  that has not passed through a sandboxed service.

## What the first deployments showed (2026-11-16)

Both profiles were deployed in the lab the day this was accepted: the core stack on a k3s
node, and the Podman profile on a single host. The split holds as decided. Four things are
different from what the text above assumes, and anyone relying on this ADR should know them.

- **On k3s a NetworkPolicy is not a boundary towards the node.** kube-router always admits
  traffic from the local node to its pods; this was measured with a deny-all policy in place.
  A process on the host network, `netagent` included, can therefore open a connection to
  every pod on that node whatever the policies say. The rules that admit `netagent` by
  address document intent and nothing more. What limits a compromised `netagent` is that it
  holds two tokens, each valid on one endpoint; every service API requires its own key, and
  that requirement is the control. Host-level policies (Cilium, Calico) would restore the
  boundary and are a candidate for after v1.0.
- **ARP isolation cannot be used in either profile as built.** The frames announce
  `netagent`'s own interface as the gateway, so an isolated device's traffic arrives at our
  host, and the guard refuses to send them while the host forwards IPv4: with forwarding on,
  "isolation" would be relaying. A k3s node and a Podman host always forward. The guard is
  right and stays; isolation frames are disabled in both profiles, and enforcement is by DNS
  only until the router driver exists. Whether the ARP driver returns in another form (frames
  that name an address no interface of ours owns, so the kernel has nothing to forward) or is
  removed is decided with the router driver, after measuring it in the lab.
- **AdGuard Home keeps one capability on k3s.** Its binary carries `NET_BIND_SERVICE` as a
  file capability and the kernel will not execute it unless the capability is in the
  container's bounding set. It is third-party and outside point 1, but it is the one
  capability in the cluster besides `netagent`'s. The Podman profile rebuilds the image
  without the file capability and runs it with none.
- **Point 7 is not in place yet.** The manifests follow the rules; nothing at admission
  enforces them until the Kyverno policy is written (roadmap step 125.12).

## Links

- ADR-0001 — core architecture (out-of-band enforcement, fail-open, enforcement tiers)
- `docs/threat-model.md` — E-01, E-02, E-05, S-04
- gVisor: <https://gvisor.dev> (Apache-2.0)
