# deploy/ — deployment artifacts

Same images everywhere; the profiles differ in how they are run.

| Path | Purpose | Lands at |
|---|---|---|
| `helm/netsoldier/` | umbrella chart (subchart per service + dependencies) | step 36 |
| `kustomize/base/` + `kustomize/overlays/{pi-edge,proxmox-soc}/` | profile overlays for k3s | steps 36, 84–85 |
| `argocd/` | app-of-apps + ApplicationSet generating both profiles | step 37 |
| `kyverno/` | admission policies: cosign `verifyImages` (signed images only), non-root, read-only rootfs, required limits | step 35 |
| `podman/` | the **lite** profile: one host, Podman + systemd Quadlets, no Kubernetes, no ClickHouse | step 125.24 |

Secrets of the k3s profiles are committed **only** SOPS-encrypted (age); see
`security/`. The lite profile generates its secrets on the host at install
time and never commits or copies them.

## The lite profile (`podman/`)

The ten-minute install for a Raspberry Pi or any Linux box: DNS-level
visibility, detection against threat feeds and a site-local list,
human-approved (or, once configured, attested automatic) DNS sinkholing, and
the web UI. Each service keeps its state in its own SQLite store on a Podman
volume; there is no ClickHouse, no packet sensor and no ML.

**Requirements.** Debian 13 or Raspberry Pi OS (trixie, 64-bit) or another
systemd distribution with Podman ≥ 5 using netavark, `aardvark-dns`,
`htpasswd` (apache2-utils) and `curl`; the installer adds the missing ones
with apt. The machine needs a fixed address on the LAN (a DHCP reservation
is enough) because clients will use it as their DNS server.

**Rootful, not rootless.** The units are system Quadlets in
`/etc/containers/systemd/` run by root's Podman, because `netagent` must hold
`NET_RAW` in the host's network namespace. Inside, every container runs as a
non-root user with all capabilities dropped, a read-only root filesystem
and `no-new-privileges`; only `netagent` keeps `NET_RAW` (ADR-0004, point 6).

### What runs

| Container | Networks | Capabilities | Published | Memory limit |
|---|---|---|---|---|
| `netsoldier-adguard` (AdGuard Home v0.107.55) | edge + internal `10.231.47.10` | none | `HOST_IP:53/udp+tcp` | 160 MiB |
| `netsoldier-threat-intel-sync` | edge + internal `.11` | none | — | 128 MiB |
| `netsoldier-detection-engine` | internal `.12` | none | — | 96 MiB |
| `netsoldier-device-inventory` | internal `.13` | none | — | 96 MiB |
| `netsoldier-killswitch` | internal `.14` | none | — | 64 MiB |
| `netsoldier-web-ui` | edge + internal `.15` | none | `HOST_IP:UI_PORT/tcp` (3000) | 128 MiB |
| `netsoldier-netagent` | host | `NET_RAW` | — (it listens on nothing) | 64 MiB |

- `netsoldier-internal` (`10.231.47.0/24`) is an *internal* Podman network:
  no route out, never forwarded to or from the LAN, nothing on it published.
  Its bridge address is how `netagent` on the host network reaches
  device-inventory and the killswitch.
- `netsoldier-edge` is an ordinary NATed bridge for the three containers that
  need egress (upstream DNS, feed downloads) or a published port.
- Only DNS and the web UI face the LAN, and only on `HOST_IP`; the AdGuard
  admin API and every service API stay on the internal network.
- The AdGuard image is upstream's, pinned by digest, rebuilt locally without
  its `cap_net_bind_service` file capability (`podman/adguard/Containerfile`);
  it binds 53 because the unit lowers `ip_unprivileged_port_start` inside the
  container's own network namespace.
- Every unit is `Restart=always`, ordered after `network-online.target`, and
  `PartOf=netsoldier.target`: `systemctl restart netsoldier.target` restarts
  the profile.

### Configuration: one file

`/etc/netsoldier/netsoldier.conf` (template: `podman/netsoldier.conf.example`).
Five values are required: `LAN_INTERFACE`, `HOST_IP`, `GATEWAY_IP`,
`GATEWAY_MAC`, `LAN_NETWORKS`. `netsoldier-lite init` writes a draft from the
default route and the neighbour table — check the gateway MAC against the
router's label, the neighbour table can be forged. Optional: `UI_URL` /
`UI_PORT`, `PROTECTED_MACS` / `PROTECTED_IPS`, `BLOCK_TTL`, upstream DNS,
`ABUSECH_AUTH_KEY`, `COMMERCIAL_MODE`, `ARP_PROBE`, the auto-block
thresholds, and where the images come from.

**An empty protected set means no automatic blocking**: every action waits
for a human in the web UI. The router (`GATEWAY_IP`/`GATEWAY_MAC`) and the DNS
server are protected either way but do not switch automatic blocking on.
Nothing ships a placeholder allowlist.

Site-local known-bad domains go in `/etc/netsoldier/local-indicators.txt`
(confidence 80, so with the default policy they always wait for approval).

From the file the installer renders the per-service environment files
(`/etc/netsoldier/env/`), the site drop-ins next to the units
(`<unit>.container.d/50-site.conf`: published addresses, image references)
and, on the first install, AdGuard's configuration. The committed units name
no address, interface or MAC of anyone's network.

### Secrets

Generated at install time from `/dev/urandom`, one per role, in
`/etc/netsoldier/secrets/` (directory 0700, files 0600, root) and handed to
the containers as Podman secrets (`Secret=…,type=env`), so they do not appear
in `podman inspect`. Existing secrets are kept on re-install.

| Secret | Used by |
|---|---|
| `killswitch-operator-token` | `KILLSWITCH_API_KEY`: web UI, operators |
| `killswitch-ingest-token` | `KILLSWITCH_INGEST_TOKEN` = detection-engine `WEBHOOK_TOKEN` (valid on `POST /evaluate` only) |
| `webhook-secret` | signs detection-engine → killswitch |
| `device-api-key` | `DEVICE_API_KEY`: device-inventory, detection-engine, web UI |
| `detection-api-key` | `DETECTION_API_KEY`: detection-engine, web UI |
| `netagent-token` | `NETAGENT_TOKEN`: netagent → device-inventory |
| `netagent-killswitch-token` | `NETAGENT_KILLSWITCH_TOKEN`: generated, not wired (ARP isolation is not offered, see below) |
| `adguard-password` | AdGuard's only user, `netsoldier` (bcrypt hash rendered into its config) |
| `web-session-secret`, `web-ui-password` | the web UI's `SESSION_SECRET` and household password |

`netsoldier-lite password` prints the UI password; `netsoldier-lite secret
NAME` prints any other. Rotating one: delete its file, re-run install (the
AdGuard hash is updated in place).

### Install, inspect, remove

```bash
# Plain script, from a checkout (copies itself to /usr/local/sbin):
sudo deploy/podman/netsoldier-lite init          # or write netsoldier.conf yourself
sudoedit /etc/netsoldier/netsoldier.conf
sudo deploy/podman/netsoldier-lite install       # idempotent; restarts the profile
sudo netsoldier-lite status
sudo netsoldier-lite uninstall                   # units, containers, networks, volumes,
                                                 # secrets, images, /etc/netsoldier
```

Ansible: the role `infra/ansible/roles/podman_edge` copies these same files
to the host, writes `netsoldier.conf` from `podman_edge_settings` and runs
the same script (`podman_edge_state: absent` uninstalls). Example:
`infra/lab/lite/playbook.yml` with `infra/lab/lite/ansible-vars.yml`.

Then point the router's DHCP "DNS server" setting at `HOST_IP`.

Images are `<IMAGE_PREFIX>/<service>:<IMAGE_TAG>` (default
`ghcr.io/migel9090/*:main`). The lab builds them on the host instead
(`infra/lab/lite/host/build-images.sh`).

### Proven in the lab

`infra/lab/lite/` installs the profile on a clean Debian 13 LXC container,
simulates a home LAN inside it (bridge without uplink, a router namespace with
DHCP, a victim namespace) and runs the smoke scenario: DHCP lease → device in
the inventory, known-bad lookup → alert with the MAC → pending action,
approval → AdGuard rule → sinkholed lookup, TTL → resolves again, audit
trail, gateway never enforced, web UI sign-in, a block surviving the
restart of every service and of the whole profile, and a false-positive
verdict surviving a restart. See
`infra/lab/lite/Taskfile.yml`: `LITE_HOST=<lab host> task lite:e2e`, or
`task lite:e2e:ansible` for the same through the role (`LITE_BUILD=local`
builds the images with Docker on the workstation).

### Memory

Measured on the amd64 lab host (`infra/lab/lite/host/measure.sh`, cgroup v2;
RSS = resident memory of the container's processes). Peaks are per
container over a whole scenario run, including every restart.

| Container | Limit | RSS idle | RSS peak |
|---|---|---|---|
| adguard | 160 MiB | 37 MiB | 53–78 MiB (filter list reload after a restart) |
| threat-intel-sync | 128 MiB | 17 MiB | 19 MiB |
| detection-engine | 96 MiB | 15 MiB | 18 MiB |
| device-inventory | 96 MiB | 10 MiB | 13 MiB |
| killswitch | 64 MiB | 10 MiB | 13 MiB |
| netagent | 64 MiB | 9 MiB | 10 MiB |
| web-ui | 128 MiB | 52 MiB | 55 MiB |
| **total** | 736 MiB | 149 MiB (anon 69 MiB) | 178–205 MiB (sum of peaks) |

Podman's own processes add 13–18 MiB (conmon ×7, aardvark-dns); the whole
lab container (Debian userspace + profile) uses 213 MiB besides page cache.
The limits are ceilings, not reservations. A Raspberry Pi 3B+ (1 GiB) has
room for this on paper; it has not been measured there yet, and arm64
images are not built yet. Runtime images take ≈ 330 MiB of disk.

### Limits and known gaps

- **ARP isolation is not offered.** Podman's bridge networking needs
  `net.ipv4.ip_forward=1`, and netagent refuses to isolate while forwarding
  is on (contract v2, 8.2). The killswitch gets no agent token, so
  `arp_isolate` is not in `available_action_types`.
- No notification channel: pending actions appear in the web UI only.
- No ClickHouse: analyst verdicts and alerts live in detection-engine's
  SQLite store and the audit log in the killswitch's (`GET /audit`); there is
  no long-term history beyond what those stores keep.
- The host's own LAN address is not in the killswitch's protected set (it can
  only see its container addresses); a DNS sinkhole never cuts a device off,
  so this matters only once device-level drivers exist here.
- IPv4 only: DNS and the UI are published on `HOST_IP`; IPv6 clients that
  learn another resolver bypass AdGuard.
- Published ports and container egress are forwarded traffic (netavark,
  nftables). A host firewall that drops forwarding by default (ufw ships
  `DEFAULT_FORWARD_POLICY="DROP"`, and the `hardening` role enables ufw)
  needs route rules for 53 and the UI port; not tested together yet.
- On an unprivileged LXC host Podman keeps network namespaces under its
  runtime directory; the units give it `/run/netsoldier/podman` so root
  logging in and out cannot unmount them.
