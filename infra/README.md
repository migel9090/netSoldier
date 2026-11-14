# infra/ — Infrastructure as code

What is here today:

| Path | What it does |
|---|---|
| `terraform/` | Proxmox VE through the `bpg/proxmox` provider (0.121.0, locked in `.terraform.lock.hcl`): downloads one pinned Debian 13 cloud image and creates **one VM**, `netsoldier-soc`, in the pool `netsoldier-lab`. It does not create bridges, storage, pools, users or a second (SPAN) NIC. State is local, outside the repository. |
| `ansible/` | `site.yml` in order: OS base (`bootstrap`), hardening (`hardening`), k3s (`k3s_server`), gVisor (`gvisor`). `kubeconfig.yml` copies the admin kubeconfig to the workstation. The Raspberry Pi play (`pi_edge`, `podman_edge` role) is kept but not exercised; `playbooks/argocd.yml` and `playbooks/kyverno.yml` belong to later steps. |
| `lab/` | The `task lab:*` targets (`lab/Taskfile.yml`, included from the root `Taskfile.yml`) and their scripts. `proxmox-token.sh` is the one-time admin bootstrap of the API token. |

CI (`.github/workflows/iac-scan.yml`) runs `terraform fmt -check`, `init -backend=false`
and `validate` only. There is no `plan` in CI and nothing in CI talks to Proxmox.

## The lab: one k3s node with gVisor

A single VM on the owner's Proxmox VE 9 host, sized to the project's design budget
(4 vCPU, 8 GiB RAM, 60 GiB disk), running k3s with gVisor available as the
`gvisor` RuntimeClass (ADR-0004). It sits on the home LAN (`vmbr0`) at a static
address, `192.168.1.61/24` by default.

### Before the first run

On the workstation: Docker (Terraform runs from the official image, it is not
installed), Python ≥ 3.12, [Task](https://taskfile.dev), `jq`, OpenSSH, `curl`.

Once, by the Proxmox admin (it uses root SSH to the host, Terraform never does):

```sh
infra/lab/proxmox-token.sh          # pool, role set, token terraform@pve!netsoldier-lab
```

It writes `~/.config/netsoldier-lab/lab.auto.tfvars` (mode 0600). Put the node's CA
certificate next to it as `~/.config/netsoldier-lab/pve-root-ca.pem` (it is
`/etc/pve/pve-root-ca.pem` on the host). The token can only:

| Path | Privileges | Used for |
|---|---|---|
| `/pool/netsoldier-lab` | `VM.*`, `Pool.Audit` | create and manage guests in the pool |
| `/storage/local` | `Datastore.AllocateTemplate`, `Datastore.Audit` | download and keep the cloud image (content type `import`) |
| `/storage/scratch2` | `Datastore.AllocateSpace`, `Datastore.Audit` | VM disk and cloud-init drive |
| `/sdn/zones/localnetwork` | `SDN.Use`, `SDN.Audit` | attach the NIC to `vmbr0` |
| `/nodes/pve` | `Sys.Audit`, `Sys.AccessNetwork` | node status; let the node fetch the image URL |

It cannot delete files on `local` (`Datastore.Allocate` is not granted), read
guest-agent data, use snippets, or touch guests outside the pool.

### Use

```sh
task lab:plan        # what Terraform would change
task lab:up          # VM + k3s + gVisor + kubeconfig; safe to re-run
task lab:smoke       # proves the node is Ready and gVisor really sandboxes
task lab:ssh -- uptime
task lab:down        # destroys the VM; the cloud image stays
```

`lab:up` runs, in order: `terraform apply` → `lab:inventory` (writes the Ansible
inventory from Terraform's `ansible_inventory` output) → `lab:trust-host` (first
contact, below) → `lab:provision` (`ansible-playbook site.yml`) → `lab:kubeconfig`.
Each step is also a target of its own. `task lab:validate` runs the static checks
(fmt, validate, syntax-check, ansible-lint) without credentials or a VM.

| Where | What |
|---|---|
| `~/.config/netsoldier-lab/lab.auto.tfvars` | endpoint and token (owner) |
| `~/.config/netsoldier-lab/pve-root-ca.pem` | Proxmox CA (owner) |
| `~/.config/netsoldier-lab/kubeconfig` | admin kubeconfig, mode 0600 (`lab:kubeconfig`) |
| `~/.local/state/netsoldier-lab/terraform.tfstate` | Terraform state (passed at `init`; survives the checkout) |
| `~/.local/state/netsoldier-lab/inventory.yml` | generated inventory |
| `~/.local/state/netsoldier-lab/known_hosts` | the lab VM's SSH host key |
| `~/.cache/netsoldier-lab/terraform-plugins` | provider cache |
| `.venv/` (repository root, ignored) | Ansible, ansible-lint, collections, kubectl (`lab:tools`) |

`LAB_CONFIG`, `LAB_STATE`, `LAB_KUBECONFIG`, `LAB_SSH_KEY` override the locations;
the SSH key defaults to `~/.ssh/claude_homelab_ed25519`. Terraform variables
(address, VM id, sizes, allowed sources) are listed in `terraform/variables.tf`
and `terraform/terraform.tfvars.example`; set them in `lab.auto.tfvars`.

### Pinned versions

| What | Version | Checksum, and where it comes from |
|---|---|---|
| Terraform image | `hashicorp/terraform:1.17.2` | index digest `sha256:6e9c1e64…`, in `lab/tf.sh` |
| Provider | `bpg/proxmox` 0.121.0 | `terraform/.terraform.lock.hcl` (linux/darwin, amd64/arm64) |
| Cloud image | Debian 13 genericcloud amd64, build `20261111-2659` | SHA-512 from that build's `SHA512SUMS` on cloud.debian.org, in `terraform/image.tf`; Proxmox checks it on download |
| k3s | `v1.37.2+k3s1` (stable channel; containerd 2.3.7) | SHA-256 from the release's `sha256sum-amd64.txt`, in `roles/k3s_server/defaults` |
| gVisor | `20261102.0` | SHA-512 of `gvisor.tar.zstd`, identical in the release bucket (`.sha512`) and the GitHub release `SHA512SUMS`, in `roles/gvisor/defaults` |
| Ansible | ansible-core 2.21.6, ansible-lint 26.11.0 | `ansible/requirements.txt`, every package hash-pinned (`pip --require-hashes`) |
| Collections | community.general 13.5.1 (+ its dependency) | `ansible/requirements.yml`; Galaxy checksums |
| kubectl | v1.37.2 | SHA-256 from dl.k8s.io, in `lab/lab.sh` |
| Smoke image | busybox 1.37.0 | by digest, in `lab/smoke.yaml` |

To move a pin, change the version and its checksum together, from the upstream
file named above.

### How it is put together

**TLS.** The provider verifies the Proxmox certificate (`proxmox_insecure`
defaults to `false`). The node's own CA is mounted into the Terraform container and
named in `SSL_CERT_DIR`, which Go reads in addition to the image's CA bundle.

**Image and VM.** The node downloads the image itself (`download-url`) and checks
its SHA-512. The VM imports it (`import_from`) onto `scratch2`, boots only from
that disk (no PXE on the LAN), and gets its account, key and static address from
Proxmox's native cloud-init: no snippets, no provider SSH. `on_boot = false`.
`lab:down` sets `vm_enabled = false` and applies, which removes the VM only: the
image stays on `local` because the token may not delete it. To remove the image or
move to a new build, an admin deletes the old file (Proxmox UI, or grant
`Datastore.Allocate` on `local`).

**First contact.** SSH host-key checking is on everywhere (`ansible.cfg`,
`lab/lib.sh`). A new VM's key cannot be known in advance (native cloud-init
cannot inject one), so `lab:trust-host` accepts it once, on first use, into the
lab's own `known_hosts`, and prints the fingerprint; compare it with the
`BEGIN SSH HOST KEY FINGERPRINTS` block on the VM's serial console in the Proxmox
UI if you want to check out of band. A host that already has an entry is never
re-trusted: a different key fails the run. `lab:down` forgets the key of the VM
it destroys.

**Who can become root.** Ansible connects as the account cloud-init creates
(`netsoldier`); the Debian cloud image gives that account passwordless sudo, and
Ansible needs it. It is the only account sshd accepts, by key only, from the
allowed sources. The hardening role itself grants no sudo rights and removes the
`NOPASSWD:ALL` file earlier versions of it wrote.

**Firewall (ufw).** Incoming is denied except: SSH from the VM's subnet (or
`ssh_allowed_cidrs`); the Kubernetes API (6443) from the machine that runs
Ansible, as the VM sees it (or `api_allowed_cidrs`); 6443 and the kubelet (10250)
from the pod network, which metrics-server and in-cluster clients need. Rules
for sources that are no longer listed are removed on the next run. Nothing
listens for the LAN beyond SSH and the API.

**k3s.** One binary from the GitHub release, checked against the pinned SHA-256
(no `curl | sh`), with a systemd unit and `/etc/rancher/k3s/config.yaml` owned by
Ansible: Traefik and ServiceLB disabled, Secrets encrypted at rest, kubeconfig
written `0600`. The copy on the workstation is `0600` too, with the cluster,
user and context named `netsoldier-lab`.

**gVisor.** The `gvisor` role unpacks the pinned release into
`/opt/gvisor/<version>/` (runsc, `containerd-shim-runsc-v1` and the `gvisor-bin/`
helpers runsc needs beside it) and registers the `runsc` handler with k3s's
embedded containerd the way the k3s documentation describes for containerd 2.x:
`/var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.tmpl`, which starts with
`{{ template "base" . }}` (k3s's own configuration) and adds only the runsc
runtime table. k3s renders it into `config.toml` on every start, so the runtime
survives k3s restarts, upgrades and reboots. The `RuntimeClass` (`gvisor` →
`runsc`) is a file in `/var/lib/rancher/k3s/server/manifests/`, which k3s applies
on start. runsc runs with `--oci-seccomp`, so a pod's `RuntimeDefault` seccomp
profile applies inside the sandbox too (runsc ignores it otherwise). The default
runtime stays `runc`: pods opt in with `runtimeClassName: gvisor`.

**Smoke check.** `lab:smoke` uses the fetched kubeconfig (so it also tests the
API through the firewall) and SSH: the node is Ready; a busybox pod with
`runtimeClassName: gvisor` sees gVisor's kernel (`uname -r` and `/proc/version`
report `4.19.0-gvisor`) while the same pod without it sees the node's kernel
(`dmesg` is refused in both: the pods are `restricted` and have no
`CAP_SYSLOG`); `detection-engine`
(`ghcr.io/migel9090/detection-engine:main`) becomes Ready in gVisor and answers
`/healthz` through its Service; containerd reports the `runsc` handler for its
sandbox. All smoke pods meet the `restricted` Pod Security Standard. The namespace
is deleted afterwards (`KEEP=1` keeps it).

### Not done here

- A second NIC for SPAN/mirror traffic and any simulated-LAN networking (later step).
- The netSoldier stack itself, ArgoCD and Kyverno on the lab cluster;
  `playbooks/argocd.yml` and `playbooks/kyverno.yml` still expect a kubeconfig at
  `infra/ansible/kubeconfig`.
- The Podman profile: `podman_edge` still does not install the Quadlet units.
- Remote state (the S3 backend is not configured) and a CI job that exercises the roles.

Never commit `*.tfstate`, `*.tfvars` (except `*.tfvars.example`), private keys or
kubeconfigs; the root `.gitignore` covers them, and all of them live outside the
repository anyway.
