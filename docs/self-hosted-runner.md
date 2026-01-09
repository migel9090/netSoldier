# Self-hosted ARM64 runner

netSoldier images target **linux/amd64** (Proxmox server) and **linux/arm64** (Pi 3B+).
Multi-arch builds run on GitHub-hosted runners via Go cross-compilation (no QEMU).
A self-hosted ARM64 runner adds **native arm64 test execution** — catching
architecture-specific bugs that cross-compiled binaries miss.

## Options

| Option | Hardware | Pros | Cons |
|---|---|---|---|
| **Pi 3B+** | Physical device | Real target, native speed | 1 GB RAM, USB2 NIC, single board |
| **QEMU VM on Proxmox** | Emulated aarch64 | More RAM, easy snapshots | Emulation overhead (~3–5x slower) |

Both run the same setup script below.

## Prerequisites

- Debian/Ubuntu-based ARM64 OS (Raspberry Pi OS 64-bit or Ubuntu Server 24.04 arm64)
- `curl`, `tar`, `jq`, `git`
- Docker (optional, for container-based isolation)
- Non-root user with `sudo` access

## Registration

### 1. Get a registration token

On a machine with `gh` CLI authenticated as a repo admin:

```bash
TOKEN=$(gh api repos/migel9090/netSoldier/actions/runners/registration-token \
  --method POST --jq '.token')
echo "$TOKEN"
```

The token expires in 1 hour.

### 2. Run the setup script

Copy `scripts/setup-arm64-runner.sh` to the target machine and run:

```bash
chmod +x setup-arm64-runner.sh
./setup-arm64-runner.sh "$TOKEN"
```

The script downloads the GitHub Actions runner, configures it with the repo,
and installs a systemd service (`actions.runner.*.service`).

### 3. Verify

```bash
# Check the service is running
systemctl --user status actions.runner.*

# Verify on GitHub
gh api repos/migel9090/netSoldier/actions/runners --jq '.runners[] | "\(.name) \(.status) \(.labels | map(.name))"'
```

The runner should appear in **Settings → Actions → Runners** with labels
`self-hosted`, `Linux`, `ARM64`.

## Usage in workflows

Jobs targeting the self-hosted runner:

```yaml
jobs:
  test-arm64:
    runs-on: [self-hosted, Linux, ARM64]
    steps:
      - uses: actions/checkout@...
      - run: go test -race -count=1 ./...
```

## Security considerations

Self-hosted runners on **public repos** can execute code from any PR fork.
Mitigations:

1. **Require approval for fork PRs** — Settings → Actions → Fork pull request
   workflows → "Require approval for all outside collaborators"
2. **Ephemeral runner** — configure with `--ephemeral` flag so the runner
   picks up one job then re-registers (clean environment per job)
3. **Isolation** — run inside a container or VM; never on a machine with
   sensitive data or network access beyond what the project needs
4. **Dedicated user** — the setup script creates a non-privileged user;
   never run the runner as root
5. **Network segmentation** — the runner needs outbound HTTPS to
   `github.com` and `*.actions.githubusercontent.com`; restrict everything else

## Deregistration

```bash
# Stop the service
systemctl --user stop actions.runner.*

# Get a removal token
REMOVE_TOKEN=$(gh api repos/migel9090/netSoldier/actions/runners/remove-token \
  --method POST --jq '.token')

# Deregister
cd ~/actions-runner && ./config.sh remove --token "$REMOVE_TOKEN"
```

## QEMU VM setup (Proxmox)

Create an aarch64 VM on Proxmox with QEMU:

```bash
# On the Proxmox host (example — adjust VM ID, storage, ISO path)
qm create 200 --name arm64-runner --memory 2048 --cores 2 \
  --bios ovmf --machine virt \
  --cpu host --arch aarch64 \
  --net0 virtio,bridge=vmbr0 \
  --cdrom local:iso/ubuntu-24.04-live-server-arm64.iso \
  --scsi0 local-lvm:16 \
  --ostype l26
```

After OS installation, SSH in and run the same setup script.
