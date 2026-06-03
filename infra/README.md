# infra/ — Infrastructure as Code

| Path | Purpose | Lands at |
|---|---|---|
| `terraform/` | Proxmox via `bpg/proxmox` provider: k3s VM (cloud-init), networks/bridges, storage; state local/MinIO; `terraform validate` + read-only `plan` in CI | steps 26–28 |
| `ansible/` | inventory (Pi + server), OS bootstrap (Debian/Ubuntu server, Raspberry Pi OS 64-bit), CIS-lite hardening (nftables/ufw, fail2ban, SSH, unattended-upgrades, non-root user), k3s install (server) / Podman+Quadlets (Pi) | steps 29–32 |

Never commit: `*.tfstate`, `*.tfvars` (use `terraform.tfvars.example`), private keys,
kubeconfigs — enforced by the root `.gitignore`.
