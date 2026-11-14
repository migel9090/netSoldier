# Defaults describe the owner's lab (Proxmox node `pve`, home LAN
# 192.168.1.0/24). Only the endpoint and the token have no default; they come
# from ~/.config/netsoldier-lab/lab.auto.tfvars written by
# infra/lab/proxmox-token.sh.

# ── Proxmox API ─────────────────────────────────────────────────

variable "proxmox_endpoint" {
  description = "Proxmox VE API URL, e.g. https://192.168.1.40:8006/"
  type        = string
}

variable "proxmox_api_token" {
  description = "API token as USER@REALM!TOKENID=SECRET"
  type        = string
  sensitive   = true
}

variable "proxmox_insecure" {
  description = "Skip TLS verification. Leave false: trust the node CA instead (infra/lab/tf.sh)."
  type        = bool
  default     = false
}

variable "proxmox_node" {
  description = "Proxmox node that hosts the lab VM"
  type        = string
  default     = "pve"
}

variable "pool_id" {
  description = "Resource pool the VM is created in (the token may only create guests there)"
  type        = string
  default     = "netsoldier-lab"
}

variable "image_datastore_id" {
  description = "Storage that keeps the cloud image (needs content type 'import')"
  type        = string
  default     = "local"
}

variable "disk_datastore_id" {
  description = "Storage for the VM disk and its cloud-init drive"
  type        = string
  default     = "scratch2"
}

variable "network_bridge" {
  description = "Existing bridge the VM NIC attaches to"
  type        = string
  default     = "vmbr0"
}

# ── VM ──────────────────────────────────────────────────────────

variable "vm_enabled" {
  description = "Whether the VM exists. `task lab:down` sets this to false; the cloud image is kept."
  type        = bool
  default     = true
}

variable "vm_id" {
  description = "Proxmox VM id"
  type        = number
  default     = 110
}

variable "vm_name" {
  description = "VM name; also the hostname and the Ansible inventory name"
  type        = string
  default     = "netsoldier-soc"
}

# The project's design budget for a user's k3s node. Do not raise it here:
# the stack has to fit what users are told to provision.
variable "cpu_cores" {
  description = "vCPUs"
  type        = number
  default     = 4

  validation {
    condition     = var.cpu_cores >= 2 && var.cpu_cores <= 4
    error_message = "The design budget is 4 vCPUs."
  }
}

variable "memory_mib" {
  description = "Memory in MiB"
  type        = number
  default     = 8192

  validation {
    condition     = var.memory_mib >= 4096 && var.memory_mib <= 8192
    error_message = "The design budget is 8 GiB."
  }
}

variable "disk_size_gib" {
  description = "Root disk size in GiB"
  type        = number
  default     = 60

  validation {
    condition     = var.disk_size_gib >= 20 && var.disk_size_gib <= 60
    error_message = "The design budget is 60 GiB."
  }
}

# ── Network ─────────────────────────────────────────────────────

variable "ipv4_address" {
  description = "Static address of the VM in CIDR notation"
  type        = string
  default     = "192.168.1.61/24"

  validation {
    condition     = can(cidrhost(var.ipv4_address, 0)) && length(split("/", var.ipv4_address)) == 2
    error_message = "Use CIDR notation, e.g. 192.168.1.61/24."
  }
}

variable "ipv4_gateway" {
  description = "Default gateway"
  type        = string
  default     = "192.168.1.1"
}

variable "dns_servers" {
  description = "DNS servers"
  type        = list(string)
  default     = ["192.168.1.1"]
}

variable "ssh_allowed_cidrs" {
  description = "Sources allowed to reach SSH on the VM. Empty: the VM's own subnet."
  type        = list(string)
  default     = []
}

variable "api_allowed_cidrs" {
  description = "Sources allowed to reach the Kubernetes API (6443). Empty: only the machine that runs Ansible."
  type        = list(string)
  default     = []
}

# ── Access ──────────────────────────────────────────────────────

variable "vm_user" {
  description = "Account cloud-init creates; Ansible connects as it"
  type        = string
  default     = "netsoldier"
}

variable "ssh_public_key" {
  description = "Public key for vm_user (task lab:* passes ~/.ssh/claude_homelab_ed25519.pub)"
  type        = string

  validation {
    condition     = can(regex("^ssh-(ed25519|rsa) ", trimspace(var.ssh_public_key)))
    error_message = "Expected an OpenSSH public key."
  }
}
