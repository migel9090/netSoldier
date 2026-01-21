variable "proxmox_endpoint" {
  description = "Proxmox VE API URL (e.g. https://pve.local:8006)"
  type        = string
}

variable "proxmox_api_token" {
  description = "API token in USER@REALM!TOKENID=UUID format"
  type        = string
  sensitive   = true
}

variable "proxmox_insecure" {
  description = "Skip TLS verification for self-signed certificates"
  type        = bool
  default     = true
}

variable "proxmox_node" {
  description = "Target Proxmox node name"
  type        = string
}

# ── k3s VM ──────────────────────────────────────────────────────

variable "k3s_cpu_cores" {
  description = "CPU cores for k3s VM"
  type        = number
  default     = 4
}

variable "k3s_memory_mb" {
  description = "Memory in MB for k3s VM"
  type        = number
  default     = 6144
}

variable "k3s_disk_gb" {
  description = "Root disk size in GB"
  type        = number
  default     = 48
}

variable "storage_pool" {
  description = "Proxmox storage pool for VM disks"
  type        = string
  default     = "local-lvm"
}

# ── Network ─────────────────────────────────────────────────────

variable "network_bridge" {
  description = "Proxmox bridge interface"
  type        = string
  default     = "vmbr0"
}

variable "k3s_ip" {
  description = "Static IP in CIDR notation (e.g. 192.168.1.100/24)"
  type        = string
}

variable "gateway" {
  description = "Default gateway"
  type        = string
}

variable "dns_servers" {
  description = "DNS servers for the VM"
  type        = list(string)
  default     = ["1.1.1.1", "1.0.0.1"]
}

# ── Cloud-init ──────────────────────────────────────────────────

variable "cloud_image_url" {
  description = "Ubuntu cloud image URL"
  type        = string
  default     = "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
}

variable "vm_user" {
  description = "Default user created by cloud-init"
  type        = string
  default     = "netsoldier"
}

variable "ssh_public_key" {
  description = "SSH public key for VM access"
  type        = string
}
