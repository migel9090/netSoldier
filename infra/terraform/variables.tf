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
