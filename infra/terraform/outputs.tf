locals {
  # One entry per VM that exists in state; empty after `task lab:down`.
  lab_hosts = {
    for vm in proxmox_virtual_environment_vm.soc : vm.name => {
      ansible_host = split("/", vm.initialization[0].ip_config[0].ipv4[0].address)[0]
      ansible_user = vm.initialization[0].user_account[0].username
      lab_vm_id    = vm.vm_id
    }
  }

  # cidrsubnet(x, 0, 0) masks the host part: 192.168.1.61/24 -> 192.168.1.0/24.
  vm_subnet = cidrsubnet(var.ipv4_address, 0, 0)
}

output "vm_id" {
  description = "Proxmox VM id (null when the VM is down)"
  value       = one(proxmox_virtual_environment_vm.soc[*].vm_id)
}

output "vm_address" {
  description = "IPv4 address of the VM (null when the VM is down)"
  value       = one([for h in local.lab_hosts : h.ansible_host])
}

output "image_id" {
  description = "Volume id of the cloud image kept on the image storage"
  value       = proxmox_download_file.debian_13.id
}

# Written to <state dir>/inventory.yml by `task lab:inventory`; Ansible reads
# nothing about the lab host that was typed by hand.
output "ansible_inventory" {
  description = "Ansible inventory (YAML) for the lab VM"
  value = yamlencode({
    all = {
      children = {
        proxmox_soc = {
          hosts = local.lab_hosts
          vars = {
            hardening_ssh_allowed_cidrs = length(var.ssh_allowed_cidrs) > 0 ? var.ssh_allowed_cidrs : [local.vm_subnet]
            k3s_api_allowed_cidrs       = var.api_allowed_cidrs
          }
        }
      }
    }
  })
}
