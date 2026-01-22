output "k3s_ip" {
  description = "k3s VM IP address"
  value       = split("/", var.k3s_ip)[0]
}

output "k3s_vm_id" {
  description = "Proxmox VM ID"
  value       = proxmox_virtual_environment_vm.k3s.vm_id
}

output "ssh_command" {
  description = "SSH into the k3s VM"
  value       = "ssh ${var.vm_user}@${split("/", var.k3s_ip)[0]}"
}

output "kubeconfig_command" {
  description = "Retrieve k3s kubeconfig (run after k3s installation)"
  value       = "scp ${var.vm_user}@${split("/", var.k3s_ip)[0]}:/etc/rancher/k3s/k3s.yaml ./kubeconfig"
}
