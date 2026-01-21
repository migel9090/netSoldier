resource "proxmox_virtual_environment_download_file" "ubuntu_cloud" {
  content_type = "iso"
  datastore_id = "local"
  node_name    = var.proxmox_node
  url          = var.cloud_image_url
}

resource "proxmox_virtual_environment_vm" "k3s" {
  name      = "k3s-soc"
  node_name = var.proxmox_node
  on_boot   = true
  started   = true
  tags      = ["k3s", "netsoldier"]

  cpu {
    cores = var.k3s_cpu_cores
    type  = "host"
  }

  memory {
    dedicated = var.k3s_memory_mb
  }

  agent {
    enabled = true
  }

  scsi_hardware = "virtio-scsi-single"

  disk {
    datastore_id = var.storage_pool
    file_id      = proxmox_virtual_environment_download_file.ubuntu_cloud.id
    interface    = "scsi0"
    size         = var.k3s_disk_gb
    iothread     = true
    discard      = "on"
    ssd          = true
  }

  network_device {
    bridge = var.network_bridge
    model  = "virtio"
  }

  operating_system {
    type = "l26"
  }

  initialization {
    ip_config {
      ipv4 {
        address = var.k3s_ip
        gateway = var.gateway
      }
    }

    dns {
      servers = var.dns_servers
    }

    user_account {
      username = var.vm_user
      keys     = [var.ssh_public_key]
    }
  }

  # cloud-init runs once at first boot; Proxmox doesn't reflect
  # init config back exactly, causing perpetual plan diffs
  lifecycle {
    ignore_changes = [initialization]
  }
}
