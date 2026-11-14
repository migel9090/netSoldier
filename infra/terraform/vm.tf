resource "proxmox_virtual_environment_vm" "soc" {
  count = var.vm_enabled ? 1 : 0

  node_name   = var.proxmox_node
  vm_id       = var.vm_id
  name        = var.vm_name
  pool_id     = var.pool_id
  description = "netSoldier lab: k3s node with gVisor. Managed by Terraform (infra/terraform); changes made by hand are overwritten."

  on_boot = false
  started = true
  # A lab VM: stop it hard on destroy instead of waiting for a guest shutdown.
  stop_on_destroy = true

  operating_system {
    type = "l26"
  }

  cpu {
    cores   = var.cpu_cores
    sockets = 1
    # gVisor checks CPU features at start-up; pass the host's through.
    type = "host"
  }

  memory {
    dedicated = var.memory_mib
  }

  # The guest agent is installed by Ansible (role bootstrap), so it is not
  # running at first boot. Do not wait for it to report addresses: the
  # address is static and reading agent data needs VM.GuestAgent.Audit,
  # which the lab token does not have.
  agent {
    enabled = true
    trim    = true
    wait_for_ip {
      disabled = true
    }
  }

  scsi_hardware = "virtio-scsi-single"

  disk {
    interface    = "scsi0"
    datastore_id = var.disk_datastore_id
    import_from  = proxmox_download_file.debian_13.id
    size         = var.disk_size_gib
    iothread     = true
    discard      = "on"
    ssd          = true
  }

  # Boot only from the disk: never fall back to PXE on the home LAN.
  boot_order = ["scsi0"]

  network_device {
    bridge = var.network_bridge
    model  = "virtio"
  }

  # Serial console for the Proxmox xterm.js console (the Debian cloud kernel
  # logs to ttyS0).
  serial_device {}

  # Proxmox's own cloud-init (no snippets): account, key and network only.
  initialization {
    datastore_id = var.disk_datastore_id

    ip_config {
      ipv4 {
        address = var.ipv4_address
        gateway = var.ipv4_gateway
      }
    }

    dns {
      servers = var.dns_servers
    }

    user_account {
      username = var.vm_user
      keys     = [trimspace(var.ssh_public_key)]
    }
  }
}
