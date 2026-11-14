provider "proxmox" {
  endpoint  = var.proxmox_endpoint
  api_token = var.proxmox_api_token

  # TLS is verified. The node's own CA is added to the trust store of the
  # Terraform container through SSL_CERT_DIR (see infra/lab/tf.sh), so a
  # self-signed Proxmox certificate needs no `insecure`.
  insecure = var.proxmox_insecure

  # No ssh block on purpose: everything in this module goes through the
  # pool-scoped API token (infra/lab/proxmox-token.sh).
}
