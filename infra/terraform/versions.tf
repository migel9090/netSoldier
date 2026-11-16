terraform {
  # Run through `task lab:*`, which uses the hashicorp/terraform image pinned
  # in infra/lab/tf.sh. Keep the two in step.
  required_version = "~> 1.17.2"

  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "0.122.0"
    }
  }

  # Local state, kept outside the repository so it outlives any checkout.
  # The path is given at init time (task lab:init does this):
  #   terraform init -backend-config=path=<state dir>/terraform.tfstate
  backend "local" {}
}
