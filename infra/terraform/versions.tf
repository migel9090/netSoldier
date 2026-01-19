terraform {
  required_version = ">= 1.7"

  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = ">= 0.66.0"
    }
  }

  backend "local" {
    path = "terraform.tfstate"
  }

  # To migrate state to MinIO, uncomment the block below and run:
  #   terraform init -migrate-state
  #
  # backend "s3" {
  #   bucket = "terraform-state"
  #   key    = "netsoldier/terraform.tfstate"
  #   region = "us-east-1"
  #
  #   endpoints = {
  #     s3 = "http://minio.local:9000"
  #   }
  #
  #   skip_credentials_validation = true
  #   skip_metadata_api_check     = true
  #   skip_requesting_account_id  = true
  #   use_path_style              = true
  # }
}
