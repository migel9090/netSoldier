locals {
  # Debian 13 "trixie" genericcloud, amd64, one dated build. The SHA-512 is
  # copied from SHA512SUMS in the same directory:
  #   https://cloud.debian.org/images/cloud/trixie/20261111-2659/SHA512SUMS
  # To move to a newer build, change both values together.
  debian_build  = "20261111-2659"
  debian_sha512 = "3247873136ba09b060fab45e9c115239f81c1d401fce00b8fa9b872013f7135d6a40b12462ab5ac03b9fa4ed5955dd0e8d1c900109a939ad7a0a4dafe7dea47b"

  debian_file = "debian-13-genericcloud-amd64-${local.debian_build}.qcow2"
  debian_url  = "https://cloud.debian.org/images/cloud/trixie/${local.debian_build}/${local.debian_file}"
}

# The node fetches the image itself (download-url) and Proxmox checks the
# checksum before the file is stored. The image is kept on `local` as content
# type `import` and outlives the VM: the lab token may add files there but not
# delete them (Datastore.Allocate is not granted), so `task lab:down` removes
# only the VM.
resource "proxmox_download_file" "debian_13" {
  node_name    = var.proxmox_node
  datastore_id = var.image_datastore_id
  content_type = "import"

  url                = local.debian_url
  file_name          = local.debian_file
  checksum           = local.debian_sha512
  checksum_algorithm = "sha512"

  # Never replace or delete behind our back: either would need a privilege
  # the token does not have.
  overwrite           = false
  overwrite_unmanaged = false
  upload_timeout      = 1800
}
