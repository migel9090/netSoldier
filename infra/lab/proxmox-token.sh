#!/usr/bin/env bash
# One-time bootstrap: a pool-scoped Proxmox API token for the netSoldier lab.
#
# Terraform creates the lab VM through the Proxmox API, and it should not do
# that as root. This script creates, on the Proxmox host:
#
#   pool   netsoldier-lab            the only place the token may create guests
#   user   terraform@pve             no password, usable through the token only
#   roles  NetsoldierLab{VM,Images,Disks,Net,Node}
#   token  terraform@pve!netsoldier-lab   expires after EXPIRE_DAYS
#
# and grants exactly:
#
#   /pool/netsoldier-lab       create/configure/start/stop guests in the pool
#   /storage/$IMAGE_STORAGE    download and keep the cloud image
#   /storage/$DISK_STORAGE     allocate VM disks
#   /sdn/zones/localnetwork    attach a NIC to an existing bridge
#   /nodes/$NODE               read node status; let the node fetch a URL
#
# The token cannot see or touch guests outside the pool, cannot change host
# networking, storage definitions, users or permissions.
#
# The secret is written to $OUT (mode 0600) and never printed. Proxmox shows
# it only once, so if the token already exists this script refuses to run:
# use --revoke first.
#
# Usage:
#   infra/lab/proxmox-token.sh            create everything, write the tfvars
#   infra/lab/proxmox-token.sh --revoke   remove the token, user, roles, pool
#
# Run it from a workstation that can `ssh $PVE_SSH` as root. It makes no other
# change to the host.
set -euo pipefail

PVE_SSH="${PVE_SSH:-pve}"
PVE_ENDPOINT="${PVE_ENDPOINT:-https://192.168.1.40:8006/}"
NODE="${NODE:-pve}"
POOL="${POOL:-netsoldier-lab}"
PVE_USER="${PVE_USER:-terraform@pve}"
TOKEN_NAME="${TOKEN_NAME:-netsoldier-lab}"
IMAGE_STORAGE="${IMAGE_STORAGE:-local}"
DISK_STORAGE="${DISK_STORAGE:-scratch2}"
EXPIRE_DAYS="${EXPIRE_DAYS:-90}"
OUT="${OUT:-$HOME/.config/netsoldier-lab/lab.auto.tfvars}"

remote() { ssh -o BatchMode=yes -o ConnectTimeout=10 "$PVE_SSH" "$@"; }

if [[ "${1:-}" == "--revoke" ]]; then
  remote "
    pveum user token remove '$PVE_USER' '$TOKEN_NAME' 2>/dev/null || true
    pveum user delete '$PVE_USER' 2>/dev/null || true
    for r in VM Images Disks Net Node; do pveum role delete NetsoldierLab\$r 2>/dev/null || true; done
    pveum pool delete '$POOL' 2>/dev/null || echo 'pool $POOL not removed (it still has members, or does not exist)'
  "
  rm -f "$OUT"
  echo "revoked: token, user and roles removed; $OUT deleted"
  exit 0
fi

if remote "pveum user token list '$PVE_USER' --output-format json 2>/dev/null" | grep -q "\"$TOKEN_NAME\""; then
  echo "token $PVE_USER!$TOKEN_NAME already exists; its secret cannot be read again." >&2
  echo "run '$0 --revoke' first if you want a new one." >&2
  exit 1
fi

# The token cannot change storage definitions, so say now if a storage does
# not accept what Terraform will put there (nothing is changed here).
storage_allows() { # <content> <storage>
  remote "pvesm status --content $1" 2>/dev/null | awk 'NR > 1 { print $1 }' | grep -qx "$2"
}
if ! storage_allows import "$IMAGE_STORAGE"; then
  echo "warning: storage '$IMAGE_STORAGE' does not accept content type 'import'; Terraform cannot keep the cloud image there." >&2
  echo "         enable it under Datacenter > Storage > $IMAGE_STORAGE > Content." >&2
fi
if ! storage_allows images "$DISK_STORAGE"; then
  echo "warning: storage '$DISK_STORAGE' does not accept content type 'images'; Terraform cannot create VM disks there." >&2
fi

expire=$(date -d "+${EXPIRE_DAYS} days" +%s)
umask 077
mkdir -p "$(dirname "$OUT")"
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

# role(): create the role, or reset an existing one to exactly these
# privileges (a role left over from an earlier run must not keep old ones).
remote "
  set -e
  role() { pveum role add \"\$1\" --privs \"\$2\" 2>/dev/null || pveum role modify \"\$1\" --privs \"\$2\"; }
  pveum pool add '$POOL' --comment 'netSoldier lab guests managed by Terraform' 2>/dev/null || true
  pveum user add '$PVE_USER' --comment 'netSoldier lab IaC, token only' 2>/dev/null || true
  role NetsoldierLabVM 'VM.Allocate VM.Audit VM.Clone VM.Config.CDROM VM.Config.CPU VM.Config.Cloudinit VM.Config.Disk VM.Config.HWType VM.Config.Memory VM.Config.Network VM.Config.Options VM.Console VM.PowerMgmt VM.Snapshot VM.Snapshot.Rollback Pool.Audit'
  role NetsoldierLabImages 'Datastore.AllocateTemplate Datastore.Audit'
  role NetsoldierLabDisks 'Datastore.AllocateSpace Datastore.Audit'
  role NetsoldierLabNet 'SDN.Use SDN.Audit'
  role NetsoldierLabNode 'Sys.Audit Sys.AccessNetwork'
  pveum acl modify '/pool/$POOL' --users '$PVE_USER' --roles NetsoldierLabVM
  pveum acl modify '/storage/$IMAGE_STORAGE' --users '$PVE_USER' --roles NetsoldierLabImages
  pveum acl modify '/storage/$DISK_STORAGE' --users '$PVE_USER' --roles NetsoldierLabDisks
  pveum acl modify /sdn/zones/localnetwork --users '$PVE_USER' --roles NetsoldierLabNet
  pveum acl modify '/nodes/$NODE' --users '$PVE_USER' --roles NetsoldierLabNode
  pveum user token add '$PVE_USER' '$TOKEN_NAME' --privsep 0 --expire $expire --comment 'netSoldier lab IaC' --output-format json
" >"$tmp"

python3 - "$tmp" "$OUT" "$PVE_ENDPOINT" <<'PY'
import json, os, re, sys

raw_path, out_path, endpoint = sys.argv[1:4]
match = re.search(r"\{.*\}", open(raw_path).read(), re.S)
if not match:
    sys.exit("could not read the token from the Proxmox reply")
token = json.loads(match.group(0))
with open(out_path, "w") as fh:
    fh.write("# netSoldier lab: Proxmox API access for Terraform. Never commit this file.\n")
    fh.write(f'proxmox_endpoint  = "{endpoint}"\n')
    fh.write(f'proxmox_api_token = "{token["full-tokenid"]}={token["value"]}"\n')
os.chmod(out_path, 0o600)
print(f"token {token['full-tokenid']} created; secret written to {out_path} (mode 0600)")
PY

echo "expires: $(date -d "@$expire" +%F)   revoke with: $0 --revoke"
