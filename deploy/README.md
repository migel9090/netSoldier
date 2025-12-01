# deploy/ — GitOps deployment artifacts

Same images everywhere; the two profiles differ only by overlay/values.

| Path | Purpose | Lands at |
|---|---|---|
| `helm/netsoldier/` | umbrella chart (subchart per service + dependencies) | step 36 |
| `kustomize/base/` + `kustomize/overlays/{pi-edge,proxmox-soc}/` | profile overlays: edge-minimal vs full SOC | steps 36, 84–85 |
| `argocd/` | app-of-apps + ApplicationSet generating both profiles | step 37 |
| `kyverno/` | admission policies: cosign `verifyImages` (signed images only), non-root, read-only rootfs, required limits | step 35 |
| `podman/` | Quadlets/compose for the Pi edge profile (systemd-native, rootless) | step 32 |

Secrets are committed **only** SOPS-encrypted (age); see `security/`.
