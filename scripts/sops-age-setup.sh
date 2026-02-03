#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
SOPS_CONFIG="${REPO_ROOT}/.sops.yaml"
AGE_KEY_DIR="${HOME}/.sops/age"
AGE_KEY_FILE="${AGE_KEY_DIR}/keys.txt"

for cmd in age-keygen sops kubectl; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR: ${cmd} is required but not found"; exit 1; }
done

if [ -f "$AGE_KEY_FILE" ]; then
  echo "Age key already exists at ${AGE_KEY_FILE}"
else
  mkdir -p "$AGE_KEY_DIR"
  age-keygen -o "$AGE_KEY_FILE" 2>&1
  chmod 600 "$AGE_KEY_FILE"
  echo "Generated age key at ${AGE_KEY_FILE}"
fi

AGE_PUBLIC_KEY=$(grep "public key:" "$AGE_KEY_FILE" | awk '{print $NF}')
echo "Public key: ${AGE_PUBLIC_KEY}"

sed -i "s|AGE_PUBLIC_KEY_PLACEHOLDER|${AGE_PUBLIC_KEY}|" "$SOPS_CONFIG"
echo "Updated ${SOPS_CONFIG}"

kubectl create namespace argocd --dry-run=client -o yaml | kubectl apply -f -
kubectl create secret generic sops-age-key \
  --namespace argocd \
  --from-file=keys.txt="$AGE_KEY_FILE" \
  --dry-run=client -o yaml | kubectl apply -f -
echo "Created sops-age-key Secret in argocd namespace"

echo ""
echo "Setup complete."
echo "  Private key : ${AGE_KEY_FILE} (NEVER commit)"
echo "  Public key  : ${AGE_PUBLIC_KEY}"
echo ""
echo "Encrypt:  sops --encrypt --in-place path/to/secret.sops.yaml"
echo "Edit:     sops path/to/secret.sops.yaml"
