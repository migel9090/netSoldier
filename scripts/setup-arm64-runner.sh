#!/usr/bin/env bash
set -euo pipefail

RUNNER_VERSION="2.334.0"
REPO_URL="https://github.com/migel9090/netSoldier"

if [ $# -lt 1 ]; then
  echo "Usage: $0 <registration-token> [runner-name]"
  echo ""
  echo "Get a token:  gh api repos/migel9090/netSoldier/actions/runners/registration-token --method POST --jq '.token'"
  exit 1
fi

TOKEN="$1"
RUNNER_NAME="${2:-$(hostname)}"
RUNNER_DIR="$HOME/actions-runner"

ARCH=$(uname -m)
case "$ARCH" in
  aarch64|arm64) ARCH_LABEL="arm64" ;;
  x86_64)        ARCH_LABEL="x64"   ;;
  *)             echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

echo "==> Installing GitHub Actions runner ${RUNNER_VERSION} (${ARCH_LABEL})"
mkdir -p "$RUNNER_DIR" && cd "$RUNNER_DIR"

TARBALL="actions-runner-linux-${ARCH_LABEL}-${RUNNER_VERSION}.tar.gz"
curl -fsSL "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/${TARBALL}" -o "$TARBALL"
tar xzf "$TARBALL"
rm "$TARBALL"

echo "==> Configuring runner '${RUNNER_NAME}'"
./config.sh \
  --url "$REPO_URL" \
  --token "$TOKEN" \
  --name "$RUNNER_NAME" \
  --labels "self-hosted,Linux,ARM64" \
  --work "_work" \
  --replace

echo "==> Installing systemd service"
sudo ./svc.sh install
sudo ./svc.sh start

echo "==> Runner '${RUNNER_NAME}' registered and running"
sudo ./svc.sh status
