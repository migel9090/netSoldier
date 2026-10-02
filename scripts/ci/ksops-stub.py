#!/usr/bin/env python3
"""Build-time stand-in for the ksops exec plugin, for CI validation only.

base/misp generates its Secret with ksops, which decrypts a SOPS-encrypted
file at `kustomize build` time. CI cannot run the real plugin: it has no
ksops binary, no decryption key, and the encrypted payload the generator
points at (secret.sops.yaml) is deliberately not committed — only
secret.sops.example.yaml is. Without a stand-in, `kustomize build` fails on
the proxmox-soc overlay and the whole overlay goes unvalidated.

This emits a structurally valid placeholder Secret so every other manifest
in the overlay still renders and gets schema-checked. No secret material is
involved and nothing here runs outside CI: ArgoCD's repo-server has the real
ksops plugin (deploy/argocd/patches/repo-server-ksops.yaml) and does the
real decryption at deploy time.

Consequence to be aware of: the contents of the generated Secret are not
covered by the gate. Only its presence and shape are.
"""

import json
import sys


def main() -> int:
    payload = sys.stdin.read()
    try:
        resource_list = json.loads(payload)
    except json.JSONDecodeError:
        import yaml  # kustomize may hand the ResourceList over as YAML

        resource_list = yaml.safe_load(payload)

    config = resource_list.get("functionConfig") or {}
    name = (config.get("metadata") or {}).get("name", "ksops-placeholder")

    json.dump(
        {
            "apiVersion": "config.kubernetes.io/v1",
            "kind": "ResourceList",
            "items": [
                {
                    "apiVersion": "v1",
                    "kind": "Secret",
                    # The generator is named "<thing>-generator"; the Secret
                    # it stands in for is "<thing>".
                    "metadata": {"name": name.removesuffix("-generator")},
                    "type": "Opaque",
                    "stringData": {"placeholder": "ci-validation-only"},
                }
            ],
        },
        sys.stdout,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
