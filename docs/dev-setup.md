# Developer setup

## Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Git | ≥ 2.40 | version control |
| Go | ≥ 1.22 | services (detection-engine, device-inventory, killswitch-controller, threat-intel-sync) |
| Python | ≥ 3.12 | ML anomaly service, pre-commit, checkov |
| Node.js | ≥ 20 LTS | web-ui (SvelteKit) |
| pnpm | ≥ 9 | JS package manager |
| Docker | ≥ 24 | container builds, hadolint hook, local testing |
| pre-commit | ≥ 3.8 | git hook framework |
| Terraform | ≥ 1.7 | infrastructure (optional — only for `infra/terraform/`) |
| Ansible | ≥ 2.16 | provisioning (optional — only for `infra/ansible/`) |

Install pre-commit:

```bash
pip install pre-commit
# or: pipx install pre-commit
```

## Repository setup

```bash
git clone <repo-url> && cd netSoldier
pre-commit install            # hooks run on every commit
pre-commit run --all-files    # one-time check of existing files
```

## Pre-commit hooks

The `.pre-commit-config.yaml` runs these hooks on every `git commit`:

| Hook | Category | What it catches |
|---|---|---|
| **gitleaks** | Secrets | API keys, tokens, private keys in staged files |
| **semgrep** | SAST | Code-level security issues, bug patterns (auto-config per language) |
| **checkov** | IaC scan | Terraform, Kubernetes, Dockerfile misconfigurations |
| **hadolint** | Dockerfile lint | Dockerfile best-practice violations |
| **gofmt / goimports** | Formatter | Go formatting and import ordering |
| **ruff** | Formatter + lint | Python linting (security, style, bugs) and formatting |
| **prettier** | Formatter | JS/TS/Svelte/CSS/JSON/YAML/Markdown formatting |
| standard hooks | General | Trailing whitespace, EOF newlines, YAML/JSON syntax, merge conflicts, large files, private keys |

Semgrep and checkov require network access on first run and can be slow.
To skip heavy hooks for a quick iteration commit:

```bash
SKIP=semgrep,checkov git commit -m "wip: ..."
```

To update hook versions:

```bash
pre-commit autoupdate
```

## Running formatters manually

```bash
# Go
gofmt -w apps/
goimports -w apps/

# Python
ruff check --fix apps/ml-anomaly/
ruff format apps/ml-anomaly/

# JS/TS/Svelte
pnpm -C apps/web-ui exec prettier --write .
```

## Editor integration

Most editors detect `.editorconfig` automatically. Recommended extensions:

- **VS Code:** EditorConfig, Go (official), Ruff, Svelte, Prettier
- **JetBrains:** EditorConfig (built-in), Go/Python/JS support built-in, Ruff plugin
- **Neovim/Helix:** editorconfig support built-in; LSPs for gopls, ruff, svelte-language-server

## npm/pnpm supply-chain hardening

The repo-level `.npmrc` enforces supply-chain defenses for all JS/TS work:

| Setting | Defense |
|---|---|
| `ignore-scripts=true` | Blocks postinstall/preinstall lifecycle scripts (primary npm attack vector) |
| `save-exact=true` | Pins exact versions — no `^`/`~` floating ranges |
| `engine-strict=true` | Fails on Node.js version mismatch instead of silently continuing |
| `strict-peer-dependencies=true` | Fails on peer dep conflicts |
| `registry=https://registry.npmjs.org/` | Explicit registry — prevents confusion attacks |
| `audit=true` | Runs `pnpm audit` on every install |

The `apps/web-ui/package.json` additionally locks:

- **`packageManager`** — Corepack enforces exact pnpm version across all machines
- **`pnpm.onlyBuiltDependencies: []`** — empty allowlist; no package can run native builds unless explicitly listed

In CI, always use `pnpm install --frozen-lockfile` to fail if the lockfile would change.

If a dependency legitimately needs a build script (e.g. `esbuild` native binary),
add it to `onlyBuiltDependencies` by name after reviewing its postinstall:

```bash
# Audit what a package runs before allowlisting
pnpm why <package> && pnpm exec -- cat node_modules/<package>/package.json | jq '.scripts'
```

## Multi-arch container builds

Images are built for **linux/amd64** (Proxmox server) and **linux/arm64** (Pi 3B+).
The Dockerfiles use `--platform=$BUILDPLATFORM` with Go cross-compilation
(`GOOS`/`GOARCH`), so no QEMU emulation is needed for the build stage.

One-time builder setup:

```bash
docker buildx create --name netsoldier-builder --driver docker-container --bootstrap
```

Build for both architectures:

```bash
# Local test (both platforms, result stays in build cache)
docker buildx build --builder netsoldier-builder \
  --platform linux/amd64,linux/arm64 \
  -t netsoldier/detection-engine:dev apps/detection-engine/

# Push to GHCR
docker buildx build --builder netsoldier-builder \
  --platform linux/amd64,linux/arm64 \
  -t ghcr.io/migel9090/detection-engine:dev --push apps/detection-engine/

# Load single-platform into local Docker (for testing)
docker buildx build --builder netsoldier-builder \
  --platform linux/amd64 --load \
  -t netsoldier/detection-engine:dev apps/detection-engine/
```

## Container registry (GHCR)

Images are published to `ghcr.io/migel9090/<service>`. In CI, the
`GITHUB_TOKEN` with `packages: write` handles authentication automatically.
For local pushes:

```bash
echo $GITHUB_TOKEN | docker login ghcr.io -u migel9090 --password-stdin
```

Image naming convention: `ghcr.io/migel9090/<service>:<version>` and
`ghcr.io/migel9090/<service>:sha-<short-sha>`. Deployment manifests pin
**digests** (immutable), not tags.

The repo's default `GITHUB_TOKEN` permission is **read-only** — each
workflow must explicitly declare `permissions: { packages: write }` to
push images. This follows least-privilege.

## What the CI adds beyond pre-commit

Pre-commit catches issues at commit time. CI (steps 14–24) adds:

- Semgrep (full repo SAST scan → SARIF → GitHub Security tab)
- CodeQL (deeper SAST, multi-language: Go/Python/JS-TS → SARIF)
- OSV-Scanner (SCA — dependency vulnerabilities via OSV.dev → SARIF, informational)
- Grype (SCA — dependency vulnerabilities, blocks on critical/high → SARIF)
- Checkov (IaC scan — Dockerfiles, GitHub Actions, Terraform, K8s → SARIF, informational)
- KICS (IaC scan — blocks on HIGH severity → SARIF)
- Gitleaks (CI gate — secret detection on every push/PR → SARIF)
- TruffleHog nightly (full history scan with `--only-verified` — alerts on active leaked credentials)
- Multi-arch image builds + SBOM + cosign signing + SLSA provenance
- PCAP corpus replay (detection regression testing)
