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
git clone <repo-url> && cd projektMigel
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

## What the CI adds beyond pre-commit

Pre-commit catches issues at commit time. CI (steps 14–24) adds:

- CodeQL (deeper SAST, multi-language)
- OSV-Scanner + Grype (SCA — dependency vulnerabilities)
- KICS (additional IaC scanning)
- TruffleHog nightly (historical secret scanning with verification)
- Multi-arch image builds + SBOM + cosign signing + SLSA provenance
- PCAP corpus replay (detection regression testing)
