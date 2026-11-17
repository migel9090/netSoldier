# Contributing — repository conventions

These conventions are team-grade discipline applied from commit one (the pipeline, not
trust, enforces quality). Established as roadmap **step 1**; review and branch protection
as of step 125.2. The project has two maintainers: a backend developer and a devops
engineer.

To report a vulnerability, do not open an issue or a pull request: see [SECURITY.md](SECURITY.md).

## TL;DR

- **Trunk-based**: `main` is always green and releasable; short-lived feature branches; squash-merge via PR.
- **Conventional Commits 1.0.0**, written in English.
- **SemVer 2.0.0**; tags `vX.Y.Z`; `v1.0.0` = production-grade gate (roadmap step 170).
- **Every change lands through a PR** with all security/CI gates green. No direct pushes to `main`.

## Commit messages — Conventional Commits 1.0.0

```
<type>(<scope>)!: <subject>

[optional body — explains WHY, wrapped at 72]

[optional footers: BREAKING CHANGE:, Refs:, Co-Authored-By:]
```

| type | when | SemVer effect |
|---|---|---|
| `feat` | new user-facing capability | MINOR |
| `fix` | bug fix | PATCH |
| `perf` | performance improvement, no behavior change | PATCH |
| `refactor` | code change, no behavior change | — |
| `docs` | documentation only | — |
| `test` | tests only | — |
| `build` | build system, Dockerfiles, dependencies | — |
| `ci` | CI/CD workflows, pipeline gates, their scripts and exceptions | — |
| `deploy` | deployment manifests and profiles: kustomize sites and bases, Quadlet units, the `lite` installer, migrations' wiring | — |
| `infra` | infrastructure as code: Terraform, Ansible, the lab | — |
| `chore` | repo plumbing that fits nothing above | — |
| `revert` | reverts a previous commit | per reverted change |

- There is **no `security` type** (roadmap decision D6): security describes why a change
  was made, not what kind of change it is. A security fix in a service is `fix(<scope>)`, a
  hardened pipeline is `ci(...)`, a hardened manifest is `deploy(...)`; say why in the body.
- `deploy` and `infra` changes do not move the version; release-please (roadmap step 146)
  lists them in sections hidden from the changelog.
- **Breaking changes**: `!` after type/scope **and** a `BREAKING CHANGE:` footer → MAJOR (post-1.0).
- **Scopes** mirror the monorepo layout: `detection-engine`, `device-inventory`, `killswitch`,
  `intel-sync`, `netagent`, `ml-anomaly`, `web-ui`, `deploy`, `infra`, `lab`, `lite`,
  `detections`, `observability`, `security`, `docs`, `ci`, `deps`, `repo`. Omit the scope
  when a change is genuinely cross-cutting.
- Subject: imperative mood, lowercase, no trailing period, ≤ 72 chars.
- When a commit implements a roadmap step, say so: `... (step N)`, e.g. `(step 125.3)`.

Examples:

```
feat(device-inventory): correlate DHCP option 55/60 with hostnames (step 42)
fix(killswitch): never enqueue actions for allowlisted devices
ci: pin all actions to commit SHAs and enable Harden-Runner (step 14)
deploy(lite): run every container with a read-only root filesystem
infra(lab): let several lab VMs coexist (step 125.6)
feat(intel-sync)!: switch IoC export schema to v2

BREAKING CHANGE: detections consuming /export/v1 must migrate to /export/v2.
```

## Versioning — SemVer 2.0.0

- Pre-1.0 (`0.y.z`): MINOR may break; we still document breaks via `BREAKING CHANGE:`.
- `v1.0.0` is **earned, not declared**: tagged only after the final audit gate
  (roadmap steps 170–172 — all gates green, SLO met, DR tested).
- Release automation (release-please, roadmap step 146) will derive versions and the
  changelog from commit history — which is why commit types above are load-bearing.
- Container images: tagged with the version **and** git SHA; deployment manifests pin
  **digests** (immutable; verified by Kyverno `verifyImages` from step 35 on).

## Branching — trunk-based development

- `main` is the only long-lived branch. No `develop`, no release branches; releases are tags on `main`.
- Feature branches: `<type>/<kebab-case-summary>`, e.g. `feat/dhcp-fingerprinting`,
  `ci/sbom-generation`, `fix/sinkhole-revert-ttl`.
- Keep branches **short-lived (≤ ~3 days)**; rebase on `main` before opening the PR.
- `main` is protected, and the protection is kept as code in
  [`.github/branch-protection.json`](.github/branch-protection.json): a PR with one
  approving review, every required check green on an up-to-date branch, enforced for
  administrators too, no force-push, no deletion. `task ci:branch-protection` compares
  the file with the live settings (read-only); the owners apply it with
  `scripts/ci/branch-protection.py --apply`.

## Pull requests & review

- Every change — including the maintainers' own — lands via a PR.
- One roadmap step is one PR, or a pair of PRs when it spans both maintainers' areas
  (roadmap section 3, rule 4).
- **Merge requirements:** every required check green (the list is in
  `.github/branch-protection.json`; the set only ever grows) **and** one approving review.
- **Cross review** (roadmap section 3, rule 5): the backend developer reviews `deploy/`,
  `infra/` and `.github/`; the devops engineer reviews `apps/`, `libs/` and `tests/`.
  [`.github/CODEOWNERS`](.github/CODEOWNERS) requests the right reviewer automatically.
  The author still goes through the checklist below before asking for review.
- **Squash-merge only**; the PR title must itself be a valid Conventional Commit —
  it becomes the commit subject on `main`.
- PR description: what + why, roadmap step reference, how it was tested (evidence,
  not assurances).

### Running the gates locally

The workflows call the same [Task](https://taskfile.dev) targets, with the same pinned
tools (`scripts/ci/tools.sh`), so a target that passes locally passes in CI:

| Target | Gate |
|---|---|
| `task lint` | gofmt and go vet, ruff, ShellCheck, actionlint, Quadlet dry run, promtool |
| `task validate` | deploy configs, every rendered site and profile (kubeconform), first-party images |
| `task scan` | gitleaks, the SOPS/plaintext-Secret check, Semgrep, Checkov, KICS, hadolint |
| `task test`, `task test:e2e`, `task test:integration` | Go and Python tests |
| `task test:corpus`, `task test:corpus:zeek-image` | PCAP corpus replay through the sensors |
| `task lab:validate` | static checks of `infra/` |

The scanners need Docker. A finding that is deliberate or a false positive gets an entry
in `scan-exceptions.toml` with a reason a reviewer can check and a review date; there is
no baseline and no soft fail. `task ci:prove-gates` plants one defect per gate in a copy
of the tree and shows each gate failing.

### Self-review checklist

- [ ] Scope is one logical change (ideally one roadmap step)?
- [ ] Tests cover the change; full suite green locally?
- [ ] No secrets, tokens, private hostnames/IPs in diff or test data?
- [ ] Killswitch/privacy invariants untouched or consciously revised (allowlist fail-open,
      human-in-the-loop, metadata-only, audit log)?
- [ ] Docs/ADR/roadmap state updated if behavior or decisions changed?
- [ ] Commit/PR message follows the conventions above?

## Language

- Code, comments, commits, PRs, runbooks: **English**.
- New `docs/` content may be either Polish or English, preferring English for
  anything portfolio-facing.
