# Contributing — repository conventions

These conventions are team-grade discipline applied from commit one, even while the
project is solo-maintained (portfolio rule: the pipeline, not trust, enforces quality).
Established as roadmap **step 1** (`context/04-roadmap.md`).

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
| `ci` | CI/CD workflows, pipeline gates | — |
| `chore` | repo plumbing that fits nothing above | — |
| `revert` | reverts a previous commit | per reverted change |

- **Breaking changes**: `!` after type/scope **and** a `BREAKING CHANGE:` footer → MAJOR (post-1.0).
- **Scopes** mirror the monorepo layout: `detection-engine`, `device-inventory`, `killswitch`,
  `intel-sync`, `ml-anomaly`, `web-ui`, `deploy`, `infra`, `detections`, `observability`,
  `security`, `docs`, `ci`, `repo`. Omit the scope when a change is genuinely cross-cutting.
- Subject: imperative mood, lowercase, no trailing period, ≤ 72 chars.
- When a commit implements a roadmap step, say so: `... (step N)`.

Examples:

```
feat(device-inventory): correlate DHCP option 55/60 with hostnames (step 42)
fix(killswitch): never enqueue actions for allowlisted devices
ci: pin all actions to commit SHAs and enable Harden-Runner (step 14)
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
- `main` is protected (enforced via GitHub branch protection at roadmap step 12:
  required PR, required status checks, no force-push). Until the GitHub repo exists,
  the same rules apply by discipline.

## Pull requests & review

- Every change — including the maintainer's — lands via a PR.
- **Merge requirements:** all CI gates green (lint, tests, SAST, SCA, secrets, IaC scan —
  as they come online in roadmap steps 14–24; the set only ever grows) **and** a review.
- **Review in solo mode:** an explicit self-review pass against the checklist below,
  done *after* a cooling-off break, recorded as a PR comment. When a second human is
  available, their review replaces self-review for anything touching `killswitch`,
  `security/` or `deploy/`.
- **Squash-merge only**; the PR title must itself be a valid Conventional Commit —
  it becomes the commit subject on `main`.
- PR description: what + why, roadmap step reference, how it was tested (evidence,
  not assurances).

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
- `context/` starter pack stays **Polish** (original project record); new `docs/` content
  may be either, preferring English for anything portfolio-facing.
