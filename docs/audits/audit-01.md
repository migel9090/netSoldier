# Audit #1 — CI foundation sanity check

- **Date:** 2026-01-17
- **Scope:** Steps 0–24 (Phase 0 DevSecOps foundation)
- **Result:** **PASS** (all criteria met)

## 1. Planted secret blocked by gitleaks

**Test:** PR #4 with a planted fake AWS key (`AKIA5X7PCHQRCJTTWBMZ` + secret key) in `test-secret.txt`.

**Result:** BLOCKED — gitleaks detected 2 leaks and failed the check.

```
WRN leaks found: 2
```

- CI run: 26912715009 (conclusion: failure)
- SARIF artifact uploaded (`gitleaks-results.sarif.zip`, artifact ID 7396575844)
- Semgrep also independently flagged the secret (defense in depth)
- Note: AWS documentation example keys (`AKIAIOSFODNN7EXAMPLE`) are allowlisted by gitleaks — confirmed by first test iteration passing; second iteration with non-allowlisted key correctly blocked

PR #4 closed without merge, branch deleted.

## 2. Multi-arch image supply chain artifacts

Image: `ghcr.io/migel9090/detection-engine:main`

### Cosign signature

**Result:** VERIFIED

```
Verification for ghcr.io/migel9090/detection-engine:main --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The code-signing certificate was verified using trusted certificate authority certificates
```

Verified with:
```bash
cosign verify \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity-regexp='github.com/migel9090/netSoldier' \
  ghcr.io/migel9090/detection-engine:main
```

### SBOM (CycloneDX)

**Result:** PRESENT — artifact `sbom-detection-engine` (82,322 bytes) uploaded to CI run 26912093019.

### SLSA L2 provenance

**Result:** PRESENT — all three provenance sub-jobs passed on CI run 26912093019:
- `provenance / detect-env`: success
- `provenance / generator`: success
- `provenance / final`: success

Provenance attestation attached to the image in GHCR by `slsa-framework/slsa-github-generator@v2.1.0`.

## 3. All gates green on clean PR

All CI checks passed on the clean push (run 26912093019, conclusion: success):
- lint (Go vet + ruff): success
- test (Go test -race + pytest): success
- build (multi-arch Docker + cosign sign + SBOM): success
- SAST (Semgrep + CodeQL Go/Python/JS-TS): success
- SCA (OSV-Scanner + Grype): success
- IaC scan (Checkov + KICS): success
- Secret scan (gitleaks): success

## 4. Action SHA pinning

**Result:** ALL ACTIONS SHA-PINNED across 5 workflow files.

| Action | SHA | Version |
|---|---|---|
| actions/checkout | `df4cb1c0...` | v6.0.3 |
| actions/setup-go | `4a360112...` | v6.4.0 |
| actions/setup-python | `a309ff8b...` | v6.2.0 |
| anchore/sbom-action | `e22c3899...` | v0.24.0 |
| anchore/scan-action | `e1165082...` | v7.4.0 |
| bridgecrewio/checkov-action | `6772af19...` | v12.3104.0 |
| checkmarx/kics-github-action | `05aa5eb7...` | v2.1.20 |
| docker/build-push-action | `26343531...` | v6.18.0 |
| docker/login-action | `74a5d142...` | v3.4.0 |
| docker/metadata-action | `902fa8ec...` | v5.7.0 |
| docker/setup-buildx-action | `e468171a...` | v3.11.1 |
| github/codeql-action/* | `87557b9c...` | v4.36.1 |
| gitleaks/gitleaks-action | `e0c47f4f...` | v3.0.0 |
| google/osv-scanner-action | `9a498708...` | v2.3.8 |
| sigstore/cosign-installer | `6f9f1778...` | v4.1.2 |
| step-security/harden-runner | `0634a267...` | v2.12.0 |
| trufflesecurity/trufflehog | `d411fff7...` | v3.95.5 |

Exception: `slsa-framework/slsa-github-generator@v2.1.0` uses a tagged version per the SLSA framework's own security guidance (the tag is the trust anchor for reusable workflows).

## 5. Harden-Runner egress audit

Harden-Runner v2.12.0 deployed on every job across all 5 workflows in **audit mode** (`egress-policy: audit`).

Egress insights dashboard: `https://app.stepsecurity.io/github/migel9090/netSoldier/actions/runs/<run-id>`

Audit mode logs all outbound network connections without blocking, building a baseline for a future transition to `egress-policy: block` with an explicit allowlist.

## 6. Observations and follow-ups

- **AWS example keys bypass:** gitleaks allowlists well-known example keys (e.g. `AKIAIOSFODNN7EXAMPLE`). This is correct behavior — they are documented fake keys.
- **Harden-Runner Node.js 20 deprecation:** step-security/harden-runner still runs on Node.js 20. Node.js 20 deprecation deadline is June 16, 2026. Cosmetic warning only — no functional impact.
- **SLSA provenance intermittent skips:** provenance job was skipped on some push-to-main CI runs while succeeding on others. Likely caused by the build job not outputting a digest on cached/unchanged builds. To investigate in a future step.
- **Dependabot configured:** weekly scans for Go, Python, npm, GitHub Actions; monthly for Docker base images. Automerge OFF, branch protection enforces PR review.
