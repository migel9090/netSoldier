# security/ — secrets policy and scanner baselines

| Content | Purpose | Lands at |
|---|---|---|
| `.sops.yaml` + SOPS policy | which paths are encrypted with which age recipients; **only encrypted files are committed**, plaintext never (root `.gitignore` is the safety net) | step 34 |
| age public keys | recipients for SOPS (private keys live outside the repo, rotation procedure in docs) | steps 34, 167 |
| scanner baselines | tuned configs/suppressions for gitleaks, Semgrep, Checkov, etc. — every suppression must carry a justification comment | steps 6, 14–18 |

Related but elsewhere: threat model and audits live in `docs/`, admission policies in
`deploy/kyverno/`, CI security gates in `.github/workflows/`.
