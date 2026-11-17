#!/usr/bin/env bash
# Show that every gate turns red on a planted defect (task ci:prove-gates).
#
#   scripts/ci/prove-gates.sh [--list] [--keep] [CASE...]
#
# Roadmap 125.3 is done when each gate has been seen to fail on a defect
# planted on purpose (a changed Suricata rule, a readable Secret, a broken
# Dockerfile, ...). A pull request per defect would prove it on GitHub; this
# proves the same commands locally, which is what the workflows run (they
# call the same Taskfile targets):
#
#   1. the current tree (tracked and untracked-but-not-ignored files) is
#      copied into a temporary git repository, as one commit;
#   2. each gate's command runs on that pristine copy and must PASS, so a
#      failure below is the planted defect's doing and not the tree's;
#   3. for each case a fresh copy gets one defect, committed, and the gate's
#      command must FAIL.
#
# Exit status 0 when every baseline passed and every planted defect failed
# its gate. Needs Docker, Python with scripts/ci/requirements.txt and git;
# the pinned tools come from scripts/ci/tools.sh. Heavy: Checkov, KICS,
# Semgrep, the sensors and the lab tools all run twice (about 15 minutes).
# --keep leaves the copies in place for inspection; CASE names (see --list)
# limit the run to those cases and their gates' baselines.
#
# Not covered here: OSV-Scanner and Grype (their vulnerability databases
# live online; the workflows run them as actions), CodeQL (GitHub's code
# scanning), and ci.yml's Go and web UI jobs (owned with ci.yml).
set -euo pipefail

REPO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
keep=0
list=0
only=()
for a in "$@"; do
  case $a in
    --keep) keep=1 ;;
    --list) list=1 ;;
    -*) echo "usage: $0 [--list] [--keep] [CASE...]" >&2; exit 2 ;;
    *) only+=("$a") ;;
  esac
done

# ── gates: name -> command, run from the root of a copy ─────────────────────
# Single-quoted on purpose: $WORK and $(...) expand when the gate runs.
# shellcheck disable=SC2016
declare -A GATE=(
  [validate-manifests]='scripts/ci/render-manifests.sh "$WORK/rendered"'
  [validate-configs]='python3 scripts/validate-configs.py'
  [check-images]='python3 scripts/check-images.py'
  [sops-check]='scripts/sops-check.sh'
  # The planted commit only: the copy's history is one fresh commit, so the
  # fingerprints in .gitleaksignore (commit:path:rule:line) cannot match it.
  [gitleaks]='"$(scripts/ci/tools.sh install gitleaks)/gitleaks" git --redact --no-banner --exit-code 1 --log-opts=HEAD~1..HEAD .'
  [hadolint]='python3 scripts/ci/iac-gate.py hadolint'
  [checkov]='python3 scripts/ci/iac-gate.py checkov'
  [kics]='python3 scripts/ci/iac-gate.py kics'
  [semgrep]='python3 scripts/ci/iac-gate.py semgrep'
  [shellcheck]='scripts/ci/lint-shell.sh'
  [actionlint]='b=$(scripts/ci/tools.sh install actionlint shellcheck) && "$b/actionlint" -shellcheck "$b/shellcheck" -pyflakes='
  [quadlet]='scripts/ci/quadlet-check.sh'
  [promtool]='scripts/ci/promtool-check.sh'
  [pcap-corpus]='scripts/ci/pcap-corpus.sh --sensor suricata'
  [terraform-fmt]='infra/lab/tf.sh fmt -check -recursive'
  [lab-static]='infra/lab/lab.sh tools >/dev/null && infra/lab/lab.sh validate'
  [require-tests]='python3 scripts/ci/require-tests.py "$WORK/e2e.log" TestNetagentNamespaceE2E'
)

# ── cases: name -> "gate|description", and plant_<name> makes the defect ─────
CASES=(
  "kubeconform-field|validate-manifests|unknown field in a Deployment spec"
  "migration-unlisted|validate-configs|a migration file the ConfigMap generator does not list"
  "home-network|validate-configs|the owner's LAN prefix in a base manifest"
  "image-unbuilt|check-images|a first-party image no CI job builds"
  "plaintext-secret|sops-check|a readable Kubernetes Secret"
  "github-token|gitleaks|a GitHub token in a committed file"
  "dockerfile|hadolint|cd and an unpinned apk add in a Dockerfile"
  "privileged-checkov|checkov|privileged web-ui container in the lab site"
  "privileged-kics|kics|privileged web-ui container in the lab site"
  "shell-injection|semgrep|subprocess with shell=True on argv"
  "shell-cd|shellcheck|cd without a fallback in a lab script"
  "workflow-injection|actionlint|untrusted event data in a run: block"
  "quadlet-key|quadlet|an unknown key in a Quadlet unit"
  "promql|promtool|a PromQL syntax error in an alert rule"
  "alert-test|promtool|a rule test whose alert does not fire"
  "suricata-rule|pcap-corpus|a changed Suricata rule (sid 9100003 renumbered)"
  "terraform-format|terraform-fmt|an unformatted Terraform file"
  "ansible-syntax|lab-static|a playbook that does not parse"
  "skipped-test|require-tests|the namespace e2e test skipped"
)

plant_kubeconform-field() { sed -i '0,/^spec:$/s//spec:\n  bogusField: 1/' deploy/kustomize/base/web-ui/deployment.yaml; }
plant_migration-unlisted() { echo 'SELECT 1;' >deploy/clickhouse/migrations/999_planted.sql; }
plant_home-network() { printf '# gateway %s.%s.%s.1\n' 192 168 1 >>deploy/kustomize/base/web-ui/deployment.yaml; }
plant_image-unbuilt() { sed -i 's|ghcr.io/migel9090/web-ui:main|ghcr.io/migel9090/planted-image:main|' deploy/kustomize/base/web-ui/deployment.yaml; }
plant_plaintext-secret() {
  cat >deploy/kustomize/base/web-ui/planted-secret.yaml <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: planted
  namespace: netsoldier
stringData:
  password: $(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')
EOF
}
plant_github-token() {
  printf 'token = "ghp_%s"\n' "$(head -c 64 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 36)" >infra/lab/planted.env
}
plant_dockerfile() { printf 'RUN cd /tmp && apk add curl\n' >>apps/web-ui/Dockerfile; }
plant_privileged() {
  python3 - <<'PY'
import yaml
p = "deploy/kustomize/sites/lab/kustomization.yaml"
k = yaml.safe_load(open(p))
k.setdefault("patches", []).append({
    "target": {"kind": "Deployment", "name": "web-ui"},
    "patch": "- op: add\n  path: /spec/template/spec/containers/0/securityContext/privileged\n  value: true\n",
})
yaml.safe_dump(k, open(p, "w"), sort_keys=False)
PY
}
plant_privileged-checkov() { plant_privileged; }
plant_privileged-kics() { plant_privileged; }
plant_shell-injection() {
  cat >scripts/planted_run.py <<'EOF'
import subprocess
import sys

subprocess.call(sys.argv[1], shell=True)
EOF
}
plant_shell-cd() { printf '#!/usr/bin/env bash\ncd /var/tmp/planted\nrm -rf ./*\n' >infra/lab/planted.sh; }
plant_workflow-injection() {
  cat >.github/workflows/planted.yml <<'EOF'
name: planted
on: issues
permissions: {}
jobs:
  echo:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
EOF
}
plant_quadlet-key() { sed -i 's/^\[Container\]$/[Container]\nBogusKey=1/' deploy/podman/units/netsoldier-web-ui.container; }
plant_promql() { sed -i '0,/expr: up{/s//expr: up{(/' deploy/kustomize/base/observability/prometheus-rules.yaml; }
plant_alert-test() {
  mkdir -p deploy/kustomize/base/observability/tests
  # A passing test next to the failing one: the run must judge both.
  for v in pass:0x10 fail:1x10; do
    cat >"deploy/kustomize/base/observability/tests/planted-${v%%:*}.yaml" <<EOF
rule_files: [../prometheus-rules.yaml]
evaluation_interval: 1m
tests:
  - interval: 1m
    input_series:
      - series: 'up{job="web-ui", namespace="netsoldier"}'
        values: '${v#*:}'
    alert_rule_test:
      - eval_time: 5m
        alertname: NetSoldierServiceDown
        exp_alerts:
          - exp_labels: {severity: critical, job: web-ui, namespace: netsoldier}
            exp_annotations:
              summary: web-ui is down
              description: web-ui in namespace netsoldier has been unreachable for over 2 minutes.
EOF
  done
}
plant_suricata-rule() { sed -i 's/sid:9100003;/sid:9100099;/' deploy/kustomize/base/suricata/local-rules-cm.yaml; }
plant_terraform-format() { printf 'variable "planted" {\ntype=string\n      default = "x"\n}\n' >infra/terraform/planted.tf; }
plant_ansible-syntax() { printf -- '- hosts: all\n  tasks: [\n' >>infra/ansible/site.yml; }
plant_skipped-test() {
  printf '=== RUN   TestNetagentNamespaceE2E\n    netagent_ns_test.go:56: unprivileged user+net namespaces unavailable\n--- SKIP: TestNetagentNamespaceE2E (0.04s)\n' >"$WORK/e2e.log"
}
# The require-tests baseline reads a log of a run that passed.
baseline_require-tests() { printf -- '=== RUN   TestNetagentNamespaceE2E\n--- PASS: TestNetagentNamespaceE2E (3.75s)\n' >"$WORK/e2e.log"; }
# gitleaks judges the last commit; the baseline's last commit adds nothing.
baseline_gitleaks() { git_q commit -q --allow-empty -m 'baseline: nothing new'; }

if ((list)); then
  for c in "${CASES[@]}"; do IFS='|' read -r n g d <<<"$c"; printf '%-20s %-20s %s\n' "$n" "$g" "$d"; done
  exit 0
fi

selected=()
for c in "${CASES[@]}"; do
  IFS='|' read -r n _ _ <<<"$c"
  if ((${#only[@]} == 0)) || [[ " ${only[*]} " == *" $n "* ]]; then selected+=("$c"); fi
done
((${#selected[@]})) || { echo "no such case: ${only[*]} (see --list)" >&2; exit 2; }

ROOT=$(mktemp -d "${TMPDIR:-/tmp}/prove-gates.XXXXXX")
cleanup() {
  if ((keep)); then echo "kept: $ROOT"; else rm -rf "$ROOT"; fi
}
trap cleanup EXIT
export LAB_STATE=$ROOT/lab-state LAB_CACHE=$ROOT/lab-cache LAB_CONFIG=$ROOT/lab-config
export LAB_VENV=${LAB_VENV:-$ROOT/lab-venv}
git_q() { git -c user.name=prove-gates -c user.email=prove-gates@localhost "$@"; }

# 1. pristine copy, one commit
pristine=$ROOT/pristine
mkdir -p "$pristine"
(cd "$REPO_DIR" && git ls-files -z -co --exclude-standard) |
  (cd "$REPO_DIR" && while IFS= read -r -d '' f; do [[ -e $f || -L $f ]] && printf '%s\0' "$f"; done) |
  (cd "$REPO_DIR" && tar --null -T - -cf -) | tar -xf - -C "$pristine"
(cd "$pristine" && git_q init -q -b main && git_q add -A && git_q commit -q -m pristine)

run_gate() { # dir gate log -> exit status of the gate's command
  local dir=$1 gate=$2 log=$3
  (cd "$dir" && WORK=$ROOT/work-$(basename "$dir") && export WORK && mkdir -p "$WORK" &&
    bash -c "${GATE[$gate]}") >"$log" 2>&1
}

declare -A baseline=()
results=()
fail=0
for c in "${selected[@]}"; do
  IFS='|' read -r name gate desc <<<"$c"
  # 2. the gate's baseline on the pristine copy, once per gate
  if [[ -z ${baseline[$gate]:-} ]]; then
    base=$ROOT/base-$gate
    cp -a "$pristine" "$base"
    if declare -F "baseline_$gate" >/dev/null; then (cd "$base" && WORK=$ROOT/work-base-$gate && export WORK && mkdir -p "$WORK" && "baseline_$gate"); fi
    printf '%-20s %-20s baseline ... ' "-" "$gate"
    if run_gate "$base" "$gate" "$ROOT/base-$gate.log"; then
      baseline[$gate]=PASS
      echo PASS
    else
      baseline[$gate]=FAIL
      echo "FAIL (the unchanged tree fails this gate; log: $ROOT/base-$gate.log)"
      tail -n 20 "$ROOT/base-$gate.log" | sed 's/^/    /'
      fail=1
    fi
  fi
  # 3. the planted defect
  copy=$ROOT/case-$name
  cp -a "$pristine" "$copy"
  (cd "$copy" && WORK=$ROOT/work-case-$name && export WORK && mkdir -p "$WORK" && "plant_$name" &&
    git_q add -A && git_q commit -q --allow-empty -m "planted: $name")
  printf '%-20s %-20s planted  ... ' "$name" "$gate"
  if run_gate "$copy" "$gate" "$ROOT/case-$name.log"; then
    echo "PASS (the defect was NOT caught; log: $ROOT/case-$name.log)"
    results+=("$name|$gate|${baseline[$gate]}|not caught|$desc")
    fail=1
  else
    echo "FAIL, as it must"
    grep -m3 -E '::error|FAIL|error|warning:|Error|failed' "$ROOT/case-$name.log" | cut -c1-160 | sed 's/^/    /' || true
    results+=("$name|$gate|${baseline[$gate]}|caught|$desc")
  fi
  ((keep)) || rm -rf "$copy" "$ROOT/work-case-$name"
done

echo
printf '%-20s %-20s %-9s %-11s %s\n' CASE GATE BASELINE DEFECT WHAT
for r in "${results[@]}"; do
  IFS='|' read -r n g b d w <<<"$r"
  printf '%-20s %-20s %-9s %-11s %s\n' "$n" "$g" "$b" "$d" "$w"
done
if ((fail)); then
  echo "prove-gates: FAILED (a baseline failed or a defect went through)"
  exit 1
fi
echo "prove-gates: OK (${#results[@]} planted defects, each caught by its gate)"
