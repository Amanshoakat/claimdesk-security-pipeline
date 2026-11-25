#!/usr/bin/env bash
# Local mirror of .github/workflows/security.yml: same tools, same flags,
# same thresholds. Used to measure runtimes and to reproduce a CI failure on
# a developer machine. Exit code is non-zero if any gate fails, and every
# gate runs even after an earlier one fails, so one run shows all problems.
set -u
cd "$(dirname "$0")/.."
mkdir -p reports
status=0
gate() {
  local name="$1"; shift
  local start end
  start=$(date +%s.%N)
  if "$@"; then result=PASS; else result=FAIL; status=1; fi
  end=$(date +%s.%N)
  printf '>>> %-34s %s  (%.1fs)\n' "$name" "$result" "$(echo "$end - $start" | bc)"
}

gate "Secrets (Gitleaks, full history)" \
  gitleaks git --redact --verbose --exit-code 1 --log-opts=HEAD --report-format json --report-path reports/gitleaks.json .
gate "SAST Semgrep (ERROR fails)" \
  semgrep scan --metrics=off --disable-version-check --config rules/semgrep --config rules/vendor --severity ERROR --error app.py seed.py
gate "SAST Bandit (HIGH sev, MED+ conf)" \
  bandit -q -r app.py seed.py --severity-level high --confidence-level medium
gate "SCA pip-audit" \
  pip-audit -r requirements.txt --disable-pip --no-deps
gate "Custom security tests" \
  python3 -m pytest tests/security -q -p no:cacheprovider

# Warning-level reports: never fail the build
semgrep scan --metrics=off --disable-version-check -q --config rules/semgrep --config rules/vendor --json --output reports/semgrep.json app.py seed.py || true
bandit -q -r app.py seed.py -f json -o reports/bandit.json --exit-zero

echo ">>> OVERALL: $([ $status -eq 0 ] && echo PASS || echo FAIL)"
exit $status
