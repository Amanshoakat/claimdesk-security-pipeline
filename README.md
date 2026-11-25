# ClaimDesk security pipeline (CA2, Secure Programming and Scripting)

ClaimDesk is a small Flask + SQLite staff expense-claims application. The
first commit (`v0-vulnerable` tag) is a deliberately vulnerable baseline with
16 documented flaws (ground truth, see `GROUND-TRUTH.md`). Later commits add
the security pipeline and fix the flaws.

## Pipeline

| Stage | Where | Checks |
|-------|-------|--------|
| Developer machine | `.pre-commit-config.yaml` | Gitleaks, Bandit (bypassable, convenience only) |
| Pull request (gating) | `.github/workflows/security.yml` | Gitleaks (full history), Semgrep, Bandit, pip-audit, custom tests |
| Main + weekly schedule | same workflow | the same gates, so new advisories surface without a code change |

Fail/warn thresholds and the reasons for them are in the report. Accepted
risks are in `SECURITY-EXCEPTIONS.md`.

## Run locally

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
# Gitleaks is a Go binary: https://github.com/gitleaks/gitleaks/releases (v8.30.1)
bash scripts/ci_local.sh            # runs every gate, prints PASS/FAIL per gate
APP_DB=dev.db python seed.py && CLAIMDESK_INSECURE_COOKIES=1 flask --app app run   # local only
```

## Layout

- `app.py`, `seed.py`: the application and the seeded test database
- `tests/security/policy.yaml`: access-control policy as data (one test per row)
- `tests/security/test_*.py`: custom tests (policy matrix, Hypothesis business rules, workflow)
- `rules/semgrep/claimdesk.yml`: custom Semgrep rules for this codebase
- `rules/vendor/`: Semgrep community rules (python/flask, python/lang/security) pinned at semgrep-rules commit a5ad1714, Semgrep Rules License v1.0
- `scripts/ci_local.sh`: local mirror of the CI gates

Rules of engagement: all testing ran on this code, on a local machine and on
the repository's own CI runner. No live system was tested.
