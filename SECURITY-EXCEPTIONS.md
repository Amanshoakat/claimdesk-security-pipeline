# Accepted-risk register

Every suppression in this repository is listed here with a reason, an owner
and a review date. A suppression that is not in this table is a defect.

| ID | Tool / rule | Location | Reason | Owner | Review |
|----|-------------|----------|--------|-------|--------|
| EX-01 | Gitleaks `generic-api-key` (fingerprint in `.gitleaksignore`) | `app.py:41` in baseline commit only | Flask session key hard-coded in the inherited baseline. Key was never used outside local development, was removed from the code and replaced by the `CLAIMDESK_SECRET_KEY` environment variable. History is kept (not rewritten) so the baseline stays reproducible for assessment. Any deployment must use a new key. | Dev lead | 2027-03-01 |
| EX-02 | Semgrep `use-defusedcsv` (`# nosemgrep`) | `app.py`, `export_claims` | Formula-injection risk is mitigated by `csv_safe()`, which prefixes cells starting with `= + - @ TAB CR`. The rule is pattern-based and cannot see the mitigation. | Dev lead | 2027-03-01 |
| EX-03 | Bandit `B101` (not suppressed, tests folder excluded from scan) | `tests/` | 18 `assert` findings: pytest uses `assert` by design and the tests never run with `-O`. | Dev lead | 2027-03-01 |

pip-audit `--ignore-vuln` entries: none.
