# Ground truth: flaws in the v0-vulnerable baseline

Planted before any tool was run, so recall can be measured against a fixed list.
Line numbers refer to `app.py` at tag `v0-vulnerable` unless stated.

| ID | Flaw | Location | CWE | Policy |
|----|------|----------|-----|--------|
| V1 | SQL injection: search term concatenated into query | app.py:129 | CWE-89 | |
| V2 | OS command injection: `label` parameter into `subprocess.run(..., shell=True)` | app.py:192 | CWE-78 | |
| V3 | Hard-coded Flask session key | app.py:41 | CWE-798 | |
| V4 | Debug mode on, bound to all interfaces | app.py:204 | CWE-489 | |
| V5 | Unsalted MD5 password hashing | app.py:116, seed.py:53 | CWE-916 | |
| V6 | Vulnerable dependency: Jinja2 3.1.2 | requirements.txt | CWE-1395 | |
| V7 | IDOR: any user can view any claim | app.py:153 | CWE-639 | P1 |
| V8 | IDOR: export returns every user's claims | app.py:184 | CWE-639 | P1 |
| V9 | Missing role check: any user can approve/reject | app.py:172 | CWE-862 | P2 |
| V10 | Self-approval allowed | app.py:172 | CWE-841 | P3 |
| V11 | No amount or date validation (negative, over limit, future) | app.py:99 | CWE-840 | P4 |
| V12 | Decided claims can be edited or re-decided | app.py:160, 172 | CWE-841 | P5 |
| V13 | Mass assignment: edit writes any submitted field (status, owner) | app.py:165 | CWE-915 | P6 |
| V14 | Missing authentication on `/admin/users` | app.py:197 | CWE-306 | P7 |
| V15 | No CSRF protection on state-changing POSTs | all POST routes | CWE-352 | |
| V16 | Session cookie lacks Secure/SameSite configuration | app config | CWE-614 | |
