#!/usr/bin/env bash
# Recreate the five demonstration branches used in the report, each one commit
# on top of main. Push them and open a pull request for each to get the CI
# evidence (failed run, then close the PR without merging).
#   D1 demo/sast-sqli          SQL built by concatenation        -> Semgrep gate
#   D2 demo/sca-jinja          Jinja2 3.1.2 pinned                -> pip-audit gate
#   D3 demo/secret-token       fake GitHub token committed        -> Gitleaks gate
#   D4 demo/authz-regression   approval open to any user          -> custom tests + custom rule
#   D5 demo/planted-miss       new receipt route, no owner check  -> expected to PASS (a miss)
set -euo pipefail
cd "$(dirname "$0")/.."
git diff --quiet || { echo "working tree not clean"; exit 1; }

new_branch() { git checkout -q main; git branch -D "$1" -q 2>/dev/null || true; git checkout -q -b "$1"; }
commit() { git add -A; git commit -q -m "$1"; echo "$(git branch --show-current) $(git rev-parse --short HEAD)"; }

new_branch demo/sast-sqli
python3 - <<'EOF'
s = open("app.py").read()
s = s.replace('''    term = f"%{request.args.get('search', '')}%"
    if user["role"] == "staff":
        rows = get_db().execute(
            "SELECT * FROM claims WHERE owner_id = ? AND description LIKE ?",
            (user["id"], term)).fetchall()''', '''    term = request.args.get("search", "")
    if user["role"] == "staff":
        rows = get_db().execute(
            "SELECT * FROM claims WHERE owner_id = ? AND description LIKE '%" + term + "%'",
            (user["id"],)).fetchall()''')
open("app.py", "w").write(s)
EOF
commit "Demo D1: search builds SQL by concatenation (deliberate SAST regression)"

new_branch demo/sca-jinja
sed -i 's/jinja2==3.1.6/jinja2==3.1.2/' requirements.txt
commit "Demo D2: pin Jinja2 3.1.2 (deliberate vulnerable dependency)"

new_branch demo/secret-token
TOKEN="ghp_$(python3 -c "import secrets,string;print(''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(36)))")"
mkdir -p config
printf '# FAKE token generated for the CA2 demo. Never valid, never used.\nGITHUB_DEPLOY_TOKEN = "%s"\n' "$TOKEN" > config/deploy_settings.py
commit "Demo D3: commit a fake GitHub token (deliberate secret leak)"

new_branch demo/authz-regression
python3 - <<'EOF'
s = open("app.py").read()
s = s.replace('methods=["POST"])\n@role_required("manager")\ndef decide_claim', 'methods=["POST"])\n@login_required\ndef decide_claim')
s = s.replace('    if claim["owner_id"] == user["id"]:\n        abort(403)  # P3: no self-approval\n', '')
open("app.py", "w").write(s)
EOF
commit "Demo D4: approval open to any logged-in user, self-approval check removed"

new_branch demo/planted-miss
python3 - <<'EOF'
s = open("app.py").read()
s = s.replace('@app.route("/claims/export")', '''@app.route("/claims/<int:claim_id>/receipt")
@login_required
def claim_receipt(claim_id):
    # New feature: printable receipt. Loads the claim directly (no owner check).
    claim = get_db().execute("SELECT * FROM claims WHERE id = ?", (claim_id,)).fetchone()
    if claim is None:
        abort(404)
    return render_template_string(PAGE, claims=[claim], message="Receipt")


@app.route("/claims/export")''')
open("app.py", "w").write(s)
EOF
commit "Demo D5: add receipt route without ownership check (expected MISS)"

git checkout -q main
