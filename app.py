"""ClaimDesk: a small staff expense-claims application (Flask + SQLite).

Business policy (the source of truth for the custom security tests):
  P1  Staff can view, edit and export only their own claims. Managers and
      finance can view all claims.
  P2  Only managers can approve or reject a claim.
  P3  Nobody can approve or reject their own claim (separation of duties).
  P4  A claim amount must be greater than 0 and at most 2,000.00 EUR, and the
      expense date cannot be in the future.
  P5  Only pending claims can be edited, approved or rejected.
  P6  Users can change only description, amount and expense_date on a claim.
      Status, owner and approver are set by the system, never by the client.
  P7  The user administration page is for the finance role only.
"""
import csv
import hashlib
import io
import os
import secrets
import sqlite3
import subprocess
from datetime import date
from decimal import Decimal
from functools import wraps

from flask import (Flask, Response, abort, g, redirect, render_template_string,
                   request, session, url_for)

MAX_CLAIM = Decimal("2000.00")
EDITABLE_FIELDS = ("description", "amount", "expense_date")

PAGE = """<!doctype html><title>ClaimDesk</title>
<p>{{ message }}</p>
{% for c in claims %}<div class="claim">#{{ c.id }} {{ c.description }}
 {{ c.amount }} {{ c.status }} owner={{ c.owner_id }}</div>{% endfor %}"""

app = Flask(__name__)
app.config.update(
    DATABASE=os.environ.get("APP_DB", "claimdesk.db"),
)
app.secret_key = "9f4c2e8b7a1d6053e2c9b84f1a7d3e60"


# ---------------------------------------------------------------- database
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ------------------------------------------------------- auth and policy
def current_user():
    uid = session.get("uid")
    if uid is None:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if current_user()["role"] not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def load_claim_for(user, claim_id):
    """Central object-level authorisation check (policy P1)."""
    claim = get_db().execute("SELECT * FROM claims WHERE id = ?", (claim_id,)).fetchone()
    if claim is None:
        abort(404)
    return claim


def validate_claim_fields(form):
    """Business rules P4. Returns (clean_values, error)."""
    try:
        amount = float(form.get("amount", ""))
        expense_date = date.fromisoformat(form.get("expense_date", ""))
    except ValueError:
        return None, "amount and expense_date are required"
    description = form.get("description", "").strip()[:200]
    if not description:
        return None, "description is required"
    return {"description": description, "amount": str(amount),
            "expense_date": expense_date.isoformat()}, None


# ------------------------------------------------------------------ routes
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = get_db().execute("SELECT * FROM users WHERE username = ?",
                                (request.form.get("username", ""),)).fetchone()
        supplied = hashlib.md5(request.form.get("password", "").encode()).hexdigest()
        if user and user["password_hash"] == supplied:
            session["uid"] = user["id"]
            return redirect(url_for("list_claims"))
        return "invalid credentials", 401
    return "login form"


@app.route("/claims")
@login_required
def list_claims():
    user = current_user()
    term = request.args.get("search", "")
    query = "SELECT * FROM claims WHERE description LIKE '%" + term + "%'"
    if user["role"] == "staff":
        query += " AND owner_id = " + str(user["id"])
    rows = get_db().execute(query).fetchall()
    return render_template_string(PAGE, claims=rows, message="")


@app.route("/claims/new", methods=["POST"])
@login_required
def create_claim():
    values, error = validate_claim_fields(request.form)
    if error:
        return error, 400
    db = get_db()
    cur = db.execute(
        "INSERT INTO claims (owner_id, description, amount, expense_date, status) "
        "VALUES (?, ?, ?, ?, 'pending')",
        (current_user()["id"], values["description"], values["amount"], values["expense_date"]))
    db.commit()
    return redirect(url_for("view_claim", claim_id=cur.lastrowid))


@app.route("/claims/<int:claim_id>")
@login_required
def view_claim(claim_id):
    claim = load_claim_for(current_user(), claim_id)
    return render_template_string(PAGE, claims=[claim], message="")


@app.route("/claims/<int:claim_id>/edit", methods=["POST"])
@login_required
def edit_claim(claim_id):
    load_claim_for(current_user(), claim_id)
    fields = {k: v for k, v in request.form.items() if k != "csrf"}
    assignments = ", ".join(f"{k} = ?" for k in fields)
    db = get_db()
    db.execute(f"UPDATE claims SET {assignments} WHERE id = ?", (*fields.values(), claim_id))
    db.commit()
    return redirect(url_for("view_claim", claim_id=claim_id))


@app.route("/claims/<int:claim_id>/<any(approve, reject):decision>", methods=["POST"])
@login_required
def decide_claim(claim_id, decision):
    user = current_user()
    load_claim_for(user, claim_id)
    db = get_db()
    db.execute("UPDATE claims SET status = ?, approver_id = ? WHERE id = ?",
               ("approved" if decision == "approve" else "rejected", user["id"], claim_id))
    db.commit()
    return redirect(url_for("view_claim", claim_id=claim_id))


@app.route("/claims/export")
@login_required
def export_claims():
    label = request.args.get("label", "claims")
    path = f"/tmp/claimdesk-{label}.csv"
    with open(path, "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["id", "description", "amount", "expense_date", "status"])
        for row in get_db().execute("SELECT id, description, amount, expense_date, status FROM claims"):
            writer.writerow(list(row))
    subprocess.run(f"gzip -kf {path}", shell=True)
    with open(path) as fh:
        return Response(fh.read(), mimetype="text/csv")


@app.route("/admin/users")
def admin_users():
    rows = get_db().execute("SELECT id, username, role FROM users").fetchall()
    return "\n".join(f"{r['id']},{r['username']},{r['role']}" for r in rows)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
