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
import io
import os
import secrets
import sqlite3
from datetime import date
from decimal import Decimal, InvalidOperation
from functools import wraps

from flask import (Flask, Response, abort, g, redirect, render_template_string,
                   request, session, url_for)
from werkzeug.security import check_password_hash

MAX_CLAIM = Decimal("2000.00")
EDITABLE_FIELDS = ("description", "amount", "expense_date")

PAGE = """<!doctype html><title>ClaimDesk</title>
<p>{{ message }}</p>
{% for c in claims %}<div class="claim">#{{ c.id }} {{ c.description }}
 {{ c.amount }} {{ c.status }} owner={{ c.owner_id }}</div>{% endfor %}"""

app = Flask(__name__)
app.config.update(
    # Secret comes from the environment. A random fallback keeps tests and
    # local runs working without ever committing a key.
    SECRET_KEY=os.environ.get("CLAIMDESK_SECRET_KEY") or secrets.token_hex(32),
    DATABASE=os.environ.get("APP_DB", "claimdesk.db"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get("CLAIMDESK_INSECURE_COOKIES") != "1",
    SESSION_COOKIE_SAMESITE="Lax",
)


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
    if user["role"] == "staff" and claim["owner_id"] != user["id"]:
        abort(403)
    return claim


def validate_claim_fields(form):
    """Business rules P4. Returns (clean_values, error)."""
    try:
        amount = Decimal(form.get("amount", ""))
    except (InvalidOperation, ValueError):
        return None, "amount must be a number"
    if not amount.is_finite() or amount <= 0 or amount > MAX_CLAIM:
        return None, "amount must be between 0.01 and 2000.00"
    if amount != amount.quantize(Decimal("0.01")):
        return None, "amount has more than two decimal places"
    try:
        expense_date = date.fromisoformat(form.get("expense_date", ""))
    except ValueError:
        return None, "expense_date must be YYYY-MM-DD"
    if expense_date > date.today():
        return None, "expense_date cannot be in the future"
    description = form.get("description", "").strip()[:200]
    if not description:
        return None, "description is required"
    return {"description": description, "amount": str(amount),
            "expense_date": expense_date.isoformat()}, None


def csv_safe(value):
    """Neutralise spreadsheet formula injection (CWE-1236) in exported cells."""
    text = str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


@app.before_request
def csrf_protect():
    """Synchroniser-token CSRF check on every state-changing request."""
    if request.method == "POST" and request.endpoint != "login":
        token = session.get("csrf")
        if not token or not secrets.compare_digest(token, request.form.get("csrf", "")):
            abort(400)


# ------------------------------------------------------------------ routes
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = get_db().execute("SELECT * FROM users WHERE username = ?",
                                (request.form.get("username", ""),)).fetchone()
        if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
            session.clear()
            session["uid"] = user["id"]
            session["csrf"] = secrets.token_urlsafe(32)
            return redirect(url_for("list_claims"))
        return "invalid credentials", 401
    return "login form"


@app.route("/csrf")
@login_required
def csrf_token():
    return session["csrf"]


@app.route("/claims")
@login_required
def list_claims():
    user = current_user()
    term = f"%{request.args.get('search', '')}%"
    if user["role"] == "staff":
        rows = get_db().execute(
            "SELECT * FROM claims WHERE owner_id = ? AND description LIKE ?",
            (user["id"], term)).fetchall()
    else:
        rows = get_db().execute("SELECT * FROM claims WHERE description LIKE ?",
                                (term,)).fetchall()
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
    user = current_user()
    claim = load_claim_for(user, claim_id)
    if claim["owner_id"] != user["id"]:
        abort(403)
    if claim["status"] != "pending":
        return "only pending claims can be edited", 409
    values, error = validate_claim_fields(request.form)
    if error:
        return error, 400
    db = get_db()
    db.execute("UPDATE claims SET description = ?, amount = ?, expense_date = ? WHERE id = ?",
               (values["description"], values["amount"], values["expense_date"], claim_id))
    db.commit()
    return redirect(url_for("view_claim", claim_id=claim_id))


@app.route("/claims/<int:claim_id>/<any(approve, reject):decision>", methods=["POST"])
@login_required
def decide_claim(claim_id, decision):
    user = current_user()
    claim = load_claim_for(user, claim_id)
    if claim["status"] != "pending":
        return "claim already decided", 409
    db = get_db()
    db.execute("UPDATE claims SET status = ?, approver_id = ? WHERE id = ? AND status = 'pending'",
               ("approved" if decision == "approve" else "rejected", user["id"], claim_id))
    db.commit()
    return redirect(url_for("view_claim", claim_id=claim_id))


@app.route("/claims/export")
@login_required
def export_claims():
    user = current_user()
    query = "SELECT id, description, amount, expense_date, status FROM claims"
    params = ()
    if user["role"] == "staff":
        query += " WHERE owner_id = ?"
        params = (user["id"],)
    out = io.StringIO()
    # nosemgrep: rules.vendor.python.lang.security.use-defusedcsv -- cells are neutralised by csv_safe(); owner: dev lead; review 2027-03-01
    writer = csv.writer(out)
    writer.writerow(["id", "description", "amount", "expense_date", "status"])
    for row in get_db().execute(query, params):
        writer.writerow([csv_safe(v) for v in row])
    return Response(out.getvalue(), mimetype="text/csv")


@app.route("/admin/users")
@role_required("finance")
def admin_users():
    rows = get_db().execute("SELECT id, username, role FROM users").fetchall()
    return "\n".join(f"{r['id']},{r['username']},{r['role']}" for r in rows)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
