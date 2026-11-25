"""Shared fixtures: every test gets a fresh, seeded throwaway database.

Deterministic by design: no network, no dependence on test order, and the
only clock dependency (future-date rule) is computed relative to today.
"""
import os
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import seed  # noqa: E402
from app import app as flask_app  # noqa: E402

PASSWORDS = {u: p for u, p, _ in seed.USERS}


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "test.db"
    seed.seed(str(path))
    return path


@pytest.fixture
def app(db_path):
    flask_app.config.update(TESTING=True, DATABASE=str(db_path),
                            SESSION_COOKIE_SECURE=False)
    return flask_app


def login(client, who):
    """Log in as a seeded user and return the CSRF token (empty if the app has none)."""
    if who == "anon":
        return ""
    resp = client.post("/login", data={"username": who, "password": PASSWORDS[who]})
    assert resp.status_code == 302, f"login failed for {who}"
    token = client.get("/csrf")
    return token.get_data(as_text=True) if token.status_code == 200 else ""


@pytest.fixture
def as_user(app):
    """Factory: as_user('alice') -> (client, csrf_token)."""
    def make(who):
        client = app.test_client()
        return client, login(client, who)
    return make


def claim_row(db_path, claim_id):
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    row = con.execute("SELECT * FROM claims WHERE id = ?", (claim_id,)).fetchone()
    con.close()
    return dict(row) if row else None


def claim_count(db_path):
    con = sqlite3.connect(db_path)
    n = con.execute("SELECT COUNT(*) FROM claims").fetchone()[0]
    con.close()
    return n
