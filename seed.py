"""Create and seed a throwaway ClaimDesk database.

Usage: APP_DB=/tmp/test.db python seed.py
The passwords below are fixtures for a local test database only. They are
not credentials for any real system.
"""
import os
import sqlite3
import sys

from werkzeug.security import generate_password_hash

SCHEMA = """
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS claims;
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('staff', 'manager', 'finance'))
);
CREATE TABLE claims (
    id INTEGER PRIMARY KEY,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    description TEXT NOT NULL,
    amount TEXT NOT NULL,
    expense_date TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    approver_id INTEGER REFERENCES users(id)
);
"""

# username, fixture password, role
USERS = [
    ("alice", "fixture-alice", "staff"),     # id 1
    ("bob", "fixture-bob", "staff"),         # id 2
    ("mia", "fixture-mia", "manager"),       # id 3
    ("fin", "fixture-fin", "finance"),       # id 4
]

# owner_id, description, amount, expense_date, status
CLAIMS = [
    (1, "ALICE-PRIVATE taxi to client", "42.50", "2026-10-01", "pending"),     # id 1
    (2, "BOB-PRIVATE hotel Cork", "180.00", "2026-10-03", "pending"),          # id 2
    (3, "MIA-PRIVATE conference fee", "350.00", "2026-10-05", "pending"),      # id 3
    (1, "ALICE-PRIVATE approved lunch", "18.00", "2026-09-20", "approved"),    # id 4
]


def seed(path):
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    con.executemany("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                    [(u, generate_password_hash(p), r) for u, p, r in USERS])
    con.executemany("INSERT INTO claims (owner_id, description, amount, expense_date, status) "
                    "VALUES (?, ?, ?, ?, ?)", CLAIMS)
    con.commit()
    con.close()


if __name__ == "__main__":
    seed(os.environ.get("APP_DB", sys.argv[1] if len(sys.argv) > 1 else "claimdesk.db"))
