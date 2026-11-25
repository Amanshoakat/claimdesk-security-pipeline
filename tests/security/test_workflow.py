"""Custom test 3: workflow integrity (P5). CWE-841, WSTG-BUSL-06.

A claim moves pending -> approved | rejected exactly once. Once decided it
cannot be edited or re-decided, and the approver is recorded by the system.
"""
from conftest import claim_row


def test_approved_claim_cannot_be_edited(as_user, db_path):
    """WF-01: the owner cannot change an approved claim (claim 4)."""
    client, csrf = as_user("alice")
    before = claim_row(db_path, 4)
    resp = client.post("/claims/4/edit", data={"description": "changed after approval",
                                               "amount": "1999.00", "expense_date": "2026-09-20",
                                               "csrf": csrf})
    assert resp.status_code == 409, f"WF-01 edit of approved claim returned {resp.status_code}"
    assert claim_row(db_path, 4) == before, "WF-01 approved claim was modified"


def test_decided_claim_cannot_be_redecided(as_user, db_path):
    """WF-02: approve then reject must not flip the outcome."""
    client, csrf = as_user("mia")
    assert client.post("/claims/1/approve", data={"csrf": csrf}).status_code == 302
    resp = client.post("/claims/1/reject", data={"csrf": csrf})
    assert resp.status_code == 409, f"WF-02 re-decision returned {resp.status_code}"
    assert claim_row(db_path, 1)["status"] == "approved"


def test_approver_is_recorded(as_user, db_path):
    """WF-03: the audit field records who approved, set by the server."""
    client, csrf = as_user("mia")
    client.post("/claims/2/approve", data={"csrf": csrf})
    assert claim_row(db_path, 2)["approver_id"] == 3
