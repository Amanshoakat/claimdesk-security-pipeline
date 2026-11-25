"""Custom test 2: business-rule validation and field-level authorisation.

Property-based (Hypothesis): rather than two or three hand-picked values, each
property is checked against many generated amounts, dates and field names,
including edge cases (0, 0.001, 2000.01, NaN, Infinity, huge exponents).

  P4  amount in (0, 2000.00], at most 2 decimals; date not in the future
      CWE-840 Business Logic Errors, WSTG-BUSL-01
  P6  status, owner_id and approver_id cannot be set by the client
      CWE-915 Improperly Controlled Modification of Object Attributes
"""
from datetime import date, timedelta
from decimal import Decimal

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from conftest import claim_count, claim_row

SETTINGS = settings(max_examples=60, deadline=None, derandomize=True,
                    suppress_health_check=[HealthCheck.function_scoped_fixture])
TODAY = date.today()

out_of_range = st.one_of(
    st.decimals(max_value=Decimal("0"), allow_nan=False, allow_infinity=False, places=2),
    st.decimals(min_value=Decimal("2000.01"), allow_nan=False, allow_infinity=False, places=2),
    st.decimals(min_value=Decimal("0.001"), max_value=Decimal("1999.999"), places=3)
      .filter(lambda d: d != d.quantize(Decimal("0.01"))),
    st.sampled_from(["NaN", "Infinity", "-Infinity", "1e9", "-0", "", "abc"]),
)
in_range = st.decimals(min_value=Decimal("0.01"), max_value=Decimal("2000.00"), places=2)


def submit(client, csrf, amount, expense_date=TODAY - timedelta(days=1), **extra):
    data = {"description": "generated claim", "amount": str(amount),
            "expense_date": expense_date.isoformat(), "csrf": csrf, **extra}
    return client.post("/claims/new", data=data)


@SETTINGS
@given(amount=out_of_range)
def test_invalid_amount_is_refused(as_user, db_path, amount):
    """BR-01: well-formed but wrong amounts never create a claim."""
    client, csrf = as_user("alice")
    before = claim_count(db_path)
    resp = submit(client, csrf, amount)
    assert resp.status_code == 400, f"BR-01 amount {amount!r} accepted with {resp.status_code}"
    assert claim_count(db_path) == before, f"BR-01 amount {amount!r} created a claim"


@SETTINGS
@given(amount=in_range)
def test_valid_amount_is_accepted(as_user, db_path, amount):
    """BR-02: control case, so the rule is not passing by refusing everything."""
    client, csrf = as_user("alice")
    before = claim_count(db_path)
    resp = submit(client, csrf, amount)
    assert resp.status_code == 302, f"BR-02 valid amount {amount} refused"
    assert claim_count(db_path) == before + 1


@SETTINGS
@given(days_ahead=st.integers(min_value=1, max_value=3650))
def test_future_dated_claim_is_refused(as_user, db_path, days_ahead):
    """BR-03: an expense cannot be dated in the future."""
    client, csrf = as_user("alice")
    before = claim_count(db_path)
    resp = submit(client, csrf, "10.00", TODAY + timedelta(days=days_ahead))
    assert resp.status_code == 400, f"BR-03 date +{days_ahead}d accepted"
    assert claim_count(db_path) == before


@SETTINGS
@given(field=st.sampled_from(["status", "owner_id", "approver_id"]),
       value=st.sampled_from(["approved", "rejected", "2", "3", "4"]))
def test_protected_fields_cannot_be_set_by_client(as_user, db_path, field, value):
    """BR-04: extra fields in an edit request are ignored (mass assignment)."""
    client, csrf = as_user("alice")
    before = claim_row(db_path, 1)
    client.post("/claims/1/edit", data={"description": "ALICE-PRIVATE taxi to client",
                                        "amount": "42.50", "expense_date": "2026-10-01",
                                        "csrf": csrf, field: value})
    after = claim_row(db_path, 1)
    for protected in ("status", "owner_id", "approver_id"):
        assert after[protected] == before[protected], (
            f"BR-04 client set {protected} to {after[protected]!r} via field {field}={value!r}")
