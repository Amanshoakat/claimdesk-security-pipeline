"""Custom test 1: access-control policy matrix (P1, P2, P3, P7).

One test is generated per row of policy.yaml, so the policy is reviewable by
someone who cannot read Python, and adding a route means adding a row.
Each row asserts on the status code AND on the data: a 403 that has already
leaked the record in the body, or a 200 that silently changed state, fails.
"""
from pathlib import Path

import pytest
import yaml

from conftest import claim_row

POLICY = yaml.safe_load((Path(__file__).parent / "policy.yaml").read_text())["rules"]


@pytest.mark.parametrize("rule", POLICY, ids=[r["id"] for r in POLICY])
def test_access_policy(as_user, db_path, rule):
    client, csrf = as_user(rule["who"])
    data = dict(rule.get("data", {}))
    if rule["method"] == "POST":
        data["csrf"] = csrf
    resp = client.open(rule["path"], method=rule["method"], data=data or None)
    body = resp.get_data(as_text=True)
    label = f'{rule["id"]} {rule["who"]} {rule["method"]} {rule["path"]} ({rule["cwe"]}, {rule["wstg"]})'

    expected = rule["expect"] if isinstance(rule["expect"], list) else [rule["expect"]]
    assert resp.status_code in expected, f"{label}: got {resp.status_code}, policy says {expected}"
    if "forbid_body" in rule:
        assert rule["forbid_body"] not in body, f"{label}: response leaked {rule['forbid_body']!r}"
    if "require_body" in rule:
        assert rule["require_body"] in body, f"{label}: expected {rule['require_body']!r} in response"
    if "then" in rule:
        expect_state = dict(rule["then"])
        row = claim_row(db_path, expect_state.pop("claim"))
        for field, value in expect_state.items():
            assert row[field] == value, f"{label}: claim {field} is {row[field]!r}, policy says {value!r}"
