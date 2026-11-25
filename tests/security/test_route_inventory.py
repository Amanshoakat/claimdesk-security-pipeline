"""Custom test 4: route inventory (added after demo D5 was missed).

The policy matrix only protects routes that have a row in policy.yaml. A new
route with no row is invisible to every other test. This test enumerates the
application's real URL map and fails if any route has no policy decision, so
"adding a route means adding a row" is enforced rather than hoped for.
It proves a decision was written down, not that the decision is right.
"""
from pathlib import Path

import yaml
from werkzeug.exceptions import MethodNotAllowed, NotFound

from app import app

POLICY = yaml.safe_load((Path(__file__).parent / "policy.yaml").read_text())["rules"]
# Routes that are deliberately public or infrastructure, with the reason.
EXEMPT = {
    "static": "Flask static files, no data",
    "login": "must be reachable before authentication",
    "csrf_token": "returns the caller's own CSRF token only",
}


def covered_endpoints():
    adapter = app.url_map.bind("localhost")
    covered = set()
    for rule in POLICY:
        path = rule["path"].split("?")[0]
        try:
            endpoint, _ = adapter.match(path, method=rule["method"])
        except (NotFound, MethodNotAllowed):
            continue
        covered.add(endpoint)
    return covered


def test_every_route_has_a_policy_row():
    """RI-01: every endpoint is either exempt (with a reason) or in policy.yaml."""
    missing = sorted({r.endpoint for r in app.url_map.iter_rules()}
                     - set(EXEMPT) - covered_endpoints())
    assert not missing, f"RI-01 routes with no access-control policy row: {missing}"
