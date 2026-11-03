"""Regenerate examples/sample-assessment/ from the vulnerable fixture.

Shows the full loop: automated scan -> analyst review file (triage, manual
finding, attack path, checklist results) -> merged report.

    python3 examples/generate.py
"""

import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "skills", "appsec-assurance", "scripts"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures"))

import build_fixture  # noqa: E402
from appsec import cli  # noqa: E402

DEST = os.path.join(ROOT, "examples", "sample-assessment")


def fp(doc, rule_id, path=None):
    for f in doc["findings"]:
        if f["rule_id"] == rule_id and (path is None or f["location"]["path"] == path):
            return f
    raise KeyError(rule_id)


def main() -> int:
    tmp = tempfile.mkdtemp()
    target = build_fixture.build(os.path.join(tmp, "vulnerable-fixture"))
    out = os.path.join(tmp, "out")
    cli.main(["scan", "--root", target, "--out", out, "--offline", "--deterministic", "--no-tools"])
    with open(os.path.join(out, "automated-findings.json"), encoding="utf-8") as fh:
        auto = json.load(fh)

    ssrf, imds = fp(auto, "INJ-SSRF-PY"), fp(auto, "IAC-IMDSV1-ALLOWED")
    sqli, pickle_ = fp(auto, "INJ-PY-SQL-STRING"), fp(auto, "DES-PY-PICKLE")
    hooks = fp(auto, "SC-INSTALL-SCRIPT")
    review = {
        "schema_version": "1",
        "assessors": ["Claude Code (appsec-assurance skill) - example run"],
        "executive_summary": (
            "This sample application is not fit for deployment. Unauthenticated users can execute code on the "
            "server (unsafe deserialization, command injection), read the database (SQL injection), and pivot from "
            "an SSRF flaw to cloud credentials because the instance allows IMDSv1. The CI workflow lets anyone who "
            "opens a pull request run code with repository secrets. Fix the five immediate items first, rotate every "
            "credential found in the repository, then address the infrastructure exposure."),
        "posture_statement": (
            "Critical. Multiple independent pre-authentication code-execution paths were confirmed by static tracing, "
            "and no authentication layer exists on any HTTP route. Runtime testing was not performed."),
        "findings": [{
            "id": "MAN-001",
            "title": "No authentication or authorization on any HTTP route",
            "severity": "high", "status": "missing-control", "confidence": "high", "category": "authorization",
            "cwe": ["CWE-306", "CWE-862"], "owasp": ["A01:2021", "A07:2021", "API2:2023"],
            "location": {"path": "app.py", "start_line": 16, "end_line": 60},
            "description": "All ten Flask routes and all Express routes are reachable without a session or token; there is no auth middleware, decorator or gateway configuration in the repository.",
            "evidence": "app.py defines @app.route handlers with no login_required/before_request hook; server.js mounts handlers directly on `app` with no auth middleware; no gateway/ingress auth config present.",
            "impact": "Every other weakness is reachable by anonymous internet users, raising each to its pre-auth severity.",
            "remediation": "Introduce a default-deny authentication layer (before_request hook / Express middleware mounted before routes), then per-route authorization checks; add a test that enumerates routes and asserts 401 without credentials.",
            "regression_test": "def test_all_routes_require_auth(client):\n    for rule in app.url_map.iter_rules():\n        if rule.endpoint == 'static':\n            continue\n        assert client.get(rule.rule).status_code in (401, 403)",
        }],
        "triage": [
            {"fingerprint": sqli["fingerprint"], "status": "confirmed", "confidence": "high",
             "reason": "Traced: request.args['id'] (app.py:17) -> f-string -> conn.execute (app.py:19); no validation or parameterization on the path."},
            {"fingerprint": pickle_["fingerprint"], "status": "confirmed", "severity": "critical", "confidence": "high",
             "reason": "request.data passed straight to pickle.loads on an unauthenticated POST route: pre-auth RCE by construction."},
            {"fingerprint": ssrf["fingerprint"], "status": "confirmed", "confidence": "high",
             "reason": "request.args['url'] reaches requests.get with no scheme/host allowlist; see AP-1."},
            {"fingerprint": hooks["fingerprint"], "status": "accepted-risk",
             "reason": "Informational duplicate of SC-INSTALL-SCRIPT-SUSPICIOUS for the same line; tracked there. (Example of a recorded decision.)"},
        ],
        "attack_paths": [{
            "id": "AP-1", "title": "Anonymous SSRF to AWS credential theft", "severity": "critical",
            "steps": [ssrf["id"], imds["id"], "MAN-001"],
            "narrative": "GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/<role> is fetched server-side (app.py:35). Terraform allows IMDSv1 (infra/main.tf:25), so no session token is required and the role's temporary credentials are returned to the attacker. No authentication protects the route (MAN-001). Not validated at runtime; static chain only."}],
        "checklist_results": [
            {"checklist": "authorization.md", "item": "AUTHZ-01", "result": "fail", "notes": "See MAN-001"},
            {"checklist": "injection.md", "item": "INJ-01", "result": "fail", "notes": "SQL injection confirmed"},
            {"checklist": "ssrf-and-outbound.md", "item": "SSRF-01", "result": "fail", "notes": "See AP-1"},
            {"checklist": "business-logic-and-race-conditions.md", "item": "BIZ-01", "result": "n/a", "notes": "No stateful business workflows in the sample"},
            {"checklist": "mobile.md", "item": "MOB-01", "result": "n/a", "notes": "No mobile client"},
            {"checklist": "logging-monitoring-and-audit.md", "item": "LOG-01", "result": "untested", "notes": "Logging config lives outside the repository"},
        ],
        "limitations": [
            "No running instance was available; all results are from static analysis (no runtime validation performed).",
            "External scanners were not installed in the example run; dependency CVEs were not checked.",
        ],
    }
    manual_path = os.path.join(out, "manual-findings.json")
    with open(manual_path, "w", encoding="utf-8") as fh:
        json.dump(review, fh, indent=2)
        fh.write("\n")
    if cli.main(["report", "--in", out, "--manual", manual_path, "--deterministic"]) != 0:
        return 1

    if os.path.isdir(DEST):
        shutil.rmtree(DEST)
    os.makedirs(DEST)
    for name in ("report.md", "findings.json", "report.sarif", "coverage.json", "inventory.json",
                 "stack.json", "activity.log.jsonl", "manual-findings.json"):
        shutil.copy(os.path.join(out, name), os.path.join(DEST, name))
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"wrote {DEST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
