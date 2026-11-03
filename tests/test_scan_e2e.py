"""End-to-end: scan the generated vulnerable fixture and check outputs."""
import io
import json
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout

from tests._util import SECRETS, make_fixture, read, read_json
from appsec import cli

EXPECTED = {
    "INJ-PY-SQL-STRING", "INJ-PY-SHELL-TRUE", "INJ-PY-SSTI", "INJ-SSRF-PY", "INJ-OPEN-REDIRECT",
    "DES-PY-PICKLE", "DES-PY-YAML-UNSAFE", "INJ-PATH-TRAVERSAL-PY", "CRY-TLS-VERIFY-DISABLED", "CFG-FLASK-DEBUG",
    "CFG-HARDCODED-APP-SECRET", "SEC-AWS-ACCESS-KEY", "SEC-GITHUB-TOKEN", "SEC-CONN-STRING-CREDS",
    "INJ-JS-SQL-STRING", "INJ-JS-CHILD-PROCESS-STRING", "XSS-REFLECTED-SEND", "AUTH-MASS-ASSIGNMENT",
    "AUTH-JWT-DECODE-NO-VERIFY-JS", "AUTH-JWT-HARDCODED-SECRET", "CRY-INSECURE-RANDOM", "INJ-PATH-TRAVERSAL-JS",
    "CFG-CORS-WILDCARD", "CFG-EXPRESS-NO-HELMET", "XSS-DOM-INNERHTML", "SC-OBFUSCATED-EXEC",
    "SC-INSTALL-SCRIPT-SUSPICIOUS", "SC-TYPOSQUAT-CANDIDATE", "SC-DEP-FROM-URL", "SC-WILDCARD-VERSION",
    "SC-NO-LOCKFILE", "SC-PIP-EXTRA-INDEX", "SC-UNPINNED-PY-REQ", "CFG-ENV-FILE-PRESENT",
    "IAC-DOCKER-NO-USER", "IAC-DOCKER-ADD-REMOTE", "IAC-DOCKER-SECRET-IN-LAYER", "IAC-DOCKER-UNPINNED-BASE",
    "SC-CURL-PIPE-SHELL", "IAC-K8S-HOST-NAMESPACE", "IAC-PRIVILEGED-CONTAINER", "IAC-K8S-PRIV-ESCALATION",
    "IAC-K8S-NO-SECURITY-CONTEXT", "IAC-TF-OPEN-INGRESS", "IAC-TF-PUBLIC-BUCKET", "IAC-DB-PUBLICLY-ACCESSIBLE",
    "IAC-ENCRYPTION-DISABLED", "IAC-IMDSV1-ALLOWED", "IAC-HARDCODED-PASSWORD",
    "CI-GHA-PRT-UNTRUSTED-CHECKOUT", "CI-GHA-SCRIPT-INJECTION", "CI-GHA-UNPINNED-ACTION", "CI-GHA-NO-PERMISSIONS",
}


def run(*argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = cli.main(list(argv))
    return code, buf.getvalue()


class ScanE2ETest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fx = make_fixture()
        cls.out = tempfile.mkdtemp(prefix="appsec-out-")
        cls.code, cls.stdout = run("scan", "--root", cls.fx, "--out", cls.out, "--deterministic", "--offline")
        cls.doc = read_json(os.path.join(cls.out, "findings.json"))
        cls.rule_ids = {f["rule_id"] for f in cls.doc["findings"]}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.fx, ignore_errors=True)
        shutil.rmtree(cls.out, ignore_errors=True)

    def test_exit_code_without_gate(self):
        self.assertEqual(self.code, 0)

    def test_expected_detections(self):
        missing = EXPECTED - self.rule_ids
        self.assertFalse(missing, f"missed detections: {sorted(missing)}")

    def test_safe_code_has_no_findings(self):
        safe = [f for f in self.doc["findings"] if f["location"]["path"] == "safe.py"]
        self.assertEqual(safe, [], "false positives on safe.py")

    def test_no_secret_leaks_in_any_output(self):
        for name in os.listdir(self.out):
            p = os.path.join(self.out, name)
            if os.path.isfile(p):
                text = read(p)
                for s in SECRETS:
                    self.assertNotIn(s, text, f"{s[:4]}… leaked in {name}")

    def test_stack_detection(self):
        st = self.doc["stack"]
        for key, val in (("frameworks", "flask"), ("frameworks", "express"), ("iac", "terraform"),
                         ("iac", "kubernetes"), ("containers", "docker"), ("ci", "github-actions"), ("cloud", "aws")):
            self.assertIn(val, st[key])
        self.assertIn("npm", st["missing_lockfiles"])

    def test_coverage_never_silent(self):
        cov = self.doc["coverage"]
        checks = {e["check"]: e for e in cov}
        self.assertIn("semgrep", checks)
        self.assertIn(checks["semgrep"]["status"], ("unavailable", "skipped", "ran", "error"))
        self.assertTrue(all(e["reason"] or e["status"] == "ran" for e in cov), "every non-run entry has a reason")
        self.assertTrue(any(e["kind"] == "manual" for e in cov), "manual-only areas are listed")
        sca = [e for e in cov if e["check"] == "known-vulnerability-lookup"]
        self.assertEqual(sca[0]["status"], "unavailable", "offline run must flag that CVEs were not checked")

    def test_report_contents(self):
        md = read(os.path.join(self.out, "report.md"))
        self.assertIn("does not prove the absence of vulnerabilities", md)
        self.assertIn("## 8. Untested areas and limitations", md)
        self.assertIn("## 9. Prioritized remediation roadmap", md)
        self.assertIn("Risk indicator: HIGH", md)

    def test_sarif_structure(self):
        s = read_json(os.path.join(self.out, "report.sarif"))
        self.assertEqual(s["version"], "2.1.0")
        run0 = s["runs"][0]
        rule_ids = {r["id"] for r in run0["tool"]["driver"]["rules"]}
        for res in run0["results"]:
            self.assertIn(res["ruleId"], rule_ids)
            self.assertIn("appsecFingerprint/v1", res["partialFingerprints"])
            self.assertIn(res["level"], ("error", "warning", "note"))
        for r in run0["tool"]["driver"]["rules"]:
            float(r["properties"]["security-severity"])

    def test_deterministic_output(self):
        out2 = tempfile.mkdtemp(prefix="appsec-out2-")
        try:
            run("scan", "--root", self.fx, "--out", out2, "--deterministic", "--offline")
            for name in ("findings.json", "report.md", "report.sarif", "inventory.json", "activity.log.jsonl"):
                a = read(os.path.join(self.out, name)).replace(self.out, "")
                b = read(os.path.join(out2, name)).replace(out2, "")
                self.assertEqual(a, b, f"{name} differs between identical runs")
        finally:
            shutil.rmtree(out2, ignore_errors=True)

    def test_fail_on_gate(self):
        out2 = tempfile.mkdtemp()
        try:
            code, out = run("scan", "--root", self.fx, "--out", out2, "--offline", "--fail-on", "critical", "--no-tools")
            self.assertEqual(code, 1)
            self.assertIn("GATE FAILED", out)
        finally:
            shutil.rmtree(out2, ignore_errors=True)

    def test_activity_log(self):
        lines = [json.loads(l) for l in read(os.path.join(self.out, "activity.log.jsonl")).splitlines()]
        actions = [l["action"] for l in lines]
        self.assertEqual(actions[0], "scan.start")
        self.assertEqual(actions[-1], "scan.end")
        self.assertIn("rules.pack", actions)

    def test_quick_mode_is_subset(self):
        out2 = tempfile.mkdtemp()
        try:
            run("scan", "--root", self.fx, "--out", out2, "--mode", "quick", "--deterministic", "--offline")
            q = read_json(os.path.join(out2, "findings.json"))
            self.assertLessEqual(len(q["findings"]), len(self.doc["findings"]))
            self.assertTrue({"SEC-AWS-ACCESS-KEY", "INJ-PY-SQL-STRING"} <= {f["rule_id"] for f in q["findings"]})
        finally:
            shutil.rmtree(out2, ignore_errors=True)

    def test_config_exclusions_and_overrides(self):
        os.makedirs(os.path.join(self.fx, ".appsec"), exist_ok=True)
        cfgp = os.path.join(self.fx, ".appsec", "config.json")
        with open(cfgp, "w") as fh:
            json.dump({"exclude": ["infra/*"], "disabled_rules": ["SC-UNPINNED-PY-REQ"],
                       "severity_overrides": {"CI-GHA-UNPINNED-ACTION": "medium"}}, fh)
        out2 = tempfile.mkdtemp()
        try:
            run("scan", "--root", self.fx, "--out", out2, "--deterministic", "--offline")
            d = read_json(os.path.join(out2, "findings.json"))
            self.assertFalse([f for f in d["findings"] if f["location"]["path"].startswith("infra/")])
            self.assertNotIn("SC-UNPINNED-PY-REQ", {f["rule_id"] for f in d["findings"]})
            sev = {f["rule_id"]: f["severity"] for f in d["findings"]}
            self.assertEqual(sev["CI-GHA-UNPINNED-ACTION"], "medium")
        finally:
            os.remove(cfgp)
            shutil.rmtree(out2, ignore_errors=True)

    def test_unknown_config_key_rejected(self):
        os.makedirs(os.path.join(self.fx, ".appsec"), exist_ok=True)
        cfgp = os.path.join(self.fx, ".appsec", "config.json")
        with open(cfgp, "w") as fh:
            json.dump({"fail_onn": "high"}, fh)
        try:
            code, out = run("scan", "--root", self.fx, "--out", tempfile.mkdtemp(), "--offline")
            self.assertEqual(code, 2)
            self.assertIn("unknown config keys", out)
        finally:
            os.remove(cfgp)


if __name__ == "__main__":
    unittest.main()
