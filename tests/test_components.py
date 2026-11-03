import io
import json
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import date

from tests._util import SKILL, make_fixture, read, read_json
from appsec import baseline, cli, dast, manual, osv, sarif, scope, supplychain
from appsec.findings import Finding, Location, compute_fingerprint, finalize, redact, summarize


def run(*argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = cli.main(list(argv))
    return code, buf.getvalue()


def F(rule="R1", path="a.py", line=1, snippet="x = 1", sev="high", status="unverified", cwe=None, src="t"):
    return Finding(rule_id=rule, title=rule, severity=sev, category="c", status=status,
                   location=Location(path, line, line, snippet), cwe=cwe or [], sources=[src])


class FindingsTest(unittest.TestCase):
    def test_fingerprint_stable_across_line_shift(self):
        self.assertEqual(compute_fingerprint(F(line=10)), compute_fingerprint(F(line=99)))
        self.assertNotEqual(compute_fingerprint(F(snippet="a")), compute_fingerprint(F(snippet="b")))

    def test_dedupe_same_location_and_cwe_from_two_tools(self):
        out = finalize([F("A", cwe=["CWE-89"], src="semgrep", sev="medium"),
                        F("B", cwe=["CWE-89"], src="builtin", sev="high")])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].sources, ["builtin", "semgrep"])
        self.assertEqual(out[0].severity, "high")

    def test_identical_lines_get_distinct_fingerprints(self):
        out = finalize([F(line=1), F(line=5)])
        self.assertEqual(len({f.fingerprint for f in out}), 2)

    def test_sorting_and_ids(self):
        out = finalize([F("L", sev="low"), F("C", sev="critical", snippet="y")])
        self.assertEqual([f.severity for f in out], ["critical", "low"])
        self.assertEqual(out[0].id, "AUTO-0001")

    def test_ids_stable_when_new_findings_merge(self):
        first = finalize([F("A", sev="low", snippet="a"), F("B", sev="medium", snippet="b")])
        ids = {f.rule_id: f.id for f in first}
        again = finalize(first + [F("C", sev="critical", snippet="c")])
        self.assertEqual({f.rule_id: f.id for f in again if f.rule_id != "C"}, ids)
        self.assertEqual(next(f.id for f in again if f.rule_id == "C"), "AUTO-0003")

    def test_summary_counts_only_open(self):
        s = summarize([F(status="false-positive"), F(snippet="b"), F(snippet="c", status="missing-control", sev="low")])
        self.assertEqual(s["open_total"], 2)

    def test_redact(self):
        self.assertNotIn("supersecretvalue", redact("supersecretvalue"))
        self.assertEqual(redact("abc"), "***")


class ManualTest(unittest.TestCase):
    TEMPLATE = os.path.join(SKILL, "templates", "manual-findings.template.json")

    def test_template_is_valid(self):
        self.assertEqual(manual.validate(manual.load(self.TEMPLATE)), [])

    def test_invalid_documents(self):
        bad = {"findings": [{"id": "M1", "title": "t", "severity": "huge", "status": "confirmed", "confidence": "high",
                             "location": {"path": "a"}, "evidence": "e", "remediation": "r"}],
               "triage": [{"fingerprint": "x", "status": "false-positive"}],
               "checklist_results": [{"checklist": "a.md", "item": "A-1", "result": "untested"}],
               "bogus": 1}
        errs = "\n".join(manual.validate(bad))
        for needle in ("severity must be", "validation_steps", "written reason", "needs a reason", "unknown top-level key"):
            self.assertIn(needle, errs)

    def test_merge_triage_and_report(self):
        fx, out = make_fixture(), tempfile.mkdtemp()
        try:
            run("scan", "--root", fx, "--out", out, "--offline", "--deterministic")
            auto = read_json(os.path.join(out, "automated-findings.json"))
            target = next(f for f in auto["findings"] if f["rule_id"] == "INJ-OPEN-REDIRECT")
            doc = manual.load(self.TEMPLATE)
            doc["triage"] = [{"fingerprint": target["fingerprint"], "status": "false-positive",
                              "reason": "next is validated by is_safe_url() upstream (test)"}]
            mp = os.path.join(out, "manual.json")
            with open(mp, "w") as fh:
                json.dump(doc, fh)
            code, _ = run("report", "--in", out, "--manual", mp, "--deterministic")
            self.assertEqual(code, 0)
            merged = read_json(os.path.join(out, "findings.json"))
            by_fp = {f["fingerprint"]: f for f in merged["findings"]}
            self.assertEqual(by_fp[target["fingerprint"]]["status"], "false-positive")
            self.assertIn("MAN-001", {f["id"] for f in merged["findings"]})
            self.assertEqual(merged["posture"]["level"], "critical")  # template attack path is critical
            md = read(os.path.join(out, "report.md"))
            for needle in ("AP-1", "Triaged and closed items", "is_safe_url", "Manual checklist results", "```diff"):
                self.assertIn(needle, md)
            # idempotent: running report twice gives identical output
            run("report", "--in", out, "--manual", mp, "--deterministic")
            self.assertEqual(md, read(os.path.join(out, "report.md")))
        finally:
            shutil.rmtree(fx, ignore_errors=True)
            shutil.rmtree(out, ignore_errors=True)


class ContinuousTest(unittest.TestCase):
    def test_diff_and_gate(self):
        base = finalize([F("A", snippet="a"), F("B", snippet="b", sev="low")])
        cur = finalize([F("B", snippet="b", sev="low", line=40), F("C", snippet="c", sev="critical")])
        d = baseline.diff(base, cur)
        self.assertEqual([f.rule_id for f in d["new"]], ["C"])
        self.assertEqual([f.rule_id for f in d["fixed"]], ["A"])
        self.assertEqual([f.rule_id for f in d["unchanged"]], ["B"])
        self.assertEqual(len(baseline.gate(d["new"], "high")), 1)
        self.assertEqual(baseline.gate(d["new"][:0], "high"), [])

    def test_ci_cli_roundtrip(self):
        fx, out = make_fixture(), tempfile.mkdtemp()
        bl = os.path.join(out, "baseline.json")
        try:
            code, _ = run("ci", "--root", fx, "--out", out, "--offline", "--baseline", bl, "--fail-on", "high")
            self.assertEqual(code, 1, "no baseline: everything is new, gate fails")
            self.assertEqual(run("baseline", "--in", out, "--write", bl)[0], 0)
            code, txt = run("ci", "--root", fx, "--out", out, "--offline", "--baseline", bl, "--fail-on", "high")
            self.assertEqual(code, 0, txt)
            self.assertIn("new=0", txt)
            with open(os.path.join(fx, "new_vuln.py"), "w") as fh:
                fh.write("import pickle\n\ndef f(b):\n    return pickle.loads(b)\n")
            code, txt = run("ci", "--root", fx, "--out", out, "--offline", "--baseline", bl, "--fail-on", "high")
            self.assertEqual(code, 1)
            self.assertIn("new=1", txt)
            self.assertIn("DES-PY-PICKLE", read(os.path.join(out, "diff.md")))
        finally:
            shutil.rmtree(fx, ignore_errors=True)
            shutil.rmtree(out, ignore_errors=True)


class ScopeTest(unittest.TestCase):
    SCOPE = {"authorized_by": "owner", "valid_until": "2099-01-01",
             "allowed_activities": ["static", "dast-passive", "dast-active", "poc"],
             "targets": [{"host": "localhost", "ports": [3000], "environment": "local", "activities": ["dast-passive", "dast-active"]},
                         {"host": "staging.example.com", "environment": "staging", "activities": ["dast-passive"]},
                         {"host": "www.example.com", "environment": "production", "activities": ["dast-passive", "dast-active"]}],
             "excluded": ["10.0.0.0/8"]}

    def check(self, target, act, **over):
        s = dict(self.SCOPE, **over)
        return scope.check(s, target, act, today=date(2026, 11, 3))[0]

    def test_allow_and_deny(self):
        self.assertTrue(self.check("http://localhost:3000/", "dast-active"))
        self.assertFalse(self.check("http://localhost:8080/", "dast-active"), "port not in scope")
        self.assertTrue(self.check("https://staging.example.com", "dast-passive"))
        self.assertFalse(self.check("https://staging.example.com", "dast-active"), "activity not allowed for target")
        self.assertFalse(self.check("https://other.example.org", "dast-passive"), "unlisted host")
        self.assertFalse(self.check("http://10.1.2.3", "dast-passive"), "excluded range")
        self.assertFalse(self.check("http://localhost:3000", "dos"), "never allowed")
        self.assertFalse(self.check("http://localhost:3000", "dast-active", valid_until="2026-01-01"), "expired")

    def test_production_rules(self):
        self.assertFalse(self.check("https://www.example.com", "dast-passive"), "needs production_confirmed")
        targets = [dict(t) for t in self.SCOPE["targets"]]
        targets[2]["production_confirmed"] = True
        self.assertTrue(self.check("https://www.example.com", "dast-passive", targets=targets))
        self.assertFalse(self.check("https://www.example.com", "dast-active", targets=targets), "never active in prod")

    def test_cli_exit_codes(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "scope.json")
        with open(p, "w") as fh:
            json.dump(self.SCOPE, fh)
        self.assertEqual(run("scope-check", "--scope", p, "--target", "http://localhost:3000", "--activity", "dast-active")[0], 0)
        self.assertEqual(run("scope-check", "--scope", p, "--target", "http://evil.example", "--activity", "dast-passive")[0], 3)
        self.assertEqual(run("scope-check", "--scope", os.path.join(d, "missing.json"), "--target", "x", "--activity", "static")[0], 3)

    def test_dast_requires_approval(self):
        fx, out = make_fixture(), tempfile.mkdtemp()
        p = os.path.join(out, "scope.json")
        with open(p, "w") as fh:
            json.dump(self.SCOPE, fh)
        try:
            run("scan", "--root", fx, "--out", out, "--offline", "--no-tools")
            code, txt = run("dast", "--scope", p, "--target", "http://localhost:3000", "--out", out)
            self.assertEqual(code, 3)
            self.assertIn("--approved", txt)
            code, _ = run("dast", "--scope", p, "--target", "http://not-in-scope.example", "--out", out, "--approved")
            self.assertEqual(code, 3)
        finally:
            shutil.rmtree(fx, ignore_errors=True)
            shutil.rmtree(out, ignore_errors=True)


class DastAnalysisTest(unittest.TestCase):
    def test_headers(self):
        fs = dast.analyze_headers("https://app.test/", 200, [
            ("Content-Type", "text/html"), ("Server", "nginx/1.18.0"),
            ("Access-Control-Allow-Origin", "*"), ("Access-Control-Allow-Credentials", "true"),
            ("Set-Cookie", "sid=abc123; Path=/")])
        ids = {f.rule_id for f in fs}
        for rid in ("DAST-HSTS-MISSING", "DAST-CSP-MISSING", "DAST-CLICKJACKING", "DAST-VERSION-DISCLOSURE",
                    "DAST-CORS-WILDCARD-CREDS", "DAST-COOKIE-FLAGS"):
            self.assertIn(rid, ids)
        self.assertFalse(any("abc123" in (f.evidence + f.title) for f in fs), "cookie values never reported")

    def test_good_headers(self):
        fs = dast.analyze_headers("https://app.test/", 200, [
            ("Content-Type", "text/html"), ("Strict-Transport-Security", "max-age=63072000"),
            ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
            ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"),
            ("Set-Cookie", "sid=x; Secure; HttpOnly; SameSite=Lax")])
        self.assertEqual(fs, [])


class SarifIngestTest(unittest.TestCase):
    def test_ingest_generic(self):
        doc = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x", "rules": [
            {"id": "py.sqli", "shortDescription": {"text": "SQL injection"},
             "properties": {"tags": ["CWE-89: Improper Neutralization", "security"], "security-severity": "8.1"}}]}},
            "results": [
                {"ruleId": "py.sqli", "level": "error", "message": {"text": "tainted"},
                 "locations": [{"physicalLocation": {"artifactLocation": {"uri": "./.github/x.py"}, "region": {"startLine": 7}}}]},
                {"ruleId": "py.sqli", "suppressions": [{"kind": "inSource"}], "message": {"text": "s"}, "locations": []}]}]}
        d = tempfile.mkdtemp()
        p = os.path.join(d, "x.sarif")
        with open(p, "w") as fh:
            json.dump(doc, fh)
        fs = sarif.ingest(p, "semgrep", d)
        self.assertEqual(len(fs), 1)
        f = fs[0]
        self.assertEqual((f.severity, f.location.path, f.location.start_line), ("high", ".github/x.py", 7))
        self.assertEqual(f.cwe, ["CWE-89"])
        self.assertEqual(f.owasp, ["A03:2021"])
        self.assertEqual(f.rule_id, "semgrep:py.sqli")


class OSVTest(unittest.TestCase):
    def test_collect_and_scan_with_mock(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "requirements.txt"), "w") as fh:
            fh.write("pyyaml==5.3\nflask>=2\n")
        with open(os.path.join(d, "package-lock.json"), "w") as fh:
            json.dump({"lockfileVersion": 3, "packages": {"": {}, "node_modules/lodash": {"version": "4.17.15"}}}, fh)
        files = ["package-lock.json", "requirements.txt"]
        pkgs = osv.collect_packages(d, files)
        self.assertIn(("PyPI", "pyyaml", "5.3", "requirements.txt"), pkgs)
        self.assertIn(("npm", "lodash", "4.17.15", "package-lock.json"), pkgs)
        self.assertEqual(len(pkgs), 2, "unpinned flask must not be queried with a guessed version")

        calls = []

        def fake_http(url, payload=None):
            calls.append(url)
            if url.endswith("/querybatch"):
                return {"results": [{"vulns": [{"id": "GHSA-test-0001"}]} if q["package"]["name"] == "pyyaml" else {}
                                    for q in payload["queries"]]}
            return {"id": "GHSA-test-0001", "summary": "Arbitrary code execution in full_load", "aliases": ["CVE-2020-1747"],
                    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                    "affected": [{"package": {"name": "PyYAML"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "5.3.1"}]}]}]}

        fs, n = osv.scan(d, files, http=fake_http)
        self.assertEqual(n, 2)
        self.assertEqual(len(fs), 1)
        self.assertEqual((fs[0].severity, fs[0].cvss_score), ("critical", 9.8))
        self.assertIn("5.3.1", fs[0].remediation)
        self.assertTrue(all("osv.dev" in c for c in calls))


class SupplyChainTest(unittest.TestCase):
    def test_typosquat(self):
        self.assertEqual(supplychain.typosquat_candidate("reqeusts", "pypi"), "requests")
        self.assertEqual(supplychain.typosquat_candidate("lodahs", "npm"), "lodash")
        self.assertEqual(supplychain.typosquat_candidate("expresss", "npm"), "express")
        self.assertEqual(supplychain.typosquat_candidate("requests", "pypi"), "")
        self.assertEqual(supplychain.typosquat_candidate("python_dateutil", "pypi"), "")
        self.assertEqual(supplychain.typosquat_candidate("fastapi-users", "pypi"), "")

    def test_dependency_tree_install_hooks(self):
        d = tempfile.mkdtemp()
        for name, scripts in (("good", {"test": "jest"}), ("bad", {"postinstall": "node -e \"require('child_process')\""}),
                              ("@scope/hooky", {"install": "node-gyp rebuild"})):
            p = os.path.join(d, "node_modules", name)
            os.makedirs(p)
            with open(os.path.join(p, "package.json"), "w") as fh:
                json.dump({"name": name, "scripts": scripts}, fh)
        fs, n = supplychain.check_dependency_tree(d)
        self.assertEqual(n, 3)
        ids = [f.rule_id for f in fs]
        self.assertEqual(ids.count("SC-DEP-SUSPICIOUS-INSTALL-HOOK"), 1)
        self.assertIn("SC-DEP-INSTALL-HOOKS-SUMMARY", ids)


if __name__ == "__main__":
    unittest.main()
