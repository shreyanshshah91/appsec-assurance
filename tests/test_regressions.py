"""Regression tests for issues found in the independent code review (v1.0.1)."""
import io
import json
import os
import shutil
import tempfile
import time
import unittest
from contextlib import redirect_stdout

from tests._util import read, read_json
from appsec import cli, config, dast, manual, rules, sarif, scope, supplychain
from appsec.engine import BUILTIN_RULES
from appsec.findings import Finding, Location, finalize
from appsec.walker import walk

PACKS, _ = rules.load_packs([BUILTIN_RULES])
ALL = {r.id: r for rs in PACKS.values() for r in rs}
AWS1, AWS2 = "AKIA" + "QWERTYUIOPASDFGH", "AKIA" + "ZXCVBNMLKJHGFDSA"
GH = "ghp_" + "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ12"


def run(*argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = cli.main(list(argv))
    return code, buf.getvalue()


def tree(files):
    d = tempfile.mkdtemp(prefix="appsec-reg-")
    for rel, content in files.items():
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb" if isinstance(content, bytes) else "w") as fh:
            fh.write(content)
    return d


def scan(files, *extra):
    d, out = tree(files), tempfile.mkdtemp()
    code, txt = run("scan", "--root", d, "--out", out, "--offline", "--no-tools", "--deterministic", *extra)
    return d, out, code, txt


class SecretLeakTest(unittest.TestCase):
    def test_multiple_secrets_on_one_line_all_redacted(self):
        d, out, _, _ = scan({"app.py": f'cfg = {{"aws": "{AWS1}", "gh": "{GH}"}}\nkeys = "{AWS1} {AWS2}"\n'})
        for name in ("findings.json", "report.md", "report.sarif", "inventory.json"):
            text = read(os.path.join(out, name))
            for s in (AWS1, AWS2, GH):
                self.assertNotIn(s, text, f"{s[:4]} leaked in {name}")
        ids = [f["rule_id"] for f in read_json(os.path.join(out, "findings.json"))["findings"]]
        self.assertIn("SEC-GITHUB-TOKEN", ids, "second secret type on the line must be its own finding")

    def test_secret_crossing_truncation_boundary(self):
        line = "x = '" + "a" * 290 + "' ; os.system(cmd) ; k = '" + GH + "'\n"
        d, out, _, _ = scan({"app.py": line})
        self.assertNotIn(GH[:12], read(os.path.join(out, "findings.json")))

    def test_external_sast_snippets_redacted(self):
        d = tempfile.mkdtemp()
        doc = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "semgrep", "rules": [
            {"id": "generic.secrets.aws", "properties": {"tags": ["CWE-798: Hard-coded Credentials"]}}]}}, "results": [
            {"ruleId": "generic.secrets.aws", "message": {"text": "Possible hardcoded password: 'Tr0ub4dor&3xyz'"},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/my%20dir/conf.py"},
                                                 "region": {"startLine": 3, "snippet": {"text": f'aws_key = "{AWS1}"'}}}}]}]}]}
        p = os.path.join(d, "s.sarif")
        with open(p, "w") as fh:
            json.dump(doc, fh)
        f = sarif.ingest(p, "semgrep", d)[0]
        blob = f.location.snippet + f.evidence + f.title
        self.assertNotIn(AWS1, blob)
        self.assertNotIn("Tr0ub4dor&3xyz", blob)
        self.assertEqual(f.category, "secrets")
        self.assertEqual(f.location.path, "src/my dir/conf.py")


class TriageAndMergeTest(unittest.TestCase):
    def test_id_only_triage_requires_matching_rule(self):
        fs = finalize([Finding("INJ-PHP-CMD-SUPERGLOBAL", "cmd", "critical", "injection", Location("a.php", 1, 1, "x"))])
        doc = {"triage": [{"id": fs[0].id, "status": "false-positive", "reason": "was the SQLi last run"}]}
        self.assertTrue(manual.validate(doc), "id without rule_id is rejected by validation")
        out, warns = manual.apply_triage(fs, {"triage": [{"id": fs[0].id, "rule_id": "INJ-PY-SQL-STRING",
                                                          "status": "false-positive", "reason": "r"}]})
        self.assertEqual(out[0].status, "unverified", "mismatched rule must not be triaged")
        self.assertTrue(warns)

    def test_manual_finding_not_swallowed_by_automated(self):
        auto = Finding("INJ-PY-SQL-STRING", "sqli", "high", "injection", Location("app.py", 2, 2, "q"),
                       cwe=["CWE-89"], sources=["builtin:injection"])
        man = Finding("MANUAL-MAN-001", "confirmed sqli", "critical", "injection", Location("app.py", 2, 2, ""),
                      status="confirmed", cwe=["CWE-89"], sources=["manual-review"], id="MAN-001",
                      validation_steps=["step"])
        out = finalize([auto, man])
        self.assertIn("MAN-001", {f.id for f in out})
        self.assertEqual(len(out), 2)

    def test_two_builtin_rules_same_line_not_merged(self):
        a = Finding("SEC-AWS-ACCESS-KEY", "aws", "high", "secrets", Location("a.py", 1, 1, "a"), cwe=["CWE-798"], sources=["builtin:secrets"])
        b = Finding("SEC-GITHUB-TOKEN", "gh", "high", "secrets", Location("a.py", 1, 1, "a"), cwe=["CWE-798"], sources=["builtin:secrets"])
        self.assertEqual(len(finalize([a, b])), 2)


class ScopeHardeningTest(unittest.TestCase):
    SC = {"authorized_by": "o", "allowed_activities": ["dast-passive"],
          "targets": [{"host": "*.example.com", "environment": "staging", "activities": ["dast-passive"]},
                      {"host": "shop.example.org", "environment": "Production", "activities": ["dast-passive"]}],
          "excluded": ["http://admin.example.com/*"]}

    def test_exclusion_bypasses_denied(self):
        for t in ("HTTP://admin.example.com/x", "http://ADMIN.example.com/x", "http://admin.example.com:80/x",
                  "http://u@admin.example.com/x", "http://admin.example.com./x"):
            self.assertFalse(scope.check(self.SC, t, "dast-passive")[0], t)
        self.assertTrue(scope.check(self.SC, "http://www.example.com/", "dast-passive")[0])

    def test_production_spelling(self):
        self.assertFalse(scope.check(self.SC, "http://shop.example.org/", "dast-passive")[0])
        for env in ("prod", "PRODUCTION", "live", "unknown"):
            self.assertEqual(scope.environment_class(env), "production")
        self.assertEqual(scope.environment_class("Staging"), "non-production")

    def test_malformed_input_denied_not_crash(self):
        for t in ("http://localhost:abc/", "http://[::1"):
            self.assertFalse(scope.check(self.SC, t, "dast-passive")[0])
        self.assertFalse(scope.check(dict(self.SC, valid_until=20991231), "http://www.example.com", "dast-passive")[0] is None)

    def test_dast_target_normalized(self):
        self.assertEqual(scope.normalize_target("127.0.0.1:8765"), "http://127.0.0.1:8765/")
        with self.assertRaises(ValueError):
            scope.normalize_target("http://admin:pw@host/")
        fs = dast.analyze_headers("HTTPS://app.test/", 200, [("Content-Type", "text/html")])
        self.assertIn("DAST-HSTS-MISSING", {f.rule_id for f in fs})


class ConfigAndEngineTest(unittest.TestCase):
    def test_bad_severity_override_rejected(self):
        d = tree({".appsec/config.json": json.dumps({"severity_overrides": {"INJ-PY-SQL-STRING": "crit"}})})
        with self.assertRaises(SystemExit):
            config.load(d)
        d = tree({".appsec/config.json": json.dumps({"max_file_size_kb": "1MB"})})
        with self.assertRaises(SystemExit):
            config.load(d)

    def test_out_dir_inside_root_not_rescanned(self):
        d = tree({"app.py": "import os\nos.system(cmd)\n"})
        out = os.path.join(d, "security-report")
        counts = []
        for _ in range(3):
            run("scan", "--root", d, "--out", out, "--offline", "--no-tools", "--deterministic")
            counts.append(len(read_json(os.path.join(out, "findings.json"))["findings"]))
        self.assertEqual(len(set(counts)), 1, counts)

    def test_tools_flag(self):
        d, out = tree({"a.py": "x=1\n"}), tempfile.mkdtemp()
        code, txt = run("scan", "--root", d, "--out", out, "--offline", "--tools", "bogus")
        self.assertEqual(code, 2)
        run("scan", "--root", d, "--out", out, "--offline", "--mode", "quick", "--tools", "bandit")
        cov = read_json(os.path.join(out, "coverage.json"))
        bandit = next(e for e in cov if e["check"] == "bandit")
        self.assertNotIn("mode profile", bandit["reason"], "--tools must override the mode profile")
        self.assertGreaterEqual(sum(1 for e in cov if e["kind"] == "tool"), 13, "unselected tools still recorded")


class ParsingTest(unittest.TestCase):
    def test_line_numbers_with_form_feed_and_u2028(self):
        d, out, _, _ = scan({"a.py": "import os\n\f\n\f\nos.system(c)\n", "b.js": "var s = ' ';\n\neval(x)\n"})
        lines = {f["location"]["path"]: f["location"]["start_line"] for f in read_json(os.path.join(out, "findings.json"))["findings"]}
        self.assertEqual(lines["a.py"], 4)
        self.assertEqual(lines["b.js"], 3)

    def test_bom_and_utf16_and_brackets(self):
        pj = b"\xef\xbb\xbf" + json.dumps({"dependencies": {"expresss": "1.0.0"}}).encode()
        ps1 = "﻿Invoke-Expression (FromBase64String($p))\n".encode("utf-16")
        d = tree({"package.json": pj, "x.ps1": ps1})
        base = tempfile.mkdtemp()
        weird = os.path.join(base, "proj[1]")
        shutil.copytree(d, weird)
        os.makedirs(os.path.join(weird, ".appsec", "rules"))
        with open(os.path.join(weird, ".appsec", "rules", "c.json"), "w") as fh:
            json.dump({"pack": "custom", "rules": [{"id": "CUST-1", "title": "t", "severity": "low", "confidence": "high",
                       "category": "c", "files": ["*.json"], "pattern": "expresss", "remediation": "remove this package",
                       "cwe": ["CWE-829"], "owasp": ["A08:2021"]}]}, fh)
        with open(os.path.join(weird, ".appsec", "config.json"), "w") as fh:
            json.dump({"custom_rule_dirs": [".appsec/rules"]}, fh)
        out = tempfile.mkdtemp()
        run("scan", "--root", weird, "--out", out, "--offline", "--no-tools")
        ids = {f["rule_id"] for f in read_json(os.path.join(out, "findings.json"))["findings"]}
        self.assertIn("SC-TYPOSQUAT-CANDIDATE", ids, "BOM-prefixed package.json must parse")
        self.assertIn("CUST-1", ids, "custom packs load from paths containing brackets")
        self.assertIn("SC-OBFUSCATED-EXEC", ids, "UTF-16 script must be scanned")

    def test_empty_file_with_permissive_file_rule(self):
        r = rules.Rule({"id": "X-EMPTY", "title": "t", "severity": "low", "confidence": "high", "category": "c",
                        "files": ["*"], "kind": "file", "all_of": ["^"], "remediation": "r"}, "p")
        fs, errs = rules.run(tree({"empty.txt": ""}), ["empty.txt"], [r])
        self.assertEqual(len(fs), 1)

    @unittest.skipIf(os.name == "nt" or os.geteuid() == 0, "needs POSIX non-root permissions")
    def test_unreadable_directory_recorded(self):
        d = tree({"ok.py": "x=1\n", "locked/a.py": "x=1\n"})
        os.chmod(os.path.join(d, "locked"), 0)
        try:
            files, skipped = walk(d, [], 1024)
            self.assertIn("locked", [s[0] for s in skipped])
        finally:
            os.chmod(os.path.join(d, "locked"), 0o755)

    def test_sarif_suppression_status_and_rule_index(self):
        d = tempfile.mkdtemp()
        doc = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "t", "rules": [
            {"id": "r0", "properties": {"tags": ["misconfiguration"]}}]}}, "results": [
            {"ruleIndex": 0, "message": {"text": "m"}, "suppressions": [{"kind": "external", "status": "rejected"}],
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "Dockerfile"}, "region": {"startLine": 1}}}]}]}]}
        p = os.path.join(d, "t.sarif")
        with open(p, "w") as fh:
            json.dump(doc, fh)
        fs = sarif.ingest(p, "trivy", d)
        self.assertEqual(len(fs), 1, "rejected suppression still reported")
        self.assertEqual(fs[0].rule_id, "trivy:r0")
        self.assertEqual(fs[0].category, "iac")


class RuleQualityTest(unittest.TestCase):
    def one(self, rid, fname, line):
        return len(ALL[rid].scan(fname, line + "\n")) if rid in ALL else None

    def test_gha_injection_forms(self):
        f = ".github/workflows/x.yml"
        self.assertEqual(self.one("CI-GHA-SCRIPT-INJECTION", f, "        run: ${{ github.event.issue.title }}"), 1)
        self.assertEqual(self.one("CI-GHA-SCRIPT-INJECTION", f, "          script: ${{ github.event.comment.body }}"), 1)
        self.assertEqual(self.one("CI-GHA-SCRIPT-INJECTION", f, "          TITLE: ${{ github.event.issue.title }}"), 0)

    def test_generic_secret_regex_is_linear(self):
        r = ALL["SEC-GENERIC-ASSIGNMENT"]
        line = ".".join(["e"] * 1995)
        t = time.perf_counter()
        r.scan("a.cfg", line + "\n")
        self.assertLess(time.perf_counter() - t, 0.05)

    def test_false_positive_fixes(self):
        self.assertEqual(self.one("SC-DEP-FROM-URL", "package.json", '  "homepage": "https://example.com",'), 0)
        self.assertEqual(self.one("SC-DEP-FROM-URL", "package.json", '    "url": "git+https://github.com/a/b.git"'), 0)
        self.assertEqual(self.one("SC-DEP-FROM-URL", "package.json", '    "left-pad": "git+https://github.com/a/b.git",'), 1)
        self.assertEqual(self.one("CRY-WEAK-PASSWORD-HASH", "a.py", "h = hashlib.sha256(file_bytes)  # passes integrity check"), 0)
        self.assertEqual(self.one("CRY-WEAK-PASSWORD-HASH", "a.py", "h = hashlib.md5(password.encode())"), 1)
        self.assertEqual(self.one("INJ-JS-CHILD-PROCESS-STRING", "a.js", "const m = re.exec(prefix + s)"), 0)
        self.assertEqual(self.one("INJ-JS-CHILD-PROCESS-STRING", "a.js", "exec('ls ' + dir)"), 1)

    def test_docker_base_structural(self):
        d = tree({"Dockerfile": "FROM node:20 AS build\nFROM build AS test\nFROM registry.local:5000/team/app\n"
                                "FROM alpine@sha256:abc\nFROM python:latest\nFROM scratch\n"})
        fs = supplychain.check_docker_base_images(d, ["Dockerfile"])
        self.assertEqual(sorted(f.location.start_line for f in fs), [3, 5])

    def test_typosquat_known_good(self):
        for name, eco in (("preact", "npm"), ("pug", "npm"), ("vuex", "npm"), ("ms", "npm"), ("scapy", "pypi"), ("boto", "pypi")):
            self.assertEqual(supplychain.typosquat_candidate(name, eco), "", name)


if __name__ == "__main__":
    unittest.main()
