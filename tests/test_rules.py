"""Rule pack integrity plus per-rule positive/negative samples."""
import unittest

from tests._util import SKILL  # noqa: F401
from appsec import engine, rules
from appsec.findings import SEVERITIES

PACKS, ERRORS = rules.load_packs([engine.BUILTIN_RULES])
ALL = {r.id: r for rs in PACKS.values() for r in rs}

# (rule_id, filename, line that MUST match, line that must NOT match)
SAMPLES = [
    ("INJ-PY-SQL-STRING", "a.py", 'cur.execute(f"SELECT * FROM t WHERE id={uid}")', 'cur.execute("SELECT * FROM t WHERE id=?", (uid,))'),
    ("INJ-JS-SQL-STRING", "a.js", "db.query(`SELECT * FROM t WHERE id=${id}`)", "db.query('SELECT * FROM t WHERE id=$1', [id])"),
    ("INJ-GO-SQL-SPRINTF", "a.go", 'db.Query(fmt.Sprintf("SELECT * FROM t WHERE id=%s", id))', 'db.Query("SELECT * FROM t WHERE id=$1", id)'),
    ("INJ-JAVA-SQL-CONCAT", "A.java", 'stmt.executeQuery("SELECT * FROM t WHERE id=" + id);', 'ps = conn.prepareStatement("SELECT * FROM t WHERE id=?");'),
    ("INJ-PY-SHELL-TRUE", "a.py", "subprocess.run(cmd, shell=True)", 'subprocess.run(["ls", path])'),
    ("INJ-PY-EVAL", "a.py", "eval(user_input)", "ast.literal_eval(user_input)"),
    ("INJ-GO-EXEC-SHELL", "a.go", 'exec.Command("sh", "-c", cmd)', 'exec.Command("ls", "-l", dir)'),
    ("INJ-SSRF-JS", "a.js", "const r = await fetch(req.query.url)", "const r = await fetch(API_URL)"),
    ("XSS-ANGULAR-BYPASS", "a.ts", "this.s.bypassSecurityTrustHtml(v)", "this.s.sanitize(SecurityContext.HTML, v)"),
    ("XSS-DOM-INNERHTML", "a.js", "el.innerHTML = location.hash", "el.innerHTML = ''"),
    ("CRY-TLS-VERIFY-DISABLED", "a.py", "requests.get(u, verify=False)", "requests.get(u, verify=True)"),
    ("CRY-TLS-VERIFY-DISABLED", "a.go", "TLSClientConfig: &tls.Config{InsecureSkipVerify: true}", "TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}"),
    ("CRY-WEAK-HASH", "a.py", "hashlib.md5(data)", "hashlib.md5(data, usedforsecurity=False)"),
    ("CRY-ECB-MODE", "A.java", 'Cipher.getInstance("AES")', 'Cipher.getInstance("AES/GCM/NoPadding")'),
    ("AUTH-JWT-ALG-NONE", "a.py", 'jwt.decode(t, k, algorithms=["none"])', 'jwt.decode(t, k, algorithms=["RS256"])'),
    ("AUTH-CSRF-DISABLED", "Sec.java", "http.csrf().disable();", "http.csrf(Customizer.withDefaults());"),
    ("DES-PY-YAML-UNSAFE", "a.py", "yaml.load(data)", "yaml.load(data, Loader=yaml.SafeLoader)"),
    ("DES-PY-PICKLE", "a.py", "pickle.loads(blob)", "json.loads(blob)"),
    ("DES-DOTNET-FORMATTER", "A.cs", "var f = new BinaryFormatter();", "var o = JsonSerializer.Deserialize<T>(s);"),
    ("CFG-CORS-WILDCARD", "a.py", 'app.add_middleware(CORSMiddleware, allow_origins=["*"])', 'app.add_middleware(CORSMiddleware, allow_origins=["https://app.example.com"])'),
    ("IAC-K8S-HOST-NAMESPACE", "d.yaml", "      hostNetwork: true", "      hostNetwork: false"),
    ("IAC-TF-OPEN-INGRESS", "m.tf", '    cidr_blocks = ["0.0.0.0/0"]', '    cidr_blocks = ["10.0.0.0/8"]'),
    ("IAC-IMDSV1-ALLOWED", "m.tf", '  http_tokens = "optional"', '  http_tokens = "required"'),
    ("CI-GHA-UNPINNED-ACTION", ".github/workflows/ci.yml", "      - uses: some-org/act@v2", "      - uses: some-org/act@8f4b7f84864484a7bf31766abe9204da3cbe65b3"),
    ("CI-GHA-SCRIPT-INJECTION", ".github/workflows/ci.yml", '      - run: echo "${{ github.event.issue.title }}"', "          TITLE: ${{ github.event.issue.title }}"),
    ("SC-OBFUSCATED-EXEC", "a.js", "eval(atob(payload))", "console.log(atob(payload))"),
    ("SC-CURL-PIPE-SHELL", "install.sh", "curl -fsSL https://x.example/i.sh | bash", "curl -fsSLo i.sh https://x.example/i.sh"),
    ("SEC-PRIVATE-KEY", "k.txt", "-----BEGIN " + "RSA PRIVATE KEY-----", "-----BEGIN PUBLIC KEY-----"),
    ("SEC-GENERIC-ASSIGNMENT", "c.py", 'api_key = "Zx81kPq2mNv7Lw0R"', 'api_key = "your-api-key-here"'),
    ("SEC-CONN-STRING-CREDS", "c.env", "DB=postgres://app:Gq72mXk1@db:5432/x", "DB=postgres://app:${DB_PASSWORD}@db:5432/x"),
]


class RulePackTest(unittest.TestCase):
    def test_packs_load_without_errors(self):
        self.assertEqual(ERRORS, [])
        self.assertGreaterEqual(len(ALL), 120)

    def test_metadata_quality(self):
        for r in ALL.values():
            with self.subTest(rule=r.id):
                self.assertIn(r.raw["severity"], SEVERITIES)
                self.assertTrue(r.raw["cwe"], "every rule maps to at least one CWE")
                self.assertTrue(all(c.startswith("CWE-") for c in r.raw["cwe"]))
                self.assertTrue(r.raw["owasp"], "every rule maps to an OWASP category")
                self.assertGreater(len(r.raw["remediation"]), 20)

    def test_samples(self):
        for rid, fname, pos, neg in SAMPLES:
            r = ALL[rid]
            with self.subTest(rule=rid):
                self.assertTrue(r.applies_to(fname), f"{rid} should apply to {fname}")
                self.assertEqual(len(r.scan(fname, pos + "\n")), 1, f"{rid} missed: {pos}")
                self.assertEqual(r.scan(fname, neg + "\n"), [], f"{rid} false positive: {neg}")

    def test_inline_suppression(self):
        r = ALL["INJ-PY-SHELL-TRUE"]
        self.assertEqual(r.scan("a.py", "subprocess.run(c, shell=True)  # appsec-ignore INJ-PY-SHELL-TRUE fixed cmd\n"), [])

    def test_secret_redaction_in_rule_output(self):
        r = ALL["SEC-GENERIC-ASSIGNMENT"]
        f = r.scan("c.py", 'api_key = "Zx81kPq2mNv7Lw0R"\n')[0]
        self.assertNotIn("Zx81kPq2mNv7Lw0R", f.location.snippet + f.evidence)

    def test_file_rule_missing_control(self):
        r = ALL["IAC-DOCKER-NO-USER"]
        self.assertEqual(len(r.scan("Dockerfile", "FROM alpine:3.20\nRUN echo hi\n")), 1)
        self.assertEqual(r.scan("Dockerfile", "FROM alpine:3.20\nUSER 10001\n"), [])
        self.assertEqual(len(r.scan("Dockerfile", "FROM alpine:3.20\nUSER root\n")), 1)

    def test_custom_rule_pack(self):
        import json, os, tempfile
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "custom.json"), "w") as fh:
            json.dump({"pack": "custom", "rules": [{"id": "ORG-NO-LEGACY-CLIENT", "title": "Legacy client", "severity": "medium",
                       "confidence": "high", "category": "org-policy", "files": ["*.py"], "pattern": r"legacy_client\.",
                       "remediation": "Use the v2 client which enforces mTLS.", "cwe": ["CWE-693"], "owasp": ["A05:2021"]}]}, fh)
        packs, errs = rules.load_packs([d])
        self.assertEqual(errs, [])
        self.assertEqual(len(packs["custom"][0].scan("x.py", "legacy_client.get()\n")), 1)

    def test_bad_rule_rejected(self):
        with self.assertRaises(rules.RuleError):
            rules.Rule({"id": "X", "title": "t", "severity": "severe", "confidence": "high", "category": "c",
                        "files": ["*"], "remediation": "r", "pattern": "x"}, "p")
        with self.assertRaises(rules.RuleError):
            rules.Rule({"id": "X", "title": "t", "severity": "low", "confidence": "high", "category": "c",
                        "files": ["*"], "remediation": "r", "pattern": "("}, "p")


if __name__ == "__main__":
    unittest.main()
