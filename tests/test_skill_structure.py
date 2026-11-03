"""The skill must load as a Claude Code skill and its docs must be internally consistent."""
import json
import os
import re
import unittest

from tests._util import ROOT, SKILL, read


class SkillStructureTest(unittest.TestCase):
    def test_frontmatter(self):
        text = read(os.path.join(SKILL, "SKILL.md"))
        m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
        self.assertIsNotNone(m, "SKILL.md needs YAML frontmatter")
        fm = dict(line.split(":", 1) for line in m.group(1).splitlines() if ":" in line)
        self.assertEqual(fm["name"].strip(), "appsec-assurance")
        self.assertRegex(fm["name"].strip(), r"^[a-z0-9-]{1,64}$")
        desc = fm["description"].strip()
        self.assertTrue(20 < len(desc) <= 1024, f"description length {len(desc)}")

    def test_all_relative_links_resolve(self):
        md_files = []
        for d, _, fs in os.walk(SKILL):
            md_files += [os.path.join(d, f) for f in fs if f.endswith(".md")]
        broken = []
        for p in md_files:
            for target in re.findall(r"\]\(([^)#\s]+)(?:#[^)]*)?\)", read(p)):
                if re.match(r"^[a-z][a-z0-9+.-]*:", target):  # URI schemes (http:, javascript: examples)
                    continue
                if not os.path.exists(os.path.normpath(os.path.join(os.path.dirname(p), target))):
                    broken.append(f"{os.path.relpath(p, SKILL)} -> {target}")
        self.assertEqual(broken, [])

    def test_checklist_index_complete(self):
        idx = read(os.path.join(SKILL, "checklists", "README.md"))
        for f in sorted(os.listdir(os.path.join(SKILL, "checklists"))):
            if f.endswith(".md") and f != "README.md":
                self.assertIn(f, idx, f"{f} missing from checklists/README.md")

    def test_stack_index_complete(self):
        idx = read(os.path.join(SKILL, "stacks", "README.md"))
        for f in sorted(os.listdir(os.path.join(SKILL, "stacks"))):
            if f.endswith(".md") and f != "README.md":
                self.assertIn(f, idx, f"{f} missing from stacks/README.md")

    def test_skill_md_mentions_existing_paths(self):
        text = read(os.path.join(SKILL, "SKILL.md"))
        for rel in set(re.findall(r"`((?:references|checklists|stacks|templates|schemas|rules|scripts)/[\w./-]+)`", text)):
            self.assertTrue(os.path.exists(os.path.join(SKILL, rel)), rel)

    def test_json_files_parse(self):
        for d in ("templates", "schemas", "rules"):
            for f in os.listdir(os.path.join(SKILL, d)):
                if f.endswith(".json"):
                    with open(os.path.join(SKILL, d, f), encoding="utf-8") as fh:
                        json.load(fh)

    def test_plugin_manifest(self):
        p = os.path.join(ROOT, ".claude-plugin", "plugin.json")
        with open(p, encoding="utf-8") as fh:
            m = json.load(fh)
        self.assertEqual(m["name"], "appsec-assurance")
        from appsec import VERSION
        self.assertEqual(m["version"], VERSION, "plugin.json version must match engine VERSION")

    @unittest.skipUnless(hasattr(__import__("sys"), "stdlib_module_names"), "needs Python 3.10+ to enumerate stdlib")
    def test_stdlib_only(self):
        allowed_third_party = {"yaml"}  # optional, imported lazily for YAML config only
        import ast
        import sys
        stdlib = set(sys.stdlib_module_names)
        pkg = os.path.join(SKILL, "scripts", "appsec")
        for d, _, fs in os.walk(pkg):
            for f in fs:
                if not f.endswith(".py"):
                    continue
                tree = ast.parse(read(os.path.join(d, f)))
                for node in ast.walk(tree):
                    names = []
                    if isinstance(node, ast.Import):
                        names = [a.name.split(".")[0] for a in node.names]
                    elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                        names = [node.module.split(".")[0]]
                    for n in names:
                        self.assertTrue(n in stdlib or n in allowed_third_party or n == "appsec", f"{f} imports {n}")


if __name__ == "__main__":
    unittest.main()
