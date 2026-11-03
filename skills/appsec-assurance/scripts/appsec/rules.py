"""Declarative rule packs (JSON) and the regex rule engine.

Rule kinds:
  line  - `pattern` matches a single line; optional `negative` suppresses that line.
  file  - every regex in `all_of` matches somewhere in the file and none in
          `none_of` does. Used for multi-signal issues and missing controls.
"""

import fnmatch
import glob
import json
import math
import os
import re
from typing import Dict, List, Optional, Tuple

from .findings import CONFIDENCES, SEVERITIES, STATUSES, Finding, Location, redact
from .walker import iter_lines, read_text

REQUIRED = ("id", "title", "severity", "confidence", "category", "files", "remediation")
KINDS = ("line", "file")
TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|specs|testdata|fixtures?)/|"
                       r"(_test\.go|\.test\.[jt]sx?|\.spec\.[jt]sx?|_spec\.rb|Test\.java|test_[^/]+\.py)$")
PLACEHOLDER = re.compile(r"(?i)(example|sample|dummy|placeholder|changeme|change_me|your[_-]?|"
                         r"xxxx|\*\*\*\*|<[^>]+>|\$\{|\{\{|%s|todo|redacted|fake|test[_-]?key|"
                         r"^0+$|^x+$|^(pass|password|passwd|pwd|secret|user|username)$|process\.env|os\.environ|getenv)")


class RuleError(ValueError):
    pass


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


class Rule:
    def __init__(self, d: Dict, pack: str):
        missing = [k for k in REQUIRED if k not in d]
        if missing:
            raise RuleError(f"rule {d.get('id', '?')} in pack {pack}: missing {missing}")
        self.raw = d
        self.pack = pack
        self.id = d["id"]
        self.kind = d.get("kind", "line")
        if self.kind not in KINDS:
            raise RuleError(f"rule {self.id}: unknown kind {self.kind}")
        if d["severity"] not in SEVERITIES:
            raise RuleError(f"rule {self.id}: bad severity {d['severity']}")
        if d["confidence"] not in CONFIDENCES:
            raise RuleError(f"rule {self.id}: bad confidence {d['confidence']}")
        self.status = d.get("status", "unverified")
        if self.status not in STATUSES:
            raise RuleError(f"rule {self.id}: bad status {self.status}")
        self.files = d["files"]
        self.exclude_files = d.get("exclude_files", [])
        flags = re.I if d.get("ignore_case") else 0
        try:
            if self.kind == "line":
                self.pattern = re.compile(d["pattern"], flags)
                self.negative = re.compile(d["negative"], flags) if d.get("negative") else None
            else:
                self.all_of = [re.compile(p, flags | re.M) for p in d.get("all_of", [])]
                self.none_of = [re.compile(p, flags | re.M) for p in d.get("none_of", [])]
                if not self.all_of:
                    raise RuleError(f"rule {self.id}: file rules need all_of")
        except re.error as e:
            raise RuleError(f"rule {self.id}: invalid regex: {e}") from None
        self.secret = bool(d.get("secret"))
        self.entropy_min = float(d.get("entropy_min", 0))

    def applies_to(self, rel: str) -> bool:
        base = os.path.basename(rel)
        def m(pats):
            return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(base, p) for p in pats)
        return m(self.files) and not m(self.exclude_files)

    def _finding(self, rel: str, ln: int, snippet: str, evidence: str) -> Finding:
        d = self.raw
        return Finding(
            rule_id=self.id, title=d["title"], severity=d["severity"],
            category=d["category"], status=self.status, confidence=d["confidence"],
            location=Location(path=rel, start_line=ln, end_line=ln, snippet=snippet[:300]),
            description=d.get("description", ""), evidence=evidence,
            impact=d.get("impact", ""), remediation=d["remediation"],
            cwe=list(d.get("cwe", [])), owasp=list(d.get("owasp", [])),
            references=list(d.get("references", [])), cvss_vector=d.get("cvss", ""),
            sources=[f"builtin:{self.pack}"],
        )

    def scan(self, rel: str, text: str) -> List[Finding]:
        out: List[Finding] = []
        if self.kind == "file":
            first_line = 0
            for rx in self.all_of:
                m = rx.search(text)
                if not m:
                    return []
                if not first_line:
                    first_line = text.count("\n", 0, m.start()) + 1
            if any(rx.search(text) for rx in self.none_of):
                return []
            line = text.splitlines()[first_line - 1] if first_line else ""
            ev = f"Matched {len(self.all_of)} required signal(s)"
            if self.none_of:
                ev += f"; none of {len(self.none_of)} expected control pattern(s) present"
            out.append(self._finding(rel, first_line, line.strip(), ev + "."))
            return out
        for ln, line in iter_lines(text):
            if len(line) > 4000:
                continue
            m = self.pattern.search(line)
            if not m or (self.negative and self.negative.search(line)):
                continue
            if "appsec-ignore" in line and self.id in line:
                continue  # inline suppression: `appsec-ignore RULE-ID reason`
            snippet = line.strip()
            evidence = f"Line matches pattern for {self.id}."
            if self.secret:
                secret = m.groupdict().get("secret") or m.group(0)
                if PLACEHOLDER.search(secret):
                    continue
                if self.entropy_min and shannon_entropy(secret) < self.entropy_min:
                    continue
                snippet = snippet.replace(secret, redact(secret))
                evidence = (f"Value {redact(secret)} (entropy {shannon_entropy(secret):.2f}). "
                            "Secret redacted; it was not used or validated.")
            out.append(self._finding(rel, ln, snippet, evidence))
        return out


_ASSIGNED_VALUE = re.compile(r"([=:]\s*[\"']?)([^\s\"',;]{4,})")


def redact_snippet(snippet: str, secret_rules: List[Rule], aggressive: bool = False) -> str:
    """Mask secret-shaped values in snippets produced by non-secret rules, so a
    line that also carries a credential never leaks it into reports."""
    for r in secret_rules:
        for m in r.pattern.finditer(snippet):
            for val in [v for v in m.groupdict().values() if v] or [m.group(0)]:
                if not PLACEHOLDER.search(val):
                    snippet = snippet.replace(val, redact(val))
    if aggressive:
        snippet = _ASSIGNED_VALUE.sub(lambda m: m.group(1) + redact(m.group(2))
                                      if "redacted" not in m.group(2) else m.group(0), snippet)
    return snippet


def load_packs(dirs: List[str]) -> Tuple[Dict[str, List[Rule]], List[str]]:
    packs: Dict[str, List[Rule]] = {}
    errors: List[str] = []
    seen_ids: Dict[str, str] = {}
    for d in dirs:
        for path in sorted(glob.glob(os.path.join(d, "*.json"))):
            try:
                with open(path, encoding="utf-8") as fh:
                    data = json.load(fh)
                name = data["pack"]
                for rd in data["rules"]:
                    r = Rule(rd, name)
                    if r.id in seen_ids:
                        raise RuleError(f"duplicate rule id {r.id} (also in {seen_ids[r.id]})")
                    seen_ids[r.id] = name
                    packs.setdefault(name, []).append(r)
            except (OSError, ValueError, KeyError, RuleError) as e:
                errors.append(f"{path}: {e}")
    return packs, errors


def run(root: str, files: List[str], rules: List[Rule], min_confidence: str = "low",
        disabled: Optional[List[str]] = None, severity_overrides: Optional[Dict] = None
        ) -> Tuple[List[Finding], List[str]]:
    disabled_set = set(disabled or [])
    conf_rank = {c: i for i, c in enumerate(CONFIDENCES)}
    active = [r for r in rules if r.id not in disabled_set
              and conf_rank[r.raw["confidence"]] <= conf_rank[min_confidence]]
    secret_rules = [r for r in rules if r.secret and r.kind == "line"]
    findings: List[Finding] = []
    errors: List[str] = []
    for rel in files:
        applicable = [r for r in active if r.applies_to(rel)]
        if not applicable:
            continue
        try:
            text = read_text(root, rel)
        except (OSError, ValueError) as e:
            errors.append(f"{rel}: {e}")
            continue
        in_test = bool(TEST_PATH.search(rel))
        for r in applicable:
            for f in r.scan(rel, text):
                if in_test and not r.secret:
                    f.confidence = "low"
                    f.description = (f.description + " (Located in test/fixture code; "
                                     "confirm whether it is reachable in production.)").strip()
                if severity_overrides and f.rule_id in severity_overrides:
                    f.severity = severity_overrides[f.rule_id]
                if not r.secret:
                    f.location.snippet = redact_snippet(f.location.snippet, secret_rules,
                                                        aggressive=f.category == "secrets")
                findings.append(f)
    return findings, errors
