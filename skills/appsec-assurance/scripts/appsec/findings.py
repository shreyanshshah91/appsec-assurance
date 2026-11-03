"""Finding model, severity ordering, fingerprinting and de-duplication."""

import hashlib
import re
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# confirmed: reproducible evidence. suspected: strong static indication, not proven.
# unverified: tool output not yet triaged. missing-control: an expected control is absent.
STATUSES = [
    "confirmed",
    "suspected",
    "unverified",
    "missing-control",
    "false-positive",
    "accepted-risk",
    "fixed",
]
# Statuses that represent open risk (counted in summaries, gates and diffs).
OPEN_STATUSES = {"confirmed", "suspected", "unverified", "missing-control"}
CONFIDENCES = ["high", "medium", "low"]


def severity_at_least(severity: str, threshold: str) -> bool:
    return SEVERITY_RANK.get(severity, 99) <= SEVERITY_RANK.get(threshold, 99)


def normalize_severity(value: Optional[str]) -> str:
    v = (value or "").strip().lower()
    aliases = {"error": "high", "warning": "medium", "warn": "medium", "note": "low",
               "moderate": "medium", "informational": "info", "none": "info",
               "unknown": "info", "negligible": "info"}
    v = aliases.get(v, v)
    return v if v in SEVERITY_RANK else "info"


@dataclass
class Location:
    path: str
    start_line: int = 0
    end_line: int = 0
    snippet: str = ""

    def short(self) -> str:
        return f"{self.path}:{self.start_line}" if self.start_line else self.path


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str
    location: Location
    status: str = "unverified"
    confidence: str = "medium"
    description: str = ""
    evidence: str = ""
    impact: str = ""
    remediation: str = ""
    cwe: List[str] = field(default_factory=list)
    owasp: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    cvss_vector: str = ""
    cvss_score: Optional[float] = None
    sources: List[str] = field(default_factory=list)
    validation_steps: List[str] = field(default_factory=list)
    regression_test: str = ""
    patch: str = ""
    triage_reason: str = ""
    id: str = ""
    fingerprint: str = ""

    def to_dict(self) -> Dict:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, d: Dict) -> "Finding":
        d = dict(d)
        loc = d.pop("location", {}) or {}
        known = set(cls.__dataclass_fields__)
        kwargs = {k: v for k, v in d.items() if k in known}
        f = cls(location=Location(**{k: v for k, v in loc.items()
                                     if k in Location.__dataclass_fields__}), **kwargs)
        f.severity = normalize_severity(f.severity)
        return f


_WS = re.compile(r"\s+")


def compute_fingerprint(f: Finding, occurrence: int = 0) -> str:
    """Stable identity that survives line shifts: rule + path + normalized code."""
    snippet = _WS.sub(" ", f.location.snippet or "").strip()
    basis = "|".join([f.rule_id, f.location.path, snippet or f.title, str(occurrence)])
    return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:20]


def sort_key(f: Finding):
    return (SEVERITY_RANK.get(f.severity, 99), f.location.path, f.location.start_line,
            f.rule_id, f.fingerprint)


def finalize(findings: List[Finding]) -> List[Finding]:
    """Assign fingerprints, merge duplicates (same location + CWE from different
    tools), sort deterministically and assign sequential IDs."""
    seen_basis: Dict[str, int] = {}
    for f in findings:
        if not f.fingerprint:
            basis = (f.rule_id, f.location.path, _WS.sub(" ", f.location.snippet).strip())
            occ = seen_basis.get(str(basis), 0)
            seen_basis[str(basis)] = occ + 1
            f.fingerprint = compute_fingerprint(f, occ)

    merged: Dict[str, Finding] = {}
    by_loc_cwe: Dict[tuple, str] = {}
    for f in findings:
        if f.fingerprint in merged:
            _merge_into(merged[f.fingerprint], f)
            continue
        key = None
        # Cross-tool merge only: an external tool and a built-in rule reporting the same
        # weakness at the same spot. Never merge analyst findings, two built-in rules,
        # or two secrets (each secret needs its own rotation).
        if f.cwe and f.location.start_line and _mergeable(f):
            key = (f.location.path, f.location.start_line, tuple(sorted(f.cwe)))
            if key in by_loc_cwe and _cross_tool(merged[by_loc_cwe[key]], f):
                _merge_into(merged[by_loc_cwe[key]], f)
                continue
        merged[f.fingerprint] = f
        if key:
            by_loc_cwe[key] = f.fingerprint

    out = sorted(merged.values(), key=sort_key)
    # IDs are stable once assigned (attack paths and triage refer to them);
    # only findings without an ID get the next free AUTO number.
    used = [int(f.id[5:]) for f in out if f.id.startswith("AUTO-") and f.id[5:].isdigit()]
    nxt = max(used, default=0) + 1
    for f in out:
        if not f.id:
            f.id = f"AUTO-{nxt:04d}"
            nxt += 1
        f.sources = sorted(set(f.sources))
    return out


def _builtin(f: Finding) -> bool:
    return all(s.startswith("builtin:") for s in f.sources)


def _mergeable(f: Finding) -> bool:
    return "manual-review" not in f.sources and f.category != "secrets"


def _cross_tool(a: Finding, b: Finding) -> bool:
    return _mergeable(a) and _mergeable(b) and _builtin(a) != _builtin(b) and not set(a.sources) & set(b.sources)


def _merge_into(target: Finding, other: Finding) -> None:
    target.sources = sorted(set(target.sources) | set(other.sources))
    if SEVERITY_RANK[other.severity] < SEVERITY_RANK[target.severity]:
        target.severity = other.severity
    for attr in ("cwe", "owasp", "references"):
        setattr(target, attr, sorted(set(getattr(target, attr)) | set(getattr(other, attr))))
    if other.confidence == "high":
        target.confidence = "high"


def summarize(findings: List[Finding]) -> Dict:
    by_sev = {s: 0 for s in SEVERITIES}
    by_status: Dict[str, int] = {}
    by_cat: Dict[str, int] = {}
    for f in findings:
        by_status[f.status] = by_status.get(f.status, 0) + 1
        if f.status in OPEN_STATUSES:
            by_sev[f.severity] += 1
            by_cat[f.category] = by_cat.get(f.category, 0) + 1
    return {
        "open_total": sum(by_sev.values()),
        "by_severity": by_sev,
        "by_status": dict(sorted(by_status.items())),
        "by_category": dict(sorted(by_cat.items())),
    }


def redact(secret: str) -> str:
    s = secret.strip()
    if len(s) <= 8:
        return "*" * len(s)
    return f"{s[:4]}…[redacted {len(s)} chars]"
