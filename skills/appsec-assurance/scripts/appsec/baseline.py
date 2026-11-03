"""Compare findings across runs by fingerprint (continuous mode)."""

import json
from typing import Dict, List

from .findings import OPEN_STATUSES, Finding, severity_at_least


def load_findings(path: str) -> List[Finding]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    items = data.get("findings", data) if isinstance(data, dict) else data
    return [Finding.from_dict(d) for d in items]


def diff(baseline: List[Finding], current: List[Finding]) -> Dict[str, List[Finding]]:
    b = {f.fingerprint: f for f in baseline if f.status in OPEN_STATUSES}
    c = {f.fingerprint: f for f in current if f.status in OPEN_STATUSES}
    return {
        "new": [c[k] for k in sorted(c) if k not in b],
        "fixed": [b[k] for k in sorted(b) if k not in c],
        "unchanged": [c[k] for k in sorted(c) if k in b],
    }


def gate(new: List[Finding], threshold: str) -> List[Finding]:
    return [f for f in new if severity_at_least(f.severity, threshold)]


def to_markdown(d: Dict[str, List[Finding]], threshold: str, blocking: List[Finding]) -> str:
    lines = ["# Security regression check", "",
             f"- New open findings: **{len(d['new'])}** ({len(blocking)} at or above `{threshold}`)",
             f"- Fixed since baseline: **{len(d['fixed'])}**",
             f"- Unchanged: {len(d['unchanged'])}", ""]
    for title, key in (("New", "new"), ("Fixed", "fixed")):
        if d[key]:
            lines += [f"## {title}", "", "| Severity | Rule | Location | Title |", "|---|---|---|---|"]
            for f in d[key]:
                lines.append(f"| {f.severity} | `{f.rule_id}` | `{f.location.short()}` | {f.title} |")
            lines.append("")
    lines.append("_Fingerprints are stable across line shifts; a moved-and-edited line may appear as fixed+new._")
    return "\n".join(lines) + "\n"
