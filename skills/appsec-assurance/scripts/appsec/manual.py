"""Manual review input: analyst findings, triage of automated findings,
attack paths, checklist results and limitations. Validated strictly so the
report never contains malformed or evidence-free entries."""

import json
from typing import Dict, List, Tuple

from . import cvss
from .findings import CONFIDENCES, SEVERITIES, STATUSES, Finding, Location

CHECK_RESULTS = ("pass", "fail", "n/a", "untested")
TRIAGE_STATUSES = ("confirmed", "suspected", "false-positive", "accepted-risk", "fixed", "missing-control")


def load(path: str) -> Dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def validate(doc: Dict) -> List[str]:
    errs: List[str] = []
    if not isinstance(doc, dict):
        return ["top level must be an object"]
    allowed = {"$schema", "schema_version", "findings", "triage", "attack_paths", "checklist_results",
               "limitations", "executive_summary", "posture_statement", "threat_model", "assessors",
               "scope_reference", "notes"}
    for k in sorted(set(doc) - allowed):
        errs.append(f"unknown top-level key '{k}'")
    ids = set()
    for i, f in enumerate(doc.get("findings", []) or []):
        p = f"findings[{i}]"
        for k in ("id", "title", "severity", "status", "confidence", "location", "evidence", "remediation"):
            if not f.get(k):
                errs.append(f"{p}: missing required '{k}'")
        if f.get("id") in ids:
            errs.append(f"{p}: duplicate id {f.get('id')}")
        ids.add(f.get("id"))
        if f.get("severity") and f["severity"] not in SEVERITIES:
            errs.append(f"{p}: severity must be one of {SEVERITIES}")
        if f.get("status") and f["status"] not in STATUSES:
            errs.append(f"{p}: status must be one of {STATUSES}")
        if f.get("confidence") and f["confidence"] not in CONFIDENCES:
            errs.append(f"{p}: confidence must be one of {CONFIDENCES}")
        loc = f.get("location") or {}
        if f.get("location") is not None and not loc.get("path"):
            errs.append(f"{p}: location.path required")
        if f.get("status") == "confirmed" and not f.get("validation_steps"):
            errs.append(f"{p}: confirmed findings need validation_steps (reproducible evidence)")
        for c in f.get("cwe", []) or []:
            if not str(c).startswith("CWE-"):
                errs.append(f"{p}: cwe entries look like 'CWE-89'")
        if f.get("cvss_vector"):
            try:
                cvss.base_score(f["cvss_vector"])
            except cvss.CVSSError as e:
                errs.append(f"{p}: cvss_vector invalid: {e}")
    for i, t in enumerate(doc.get("triage", []) or []):
        p = f"triage[{i}]"
        if not (t.get("fingerprint") or t.get("id")):
            errs.append(f"{p}: needs 'fingerprint' (preferred) or 'id'")
        if t.get("status") not in TRIAGE_STATUSES:
            errs.append(f"{p}: status must be one of {TRIAGE_STATUSES}")
        if not t.get("reason"):
            errs.append(f"{p}: a written reason is required for every triage decision")
    for i, a in enumerate(doc.get("attack_paths", []) or []):
        p = f"attack_paths[{i}]"
        for k in ("id", "title", "steps", "severity", "narrative"):
            if not a.get(k):
                errs.append(f"{p}: missing '{k}'")
        if a.get("severity") and a["severity"] not in SEVERITIES:
            errs.append(f"{p}: bad severity")
    for i, c in enumerate(doc.get("checklist_results", []) or []):
        p = f"checklist_results[{i}]"
        if not c.get("checklist") or not c.get("item"):
            errs.append(f"{p}: needs 'checklist' and 'item'")
        if c.get("result") not in CHECK_RESULTS:
            errs.append(f"{p}: result must be one of {CHECK_RESULTS}")
        if c.get("result") in ("n/a", "untested") and not c.get("notes"):
            errs.append(f"{p}: '{c.get('result')}' needs a reason in notes")
    if not isinstance(doc.get("limitations", []), list):
        errs.append("limitations must be a list of strings")
    return errs


def to_findings(doc: Dict) -> List[Finding]:
    out = []
    for f in doc.get("findings", []) or []:
        loc = f.get("location") or {}
        fd = Finding(
            rule_id=f.get("rule_id") or f"MANUAL-{f['id']}", title=f["title"], severity=f["severity"],
            category=f.get("category", "manual-review"), status=f["status"], confidence=f["confidence"],
            location=Location(path=loc.get("path", ""), start_line=int(loc.get("start_line") or 0),
                              end_line=int(loc.get("end_line") or loc.get("start_line") or 0),
                              snippet=loc.get("snippet", "")),
            description=f.get("description", ""), evidence=f["evidence"], impact=f.get("impact", ""),
            remediation=f["remediation"], cwe=f.get("cwe", []), owasp=f.get("owasp", []),
            references=f.get("references", []), cvss_vector=f.get("cvss_vector", ""),
            validation_steps=f.get("validation_steps", []), regression_test=f.get("regression_test", ""),
            patch=f.get("patch", ""), sources=["manual-review"], id=f["id"])
        out.append(fd)
    return out


def apply_triage(findings: List[Finding], doc: Dict) -> Tuple[List[Finding], List[str]]:
    by_fp = {f.fingerprint: f for f in findings}
    by_id = {f.id: f for f in findings}
    warnings = []
    for t in doc.get("triage", []) or []:
        f = by_fp.get(t.get("fingerprint", "")) or by_id.get(t.get("id", ""))
        if not f:
            warnings.append(f"triage entry {t.get('fingerprint') or t.get('id')} matches no finding (stale?)")
            continue
        f.status = t["status"]
        f.triage_reason = t["reason"]
        if t.get("severity") in SEVERITIES:
            f.severity = t["severity"]
        if t.get("confidence") in CONFIDENCES:
            f.confidence = t["confidence"]
    return findings, warnings
