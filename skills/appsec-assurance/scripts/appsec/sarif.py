"""SARIF 2.1.0 export (GitHub code scanning compatible) and generic SARIF ingest
so any SARIF-emitting scanner can be integrated with a one-line adapter."""

import json
import os
import re
import urllib.parse
from typing import Dict, List

from . import TOOL_NAME, TOOL_URI, VERSION
from .findings import Finding, Location, normalize_severity
from .rules import redact_snippet
from .standards import owasp_for_cwes

SEV_TO_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SEV_TO_SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}
_CWE_RX = re.compile(r"CWE[-_ ]?(\d+)", re.I)
SECRET_CWES = {"CWE-798", "CWE-259", "CWE-321", "CWE-540"}


def export(findings: List[Finding], path: str) -> None:
    rules: Dict[str, Dict] = {}
    results = []
    for f in findings:
        if f.status in ("false-positive", "fixed"):
            continue
        if f.rule_id not in rules:
            tags = ["security"] + [c.lower().replace("cwe-", "external/cwe/cwe-") for c in f.cwe] + f.owasp
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": re.sub(r"[^A-Za-z0-9]", "", f.title.title())[:100] or f.rule_id,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description or f.title},
                "help": {"text": f.remediation or "See report.", "markdown": f.remediation or "See report."},
                "defaultConfiguration": {"level": SEV_TO_LEVEL[f.severity]},
                "properties": {"tags": tags, "security-severity": _sec_sev(f), "precision": _precision(f)},
            }
        loc = {"physicalLocation": {"artifactLocation": {"uri": f.location.path, "uriBaseId": "%SRCROOT%"}}}
        if f.location.start_line:
            loc["physicalLocation"]["region"] = {"startLine": f.location.start_line,
                                                 "endLine": max(f.location.end_line, f.location.start_line)}
        results.append({
            "ruleId": f.rule_id,
            "level": SEV_TO_LEVEL[f.severity],
            "message": {"text": f"{f.title} [{f.status}, confidence {f.confidence}]. {f.evidence}".strip()},
            "locations": [loc],
            "partialFingerprints": {"appsecFingerprint/v1": f.fingerprint},
            "properties": {"status": f.status, "confidence": f.confidence, "severity": f.severity,
                           "sources": f.sources, "findingId": f.id},
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": TOOL_NAME, "version": VERSION, "informationUri": TOOL_URI,
                                "rules": [rules[k] for k in sorted(rules)]}},
            "results": results,
            "originalUriBaseIds": {"%SRCROOT%": {"uri": "./"}},
        }],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=False)
        fh.write("\n")


def _sec_sev(f: Finding) -> str:
    if f.cvss_score is not None:
        return f"{f.cvss_score:.1f}"
    return SEV_TO_SCORE[f.severity]


def _precision(f: Finding) -> str:
    return {"high": "high", "medium": "medium", "low": "low"}.get(f.confidence, "medium")


def _sev_from_result(result: Dict, rule: Dict) -> str:
    props = {**(rule.get("properties") or {}), **(result.get("properties") or {})}
    ss = props.get("security-severity")
    if ss is not None:
        try:
            v = float(ss)
            return "critical" if v >= 9 else "high" if v >= 7 else "medium" if v >= 4 else "low" if v > 0 else "info"
        except (TypeError, ValueError):
            pass
    for key in ("severity", "issue_severity", "Severity"):
        if isinstance(props.get(key), str):
            return normalize_severity(props[key])
    level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level") or "warning"
    return normalize_severity(level)


def ingest(path: str, tool: str, root: str, secret_tool: bool = False) -> List[Finding]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        doc = json.load(fh)
    out: List[Finding] = []
    abs_root = os.path.realpath(root)
    for run in doc.get("runs", []) or []:
        driver = ((run.get("tool") or {}).get("driver") or {})
        rule_list = driver.get("rules", []) or []
        rules = {r.get("id"): r for r in rule_list}
        for ext in (run.get("tool") or {}).get("extensions", []) or []:
            for r in ext.get("rules", []) or []:
                rules.setdefault(r.get("id"), r)
        for res in run.get("results", []) or []:
            idx = res.get("ruleIndex", (res.get("rule") or {}).get("index"))
            by_index = rule_list[idx] if isinstance(idx, int) and 0 <= idx < len(rule_list) else {}
            rid = res.get("ruleId") or (res.get("rule") or {}).get("id") or by_index.get("id") or "unknown"
            rule = rules.get(rid) or by_index
            # Only accepted suppressions hide a result; rejected / under-review ones still count.
            sups = res.get("suppressions") or []
            if sups and any(x.get("status", "accepted") == "accepted" for x in sups):
                continue
            locs = res.get("locations") or [{}]
            phys = (locs[0].get("physicalLocation") or {})
            uri = ((phys.get("artifactLocation") or {}).get("uri") or "")
            uri = urllib.parse.unquote(re.sub(r"^file://", "", uri))
            if os.path.isabs(uri):
                uri = os.path.relpath(os.path.realpath(uri), abs_root)
            uri = uri.replace(os.sep, "/")
            if uri.startswith("./"):
                uri = uri[2:]
            region = phys.get("region") or {}
            tags = " ".join((rule.get("properties") or {}).get("tags", []) or [])
            text_blob = " ".join([tags, json.dumps(rule.get("relationships", [])), rid,
                                  (rule.get("shortDescription") or {}).get("text", "")])
            cwes = sorted({f"CWE-{n}" for n in _CWE_RX.findall(text_blob)})
            is_secret = secret_tool or bool(SECRET_CWES & set(cwes)) or re.search(r"secret|credential|password", rid, re.I) is not None
            # Every tool's text is redacted: SAST tools quote hardcoded credentials in snippets and messages.
            snippet = redact_snippet(((region.get("snippet") or {}).get("text") or "").strip(), aggressive=is_secret)
            msg = redact_snippet((res.get("message") or {}).get("text", ""), aggressive=is_secret)
            title = (rule.get("shortDescription") or {}).get("text") or msg.split("\n")[0][:120] or rid
            out.append(Finding(
                rule_id=f"{tool}:{rid}", title=title.strip(), severity=_sev_from_result(res, rule),
                category="secrets" if is_secret else _category(tool, cwes, tags),
                status="unverified", confidence="medium",
                location=Location(path=uri or "(unknown)", start_line=int(region.get("startLine") or 0),
                                  end_line=int(region.get("endLine") or region.get("startLine") or 0),
                                  snippet=snippet[:300]),
                description=((rule.get("fullDescription") or {}).get("text") or "")[:2000],
                evidence=msg[:1000],
                remediation=((rule.get("help") or {}).get("text") or "See tool documentation.")[:2000],
                cwe=cwes, owasp=owasp_for_cwes(cwes),
                references=[rule["helpUri"]] if rule.get("helpUri") else [],
                sources=[tool],
            ))
    return out


def _category(tool: str, cwes: List[str], tags: str = "") -> str:
    if re.search(r"misconfig|iac|config", tags, re.I):
        return "iac"
    if tool in ("osv-scanner", "npm-audit", "pip-audit", "govulncheck"):
        return "vulnerable-dependency"
    if tool in ("checkov", "hadolint", "kics"):
        return "iac"
    if tool == "zizmor":
        return "cicd"
    if tool == "trivy":
        return "vulnerable-dependency"  # trivy misconfig results are caught by their tags above
    return "code"
