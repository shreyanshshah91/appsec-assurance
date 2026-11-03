"""SARIF 2.1.0 export (GitHub code scanning compatible) and generic SARIF ingest
so any SARIF-emitting scanner can be integrated with a one-line adapter."""

import json
import os
import re
from typing import Dict, List

from . import TOOL_NAME, TOOL_URI, VERSION
from .findings import Finding, Location, normalize_severity, redact
from .standards import owasp_for_cwes

SEV_TO_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SEV_TO_SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}
_CWE_RX = re.compile(r"CWE[-_ ]?(\d+)", re.I)


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
        rules = {r.get("id"): r for r in driver.get("rules", []) or []}
        for ext in (run.get("tool") or {}).get("extensions", []) or []:
            for r in ext.get("rules", []) or []:
                rules.setdefault(r.get("id"), r)
        for res in run.get("results", []) or []:
            rid = res.get("ruleId") or (res.get("rule") or {}).get("id") or "unknown"
            rule = rules.get(rid, {})
            if res.get("suppressions"):
                continue
            locs = res.get("locations") or [{}]
            phys = (locs[0].get("physicalLocation") or {})
            uri = ((phys.get("artifactLocation") or {}).get("uri") or "")
            uri = re.sub(r"^file://", "", uri)
            if os.path.isabs(uri):
                uri = os.path.relpath(os.path.realpath(uri), abs_root)
            uri = uri.replace(os.sep, "/")
            if uri.startswith("./"):
                uri = uri[2:]
            region = phys.get("region") or {}
            snippet = ((region.get("snippet") or {}).get("text") or "").strip()
            if secret_tool and snippet:
                snippet = redact(snippet)
            tags = " ".join((rule.get("properties") or {}).get("tags", []) or [])
            text_blob = " ".join([tags, json.dumps(rule.get("relationships", [])), rid,
                                  (rule.get("shortDescription") or {}).get("text", "")])
            cwes = sorted({f"CWE-{n}" for n in _CWE_RX.findall(text_blob)})
            msg = (res.get("message") or {}).get("text", "")
            title = (rule.get("shortDescription") or {}).get("text") or msg.split("\n")[0][:120] or rid
            out.append(Finding(
                rule_id=f"{tool}:{rid}", title=title.strip(), severity=_sev_from_result(res, rule),
                category="secrets" if secret_tool else _category(tool, cwes),
                status="unverified", confidence="medium",
                location=Location(path=uri or "(unknown)", start_line=int(region.get("startLine") or 0),
                                  end_line=int(region.get("endLine") or region.get("startLine") or 0),
                                  snippet=snippet[:300]),
                description=((rule.get("fullDescription") or {}).get("text") or "")[:2000],
                evidence=(redact(msg) if secret_tool and len(msg) > 200 else msg[:1000]),
                remediation=((rule.get("help") or {}).get("text") or "See tool documentation.")[:2000],
                cwe=cwes, owasp=owasp_for_cwes(cwes),
                references=[rule["helpUri"]] if rule.get("helpUri") else [],
                sources=[tool],
            ))
    return out


def _category(tool: str, cwes: List[str]) -> str:
    if tool in ("osv-scanner", "npm-audit", "pip-audit", "govulncheck"):
        return "vulnerable-dependency"
    if tool in ("checkov", "hadolint", "kics"):
        return "iac"
    if tool == "zizmor":
        return "cicd"
    if tool == "trivy":
        return "vulnerable-dependency" if not cwes else "iac"
    return "code"
