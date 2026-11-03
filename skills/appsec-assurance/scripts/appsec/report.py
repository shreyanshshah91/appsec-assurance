"""Developer-friendly Markdown report. Structure: references/reporting.md."""

from typing import Dict, List

from .findings import OPEN_STATUSES, SEVERITIES, Finding
from .standards import OWASP_TOP10_2021, coverage_matrix

DISCLAIMER = (
    "> **Assurance statement.** This assessment reduces risk; it does not prove the absence of "
    "vulnerabilities. Passing automated checks is not evidence that the application is secure. "
    "Areas listed under *Untested areas and limitations* were not assessed and must not be assumed safe."
)


def posture(findings: List[Finding], attack_paths: List[Dict]) -> Dict:
    open_ = [f for f in findings if f.status in OPEN_STATUSES]
    sev = {s: sum(1 for f in open_ if f.severity == s) for s in SEVERITIES}
    chain_sev = {a.get("severity") for a in attack_paths or []}
    confirmed_crit = any(f.severity == "critical" and f.status == "confirmed" for f in open_)
    if confirmed_crit or "critical" in chain_sev:
        level, text = "critical", "Critical risk: at least one confirmed critical issue or critical attack path."
    elif sev["critical"] or sev["high"] or "high" in chain_sev:
        level, text = "high", "High risk: critical/high weaknesses require prompt remediation or validation."
    elif sev["medium"]:
        level, text = "elevated", "Elevated risk: medium-severity weaknesses and/or missing controls present."
    elif sev["low"] or sev["info"]:
        level, text = "guarded", "Guarded: only low/informational items found by the checks that ran."
    else:
        level, text = "no-open-findings", "No open findings from the checks that ran. This is not a statement that the application is secure."
    return {"level": level, "statement": text, "open_by_severity": sev}


def _esc(s: str) -> str:
    return (s or "").replace("|", "\\|").replace("\n", " ")


def render(doc: Dict, findings: List[Finding]) -> str:
    run, stack, summ = doc["run"], doc["stack"], doc["summary"]
    L: List[str] = []
    a = L.append
    a(f"# Application Security Assessment — {run['target']}")
    a("")
    a("| Field | Value |")
    a("|---|---|")
    a(f"| Mode | `{run['mode']}` |")
    a(f"| Engine | {doc['tool']['name']} {doc['tool']['version']} |")
    if run.get("git_commit"):
        a(f"| Commit | `{run['git_commit'][:12]}` |")
    if run.get("started"):
        a(f"| Started / finished (UTC) | {run['started']} / {run.get('finished')} |")
    a(f"| Files scanned | {run['files_scanned']} |")
    a(f"| Manual review merged | {'yes' if doc.get('manual_review_included') else 'no — automated results only'} |")
    a("")
    a(DISCLAIMER)
    a("")

    # 1. Executive summary
    p = doc["posture"]
    a("## 1. Executive summary")
    a("")
    if doc.get("executive_summary"):
        a(doc["executive_summary"])
    else:
        top = [f for f in findings if f.status in OPEN_STATUSES][:5]
        a(f"Automated assessment in `{run['mode']}` mode found **{summ['open_total']} open item(s)**. "
          + ("Top items: " + "; ".join(f"{f.title} (`{f.location.short()}`, {f.severity})" for f in top) + "." if top else ""))
        a("")
        a("_No analyst executive summary was provided. Automated results have not been triaged; "
          "expect false positives and missed issues until manual review (SKILL.md phases 3–7) is complete._")
    a("")

    # 2. Posture
    a("## 2. Overall security posture")
    a("")
    a(f"**Risk indicator: {p['level'].upper()}** — {p['statement']}")
    a("")
    if doc.get("posture_statement"):
        a(doc["posture_statement"])
        a("")
    a("| Severity | " + " | ".join(SEVERITIES) + " |")
    a("|---|" + "---|" * len(SEVERITIES))
    a("| Open | " + " | ".join(str(p["open_by_severity"][s]) for s in SEVERITIES) + " |")
    a("")
    a("Status counts (all findings): " + ", ".join(f"{k}: {v}" for k, v in summ["by_status"].items()) if summ["by_status"] else "No findings recorded.")
    a("")

    # 3. Technologies
    a("## 3. Technologies and components assessed")
    a("")
    def lst(x):
        return ", ".join(x) if x else "none detected"
    a(f"- **Languages:** {lst([f'{k} ({v})' for k, v in sorted(stack['languages'].items(), key=lambda kv: (-kv[1], kv[0]))])}")
    a(f"- **Frameworks:** {lst(stack['frameworks'])}")
    a(f"- **Package managers:** {lst(stack['package_managers'])}; missing lockfiles: {lst(stack['missing_lockfiles'])}")
    a(f"- **Data stores:** {lst(stack['datastores'])}")
    a(f"- **Containers / IaC / cloud:** {lst(stack['containers'] + stack['iac'] + stack['cloud'])}")
    a(f"- **CI/CD:** {lst(stack['ci'])}; **Mobile:** {lst(stack['mobile'])}")
    if stack.get("unsupported_languages"):
        a(f"- **Limited support:** {lst(stack['unsupported_languages'])} (generic checks only)")
    a("")
    inv = doc.get("inventory_summary", {})
    if inv:
        a("**Attack-surface inventory (regex-derived, see inventory.json):** " +
          ", ".join(f"{k}: {v}" for k, v in inv.items()))
        a("")
    for h in doc.get("trust_boundary_hints", []):
        a(f"- {h}")
    a("")

    # 4. Standards & coverage
    a("## 4. Standards and coverage")
    a("")
    a("### OWASP Top 10 (2021) mapping")
    a("")
    a("| Category | Open findings |")
    a("|---|---|")
    for k, v in coverage_matrix(findings, doc["coverage"]).items():
        a(f"| {k} {v['name']} | {v['open_findings']} |")
    a("")
    a("_A zero means no open finding was mapped to the category, not that the category was fully tested._")
    a("")
    a("### Check ledger")
    a("")
    a("| Area | Check | Kind | Status | Findings | Notes |")
    a("|---|---|---|---|---|---|")
    for e in doc["coverage"]:
        if e["kind"] == "file":
            continue
        a(f"| {e['area']} | {_esc(e['check'])} | {e['kind']} | **{e['status']}** | {e['findings']} | {_esc(e['reason'])} |")
    skipped_files = [e for e in doc["coverage"] if e["kind"] == "file"]
    if skipped_files:
        a("")
        a(f"{len(skipped_files)} file(s) were skipped (size/symlink/unreadable); see coverage.json.")
    cr = doc.get("checklist_results") or []
    if cr:
        a("")
        a("### Manual checklist results")
        a("")
        counts: Dict[str, Dict[str, int]] = {}
        for c in cr:
            counts.setdefault(c["checklist"], {"pass": 0, "fail": 0, "n/a": 0, "untested": 0})[c["result"]] += 1
        a("| Checklist | pass | fail | n/a | untested |")
        a("|---|---|---|---|---|")
        for k in sorted(counts):
            c = counts[k]
            a(f"| {k} | {c['pass']} | {c['fail']} | {c['n/a']} | {c['untested']} |")
    a("")

    # 5. Attack paths
    if doc.get("attack_paths"):
        a("## 5. Attack paths")
        a("")
        for ap in doc["attack_paths"]:
            a(f"### {ap['id']}: {ap['title']} ({ap['severity']})")
            a("")
            a(f"Chain: {' → '.join(ap['steps'])}")
            a("")
            a(ap["narrative"])
            a("")

    # 6. Findings
    open_f = [f for f in findings if f.status in OPEN_STATUSES]
    a("## 6. Findings")
    a("")
    if not open_f:
        a("No open findings from the checks that ran.")
        a("")
    else:
        a("| ID | Severity | Status | Confidence | Title | Location |")
        a("|---|---|---|---|---|---|")
        for f in open_f:
            a(f"| [{f.id}](#{f.id.lower()}) | {f.severity} | {f.status} | {f.confidence} | {_esc(f.title)} | `{_esc(f.location.short())}` |")
        a("")
        for f in open_f:
            a(f"### {f.id}")
            a("")
            a(f"**{f.title}**")
            a("")
            a(f"- **Severity:** {f.severity}" + (f" · **CVSS 3.1:** {f.cvss_score} (`{f.cvss_vector}`)" if f.cvss_score is not None else ""))
            a(f"- **Status / confidence:** {f.status} / {f.confidence}")
            a(f"- **Location:** `{f.location.short()}`")
            if f.cwe or f.owasp:
                a(f"- **Classification:** {', '.join(f.cwe + f.owasp)}")
            a(f"- **Detected by:** {', '.join(f.sources)} · rule `{f.rule_id}` · fingerprint `{f.fingerprint}`")
            if f.location.snippet:
                a("")
                a("```")
                a(f.location.snippet)
                a("```")
            for label, val in (("Description", f.description), ("Evidence", f.evidence), ("Impact", f.impact),
                               ("Triage note", f.triage_reason)):
                if val:
                    a("")
                    a(f"**{label}.** {val}")
            if f.validation_steps:
                a("")
                a("**Safe validation steps.**")
                a("")
                for i, s in enumerate(f.validation_steps, 1):
                    a(f"{i}. {s}")
            a("")
            a(f"**Remediation.** {f.remediation}")
            if f.patch:
                a("")
                a("Suggested patch (not applied):")
                a("")
                a("```diff")
                a(f.patch.rstrip())
                a("```")
            if f.regression_test:
                a("")
                a("**Regression test.**")
                a("")
                a("```")
                a(f.regression_test.rstrip())
                a("```")
            a("")

    closed = [f for f in findings if f.status not in OPEN_STATUSES]
    if closed:
        a("## 7. Triaged and closed items")
        a("")
        a("Kept for auditability. Every decision has a recorded reason.")
        a("")
        a("| ID | Status | Title | Location | Reason |")
        a("|---|---|---|---|---|")
        for f in closed:
            a(f"| {f.id} | {f.status} | {_esc(f.title)} | `{_esc(f.location.short())}` | {_esc(f.triage_reason)} |")
        a("")

    # 8. Limitations
    a("## 8. Untested areas and limitations")
    a("")
    gaps = [e for e in doc["coverage"] if e["status"] in ("skipped", "unavailable", "error") and e["kind"] != "file"]
    for e in gaps:
        a(f"- **{e['area']} / {e['check']}** — {e['status']}: {e['reason']}")
    for lim in doc.get("limitations", []):
        a(f"- {lim}")
    a("- Regex-based built-in rules do not perform inter-procedural data-flow analysis; absence of a match is not absence of a flaw.")
    a("- Dependency findings report known advisories only; reachability and zero-days are not assessed.")
    for w in doc.get("triage_warnings", []):
        a(f"- Triage warning: {w}")
    a("")

    # 9. Roadmap
    a("## 9. Prioritized remediation roadmap")
    a("")
    buckets = [
        ("Immediate (0–7 days)", lambda f: f.severity == "critical" or (f.severity == "high" and f.status == "confirmed")),
        ("Short term (≤30 days)", lambda f: f.severity == "high" or (f.severity == "medium" and f.status == "confirmed")),
        ("Planned (≤90 days)", lambda f: f.severity == "medium" or f.status == "missing-control"),
        ("Hardening backlog", lambda f: True),
    ]
    placed = set()
    for name, pred in buckets:
        items = [f for f in open_f if f.id not in placed and pred(f)]
        if not items:
            continue
        a(f"**{name}**")
        a("")
        for f in items:
            placed.add(f.id)
            a(f"- [ ] {f.id} — {f.title} (`{f.location.short()}`)")
        a("")
    if not open_f:
        a("Nothing open. Close the gaps in section 8 next.")
        a("")

    # 10. Regression
    a("## 10. Regression testing")
    a("")
    rt = [f for f in findings if f.regression_test]
    if rt:
        for f in rt:
            a(f"- {f.id}: see regression test in finding details.")
    else:
        a("No finding-specific regression tests recorded yet. For each fix (Mode 4), add a test that fails on the vulnerable code and passes after the fix.")
    a("")
    a("Run continuous mode to detect regressions by fingerprint: "
      "`appsec.py ci --baseline .appsec/baseline.json --fail-on high`.")
    a("")
    a("---")
    a("Machine-readable outputs: `findings.json` (full results), `report.sarif` (SARIF 2.1.0), "
      "`coverage.json`, `inventory.json`, `stack.json`, `activity.log.jsonl` (audit trail).")
    return "\n".join(L) + "\n"
