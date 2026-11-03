"""Scan orchestration: detect -> inventory -> built-in rules -> structural
checks -> external tools -> (opt-in) OSV API -> score -> dedupe -> write."""

import json
import os
import subprocess
import time
from typing import Dict, List, Optional

from . import TOOL_NAME, VERSION, adapters, cvss, detect, inventory, manual, osv, report, rules, sarif, supplychain
from .coverage import Coverage
from .findings import Finding, OPEN_STATUSES, finalize, summarize
from .log import ActivityLog
from .walker import walk

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BUILTIN_RULES = os.path.join(SKILL_DIR, "rules")

# Areas the engine cannot assess automatically. Always listed so reports never
# imply they were covered by the scan alone.
MANUAL_ONLY_AREAS = [
    ("authorization", "Object/function-level authorization (BOLA/IDOR/BFLA) on every route - requires code tracing (checklists/authorization.md)"),
    ("business-logic", "Business logic, race conditions and transaction integrity (checklists/business-logic-and-race-conditions.md)"),
    ("authentication", "Authentication flows: login, reset, MFA, session lifecycle (checklists/authentication.md, session-jwt-oauth.md)"),
    ("data-flow", "Source-to-sink data-flow tracing across components"),
    ("threat-model", "Threat model and attack-path chaining (references/threat-modeling.md)"),
    ("runtime", "Runtime behaviour, deployed configuration and infrastructure state (needs authorized DAST/cloud review)"),
    ("privacy", "Data classification, retention, backups and disaster recovery (checklists/privacy-and-data-protection.md)"),
]


def _now(deterministic: bool) -> Optional[str]:
    if deterministic:
        return None
    sde = os.environ.get("SOURCE_DATE_EPOCH")
    t = time.gmtime(int(sde)) if sde and sde.isdigit() else time.gmtime()
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", t)


def _git_commit(root: str) -> str:
    try:
        r = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"], capture_output=True, timeout=10)
        return r.stdout.decode().strip() if r.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _write_json(path: str, data) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True, default=lambda o: o.to_dict() if hasattr(o, "to_dict") else str(o))
        fh.write("\n")


def score(findings: List[Finding]) -> None:
    for f in findings:
        if f.cvss_vector and f.cvss_score is None:
            try:
                f.cvss_score = cvss.base_score(f.cvss_vector)
            except cvss.CVSSError:
                f.cvss_vector = ""


def run_scan(root: str, cfg: Dict, out: str, *, offline: bool = False, osv_api: bool = False,
             deterministic: bool = False, tools_only: Optional[List[str]] = None, no_tools: bool = False) -> Dict:
    root = os.path.abspath(root)
    os.makedirs(os.path.join(out, "raw"), exist_ok=True)
    log_path = os.path.join(out, "activity.log.jsonl")
    if os.path.exists(log_path):
        os.remove(log_path)
    log = ActivityLog(log_path, deterministic=deterministic)
    cov = Coverage()
    profile = cfg["profile"]
    started = _now(deterministic)
    log.event("scan.start", root="." if deterministic else root, mode=cfg["mode"], engine=VERSION,
              config=cfg.get("_path"), offline=offline, osv_api=osv_api)

    files, skipped = walk(root, cfg["effective_excludes"], int(cfg["max_file_size_kb"]))
    log.event("files.enumerated", included=len(files), skipped=len(skipped))
    for rel, why in skipped:
        cov.record("files", rel, "skipped", why, kind="file")

    stack = detect.detect(root, files)
    log.event("stack.detected", **{k: stack[k] for k in ("primary_languages", "frameworks", "iac", "ci")})
    for lang in stack["unsupported_languages"]:
        cov.record("stack", f"language:{lang}", "unavailable",
                   "no built-in rules or stack guide; generic checklists only")

    findings: List[Finding] = []

    # Built-in rule packs
    dirs = [BUILTIN_RULES] + [os.path.join(root, d) for d in cfg.get("custom_rule_dirs", [])]
    packs, errors = rules.load_packs(dirs)
    for e in errors:
        cov.record("rules", e.split(":")[0], "error", e)
        log.event("rules.error", error=e)
    secret_rules = [r for rs in packs.values() for r in rs if r.secret and r.kind == "line"]
    inv = inventory.build(root, files, redactor=lambda s: rules.redact_snippet(s, secret_rules, aggressive=True))
    log.event("inventory.built", summary=inv["summary"])
    cov.record("inventory", "attack-surface-inventory", "ran", findings=0)
    enabled = cfg["rule_packs"].get("enabled", ["all"])
    disabled_packs = set(cfg["rule_packs"].get("disabled", []))
    for name in sorted(packs):
        if name in disabled_packs or ("all" not in enabled and name not in enabled):
            cov.record("rules", f"pack:{name}", "skipped", "disabled by configuration")
            continue
        fs, errs = rules.run(root, files, packs[name], profile["min_confidence"],
                             cfg.get("disabled_rules"), cfg.get("severity_overrides"))
        findings.extend(fs)
        cov.record("rules", f"pack:{name}", "ran", f"{len(packs[name])} rules, {len(errs)} unreadable files", len(fs))
        log.event("rules.pack", pack=name, rules=len(packs[name]), findings=len(fs))

    # Structural supply-chain checks
    sc = supplychain.check_lockfiles(stack) + supplychain.check_typosquats(root, files)
    findings.extend(sc)
    cov.record("supply-chain", "lockfiles+typosquat-heuristic", "ran", findings=len(sc))
    tracked, why = supplychain.check_tracked_env_files(root)
    findings.extend(tracked)
    cov.record("secrets", "git-tracked-sensitive-files", "ran" if not why else "not-applicable", why, len(tracked))
    if profile.get("dependency_tree_scan"):
        dt, n = supplychain.check_dependency_tree(root)
        findings.extend(dt)
        cov.record("supply-chain", "installed-npm-install-hooks", "ran" if n else "not-applicable",
                   f"{n} installed packages read statically" if n else "no node_modules present", len(dt))
    else:
        cov.record("supply-chain", "installed-npm-install-hooks", "skipped", f"runs in deep mode only (mode={cfg['mode']})")

    # External tools
    tcfg = cfg.get("tools", {})
    wanted = profile["tools"]
    disabled_tools = set(tcfg.get("disabled", []))
    timeout = int(tcfg.get("timeout_seconds", 900))
    for ad in adapters.REGISTRY:
        area = ad.area
        if tools_only is not None and ad.name not in tools_only:
            continue
        if no_tools:
            cov.record(area, ad.name, "skipped", "--no-tools given", kind="tool")
            continue
        if ad.name in disabled_tools:
            cov.record(area, ad.name, "skipped", "disabled by configuration", kind="tool")
            continue
        if wanted != "all" and ad.name not in wanted:
            cov.record(area, ad.name, "skipped", f"not part of {cfg['mode']} mode profile", kind="tool")
            continue
        if not ad.applies(stack):
            cov.record(area, ad.name, "not-applicable", "stack does not use this technology", kind="tool")
            continue
        if ad.network and (offline or not cfg.get("allow_network_tools", True)):
            cov.record(area, ad.name, "skipped", "needs network (vulnerability DB/rules) and offline mode is on", kind="tool")
            continue
        if not ad.available():
            cov.record(area, ad.name, "unavailable", f"not installed - {ad.install}", kind="tool")
            continue
        try:
            fs = ad.run(root, os.path.join(out, "raw"), cfg, stack, timeout, log)
            findings.extend(fs)
            cov.record(area, ad.name, "ran", findings=len(fs), kind="tool")
            log.event("tool.done", tool=ad.name, findings=len(fs))
        except Exception as e:  # noqa: BLE001 - every tool failure must be recorded, not raised
            cov.record(area, ad.name, "error", str(e)[:300], kind="tool")
            log.event("tool.error", tool=ad.name, error=str(e)[:300])

    # Built-in OSV lookup (opt-in, sends package names+versions to api.osv.dev)
    if osv_api or cfg.get("osv_api"):
        if offline:
            cov.record("sca", "osv-api", "skipped", "offline mode")
        else:
            try:
                fs, n = osv.scan(root, files)
                findings.extend(fs)
                cov.record("sca", "osv-api", "ran", f"{n} pinned packages queried", len(fs))
                log.event("osv.done", packages=n, findings=len(fs))
            except Exception as e:  # noqa: BLE001
                cov.record("sca", "osv-api", "error", str(e)[:300])
    else:
        cov.record("sca", "osv-api", "skipped", "opt-in: pass --osv-api (sends package names/versions to api.osv.dev)")

    if not any(e["status"] == "ran" and e["area"] in ("sca", "sca+iac") for e in cov.entries):
        cov.record("sca", "known-vulnerability-lookup", "unavailable",
                   "no SCA source ran - dependency CVEs were NOT checked. Install osv-scanner/trivy or use --osv-api.")

    for area, desc in MANUAL_ONLY_AREAS:
        cov.record(area, desc, "skipped", "requires analyst review (SKILL.md phases 3-7)", kind="manual")

    score(findings)
    findings = finalize(findings)
    log.event("scan.findings", total=len(findings), open=sum(f.status in OPEN_STATUSES for f in findings))

    doc = {
        "schema_version": "1",
        "tool": {"name": TOOL_NAME, "version": VERSION},
        "run": {"mode": cfg["mode"], "target": os.path.basename(root), "git_commit": _git_commit(root),
                "started": started, "finished": _now(deterministic), "config": cfg.get("_path"),
                "offline": offline, "files_scanned": len(files), "fail_on": cfg.get("fail_on")},
        "stack": stack,
        "inventory_summary": inv["summary"],
        "trust_boundary_hints": inv["trust_boundary_hints"],
        "coverage": cov.to_list(),
        "findings": [f.to_dict() for f in findings],
    }
    _write_json(os.path.join(out, "stack.json"), stack)
    _write_json(os.path.join(out, "inventory.json"), inv)
    _write_json(os.path.join(out, "coverage.json"), cov.to_list())
    _write_json(os.path.join(out, "automated-findings.json"), doc)
    log.event("scan.end")
    return build_outputs(out, None, deterministic=deterministic)


def build_outputs(out: str, manual_path: Optional[str], deterministic: bool = False) -> Dict:
    """Merge automated results with the analyst's manual file and write
    findings.json, report.md and report.sarif. Idempotent."""
    with open(os.path.join(out, "automated-findings.json"), encoding="utf-8") as fh:
        doc = json.load(fh)
    findings = [Finding.from_dict(d) for d in doc["findings"]]
    mdoc: Dict = {}
    warnings: List[str] = []
    if manual_path:
        mdoc = manual.load(manual_path)
        errs = manual.validate(mdoc)
        if errs:
            raise SystemExit("manual findings file is invalid:\n  " + "\n  ".join(errs))
        findings, warnings = manual.apply_triage(findings, mdoc)
        mf = manual.to_findings(mdoc)
        score(mf)
        findings = finalize(findings + mf)
    doc = dict(doc)
    doc["findings"] = [f.to_dict() for f in findings]
    doc["summary"] = summarize(findings)
    doc["attack_paths"] = mdoc.get("attack_paths", [])
    doc["checklist_results"] = mdoc.get("checklist_results", [])
    doc["limitations"] = mdoc.get("limitations", [])
    doc["executive_summary"] = mdoc.get("executive_summary", "")
    doc["posture_statement"] = mdoc.get("posture_statement", "")
    doc["threat_model"] = mdoc.get("threat_model", "")
    doc["triage_warnings"] = warnings
    doc["manual_review_included"] = bool(manual_path)
    doc["posture"] = report.posture(findings, doc["attack_paths"])
    _write_json(os.path.join(out, "findings.json"), doc)
    sarif.export(findings, os.path.join(out, "report.sarif"))
    with open(os.path.join(out, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(report.render(doc, findings))
    return doc
