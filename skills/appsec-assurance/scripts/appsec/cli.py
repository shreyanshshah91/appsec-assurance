"""Command-line interface.

Exit codes: 0 success, 1 security gate failed, 2 usage/runtime error, 3 out of scope.
"""

import argparse
import http.client
import json
import os
import shutil
import sys
from typing import List, Optional

from . import VERSION, adapters, baseline, config, cvss, dast, engine, manual, rules, scope
from .findings import SEVERITIES, Finding, OPEN_STATUSES, finalize, severity_at_least
from .log import ActivityLog


def _p(*a):
    print(*a, flush=True)


def cmd_doctor(args) -> int:
    _p(f"appsec-assurance {VERSION}  (python {sys.version.split()[0]})")
    _p("Built-in engine: OK (stdlib only)")
    packs, errs = rules.load_packs([engine.BUILTIN_RULES])
    _p(f"Rule packs: {len(packs)} packs, {sum(len(v) for v in packs.values())} rules" + (f", {len(errs)} errors" if errs else ""))
    for e in errs:
        _p(f"  ! {e}")
    _p("")
    _p(f"{'tool':<13} {'area':<9} {'net':<4} status")
    for ad in adapters.REGISTRY:
        status = shutil.which(ad.binary) or f"missing -> {ad.install}"
        _p(f"{ad.name:<13} {ad.area:<9} {'yes' if ad.network else 'no':<4} {status}")
    _p("")
    _p("Missing tools are optional; their checks are recorded as 'unavailable' in coverage.json.")
    return 0 if not errs else 2


def _gate(findings: List[Finding], threshold: Optional[str]) -> int:
    if not threshold:
        return 0
    blocking = [f for f in findings if f.status in OPEN_STATUSES and severity_at_least(f.severity, threshold)]
    if blocking:
        _p(f"GATE FAILED: {len(blocking)} open finding(s) at or above '{threshold}'.")
        return 1
    _p(f"Gate passed: no open findings at or above '{threshold}'.")
    return 0


def _print_summary(doc, out):
    s = doc["summary"]["by_severity"]
    _p(f"Open findings: {doc['summary']['open_total']}  " + "  ".join(f"{k}={v}" for k, v in s.items()))
    _p(f"Posture indicator: {doc['posture']['level']}")
    gaps = [e for e in doc["coverage"] if e["status"] in ("unavailable", "error") and e["kind"] != "file"]
    if gaps:
        _p(f"Coverage gaps ({len(gaps)}): " + ", ".join(sorted({e['check'][:40] for e in gaps})))
    _p(f"Reports: {os.path.join(out, 'report.md')}, findings.json, report.sarif")


def _scan(args):
    cfg = config.resolve(config.load(args.root, args.config), args.mode)
    if args.fail_on:
        cfg["fail_on"] = args.fail_on
    tools_only = [t.strip() for t in args.tools.split(",") if t.strip()] if args.tools else None
    if tools_only:
        unknown = sorted(set(tools_only) - {a.name for a in adapters.REGISTRY})
        if unknown:
            raise SystemExit(f"unknown tool(s): {', '.join(unknown)}; known: {', '.join(a.name for a in adapters.REGISTRY)}")
    return cfg, engine.run_scan(args.root, cfg, args.out, offline=args.offline, osv_api=args.osv_api,
                                deterministic=args.deterministic, tools_only=tools_only, no_tools=args.no_tools)


def cmd_scan(args) -> int:
    cfg, doc = _scan(args)
    _print_summary(doc, args.out)
    findings = [Finding.from_dict(d) for d in doc["findings"]]
    return _gate(findings, args.fail_on)


def cmd_report(args) -> int:
    if not os.path.isfile(os.path.join(args.input, "automated-findings.json")):
        _p(f"error: {args.input}/automated-findings.json not found; run `scan` first")
        return 2
    doc = engine.build_outputs(args.input, args.manual, deterministic=args.deterministic)
    _print_summary(doc, args.input)
    for w in doc.get("triage_warnings", []):
        _p(f"warning: {w}")
    return 0


def cmd_validate(args) -> int:
    try:
        doc = manual.load(args.file)
    except (OSError, ValueError) as e:
        _p(f"error: cannot read {args.file}: {e}")
        return 2
    errs = manual.validate(doc)
    if errs:
        _p(f"{args.file}: {len(errs)} problem(s)")
        for e in errs:
            _p(f"  - {e}")
        return 2
    _p(f"{args.file}: valid ({len(doc.get('findings', []))} findings, {len(doc.get('triage', []))} triage decisions)")
    return 0


def cmd_cvss(args) -> int:
    try:
        s, r = cvss.score_and_rating(args.vector)
    except cvss.CVSSError as e:
        _p(f"error: {e}")
        return 2
    _p(json.dumps({"vector": args.vector, "base_score": s, "severity": r}))
    return 0


def cmd_ci(args) -> int:
    threshold = args.fail_on
    args.fail_on = None
    _, doc = _scan(args)
    current = [Finding.from_dict(d) for d in doc["findings"]]
    base = []
    if args.baseline and os.path.isfile(args.baseline):
        base = baseline.load_findings(args.baseline)
    else:
        _p("No baseline found: every open finding is treated as new.")
    d = baseline.diff(base, current)
    blocking = baseline.gate(d["new"], threshold)
    with open(os.path.join(args.out, "diff.json"), "w", encoding="utf-8") as fh:
        json.dump({k: [f.to_dict() for f in v] for k, v in d.items()} | {"threshold": threshold,
                  "blocking": [f.fingerprint for f in blocking]}, fh, indent=2, sort_keys=True)
    with open(os.path.join(args.out, "diff.md"), "w", encoding="utf-8") as fh:
        fh.write(baseline.to_markdown(d, threshold, blocking))
    _p(f"new={len(d['new'])} fixed={len(d['fixed'])} unchanged={len(d['unchanged'])} blocking={len(blocking)}")
    _p(f"Diff: {os.path.join(args.out, 'diff.md')}")
    if blocking:
        _p(f"GATE FAILED: {len(blocking)} new finding(s) at or above '{threshold}'.")
        return 1
    return 0


def cmd_baseline(args) -> int:
    path = os.path.join(args.input, "findings.json")
    if not os.path.isfile(path):
        _p(f"error: {path} not found")
        return 2
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    keep = [f for f in doc["findings"] if f["status"] in OPEN_STATUSES]
    os.makedirs(os.path.dirname(os.path.abspath(args.write)), exist_ok=True)
    with open(args.write, "w", encoding="utf-8") as fh:
        json.dump({"schema_version": "1", "source_commit": doc["run"].get("git_commit"), "findings": keep},
                  fh, indent=2, sort_keys=True)
        fh.write("\n")
    _p(f"Baseline written: {args.write} ({len(keep)} open findings). Existing risks in a baseline are hidden from CI gates; review it periodically.")
    return 0


def cmd_diff(args) -> int:
    d = baseline.diff(baseline.load_findings(args.baseline), baseline.load_findings(args.current))
    blocking = baseline.gate(d["new"], args.fail_on)
    sys.stdout.write(baseline.to_markdown(d, args.fail_on, blocking))
    return 1 if blocking else 0


def cmd_scope_check(args) -> int:
    try:
        sc = scope.load(args.scope)
    except (OSError, ValueError) as e:
        _p(f"DENIED: cannot load scope file: {e}")
        return 3
    ok, why = scope.check(sc, args.target, args.activity)
    _p(("ALLOWED: " if ok else "DENIED: ") + why)
    return 0 if ok else 3


def cmd_dast(args) -> int:
    auto = os.path.join(args.out, "automated-findings.json")
    if not os.path.isfile(auto):
        _p("error: run `scan` first so DAST results can be merged into the report")
        return 2
    try:
        sc = scope.load(args.scope)
        target = scope.normalize_target(args.target)  # one canonical URL for the gate and the request
    except (OSError, ValueError) as e:
        _p(f"DENIED: {e}")
        return 3
    ok, why = scope.check(sc, target, "dast-passive")
    log = ActivityLog(os.path.join(args.out, "activity.log.jsonl"))
    log.event("dast.scope-check", target=target, allowed=ok, reason=why)
    if not ok:
        _p(f"DENIED: {why}")
        return 3
    if not args.approved:
        _p("Refusing to send traffic without --approved (the user must approve this specific run in chat).")
        return 3
    found = []
    try:
        status, headers = dast.fetch(target)
        log.event("dast.request", method="GET", target=target, status=status)
        found += dast.analyze_headers(target, status, headers)
    except (OSError, ValueError, http.client.HTTPException) as e:
        _p(f"error: request failed: {e}")
        return 2
    if args.zap:
        try:
            found += dast.zap_baseline(target, os.path.join(args.out, "raw"), 1800)
            log.event("dast.zap-baseline", target=target, findings=len(found))
        except (FileNotFoundError, OSError, ValueError) as e:
            _p(f"warning: ZAP baseline not run: {e}")
    with open(auto, encoding="utf-8") as fh:
        doc = json.load(fh)
    existing = [Finding.from_dict(d) for d in doc["findings"]]
    merged = finalize(existing + found)
    doc["findings"] = [f.to_dict() for f in merged]
    doc["coverage"].append({"area": "dast", "check": f"passive-headers:{target}", "kind": "dast",
                            "status": "ran", "reason": why, "findings": len(found)})
    with open(auto, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
    out = engine.build_outputs(args.out, args.manual)
    _p(f"Passive DAST: {len(found)} finding(s) merged.")
    _print_summary(out, args.out)
    return 0


def cmd_rules(args) -> int:
    packs, errs = rules.load_packs([engine.BUILTIN_RULES])
    for name in sorted(packs):
        for r in packs[name]:
            _p(f"{r.id:<36} {r.raw['severity']:<8} {r.raw['confidence']:<6} {name:<16} {r.raw['title']}")
    for e in errs:
        _p(f"! {e}")
    return 2 if errs else 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="appsec.py", description="appsec-assurance security assessment engine")
    ap.add_argument("--version", action="version", version=VERSION)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("doctor", help="show engine, rules and external tool availability").set_defaults(fn=cmd_doctor)
    sub.add_parser("rules", help="list built-in rules").set_defaults(fn=cmd_rules)

    def scan_args(p):
        p.add_argument("--root", default=".", help="repository to assess (default: cwd)")
        p.add_argument("--mode", choices=config.MODES, help="assessment mode (default: config or comprehensive)")
        p.add_argument("--out", default=".appsec/out", help="output directory")
        p.add_argument("--config", help="config file (default: .appsec/config.json if present)")
        p.add_argument("--offline", action="store_true", help="never run tools that need network access")
        p.add_argument("--osv-api", action="store_true", help="query api.osv.dev with package names/versions (opt-in)")
        p.add_argument("--tools", help="comma-separated subset of external tools to run")
        p.add_argument("--no-tools", action="store_true", help="built-in checks only")
        p.add_argument("--deterministic", action="store_true", help="omit timestamps for reproducible output")

    p = sub.add_parser("scan", help="run automated assessment")
    scan_args(p)
    p.add_argument("--fail-on", choices=SEVERITIES, help="exit 1 if open findings at/above this severity")
    p.set_defaults(fn=cmd_scan)

    p = sub.add_parser("report", help="merge manual review and regenerate reports")
    p.add_argument("--in", dest="input", default=".appsec/out")
    p.add_argument("--manual", help="manual findings JSON (templates/manual-findings.template.json)")
    p.add_argument("--deterministic", action="store_true")
    p.set_defaults(fn=cmd_report)

    p = sub.add_parser("validate", help="validate a manual findings file")
    p.add_argument("file")
    p.set_defaults(fn=cmd_validate)

    p = sub.add_parser("cvss", help="compute a CVSS 3.1 base score")
    p.add_argument("vector")
    p.set_defaults(fn=cmd_cvss)

    p = sub.add_parser("ci", help="continuous mode: scan, diff against baseline, gate on new findings")
    scan_args(p)
    p.add_argument("--baseline", default=".appsec/baseline.json")
    p.add_argument("--fail-on", choices=SEVERITIES, default="high")
    p.set_defaults(fn=cmd_ci)

    p = sub.add_parser("baseline", help="write current open findings as the accepted baseline")
    p.add_argument("--in", dest="input", default=".appsec/out")
    p.add_argument("--write", default=".appsec/baseline.json")
    p.set_defaults(fn=cmd_baseline)

    p = sub.add_parser("diff", help="diff two findings files")
    p.add_argument("--baseline", required=True)
    p.add_argument("--current", required=True)
    p.add_argument("--fail-on", choices=SEVERITIES, default="high")
    p.set_defaults(fn=cmd_diff)

    p = sub.add_parser("scope-check", help="check a target/activity against the scope file")
    p.add_argument("--scope", default=".appsec/scope.json")
    p.add_argument("--target", required=True)
    p.add_argument("--activity", required=True, choices=scope.ACTIVITIES + scope.FORBIDDEN_ALWAYS)
    p.set_defaults(fn=cmd_scope_check)

    p = sub.add_parser("dast", help="passive DAST (single GET + header analysis) against an in-scope target")
    p.add_argument("--scope", default=".appsec/scope.json")
    p.add_argument("--target", required=True)
    p.add_argument("--out", default=".appsec/out")
    p.add_argument("--manual")
    p.add_argument("--approved", action="store_true", help="confirms the user approved this run in chat")
    p.add_argument("--zap", action="store_true", help="also run ZAP baseline (passive) if installed")
    p.set_defaults(fn=cmd_dast)
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except SystemExit as e:
        if isinstance(e.code, str):
            _p(f"error: {e.code}")
            return 2
        raise
    except KeyboardInterrupt:
        return 2
