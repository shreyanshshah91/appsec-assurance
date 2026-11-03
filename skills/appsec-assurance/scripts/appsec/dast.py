"""Passive dynamic checks against an in-scope target: a single GET request,
inspecting response headers and cookies. No payloads, no crawling, no fuzzing.
Optional ZAP baseline (passive) if `zap-baseline.py` is installed."""

import http.client
import json
import os
import shutil
import subprocess
import urllib.parse
from typing import Dict, List, Tuple

from .findings import Finding, Location

A05 = "A05:2021"
HEADER_CHECKS = [
    ("strict-transport-security", "DAST-HSTS-MISSING", "Strict-Transport-Security header missing", "medium", ["CWE-319"], "https-only"),
    ("content-security-policy", "DAST-CSP-MISSING", "Content-Security-Policy header missing", "medium", ["CWE-693"], "html"),
    ("x-content-type-options", "DAST-XCTO-MISSING", "X-Content-Type-Options: nosniff missing", "low", ["CWE-693"], "any"),
    ("referrer-policy", "DAST-REFERRER-POLICY-MISSING", "Referrer-Policy header missing", "low", ["CWE-200"], "html"),
]


def fetch(url: str, timeout: int = 15) -> Tuple[int, List[Tuple[str, str]]]:
    p = urllib.parse.urlparse(url)
    conn_cls = http.client.HTTPSConnection if p.scheme == "https" else http.client.HTTPConnection
    if not p.hostname:
        raise ValueError(f"cannot parse host from {url!r}")
    conn = conn_cls(p.hostname, p.port, timeout=timeout)
    path = (p.path or "/") + (f"?{p.query}" if p.query else "")
    conn.request("GET", path, headers={"User-Agent": "appsec-assurance-passive-check"})
    resp = conn.getresponse()
    headers = resp.getheaders()
    resp.read(65536)
    conn.close()
    return resp.status, headers


def analyze_headers(url: str, status: int, headers: List[Tuple[str, str]]) -> List[Finding]:
    h: Dict[str, List[str]] = {}
    for k, v in headers:
        h.setdefault(k.lower(), []).append(v)
    out = []
    is_https = urllib.parse.urlparse(url).scheme.lower() == "https"
    ctype = ";".join(h.get("content-type", [""])).lower()
    is_html = "html" in ctype or not ctype

    def add(rule, title, sev, cwe, evidence, remediation, status_="missing-control"):
        out.append(Finding(rule_id=rule, title=title, severity=sev, category="security-headers",
                           status=status_, confidence="high", location=Location(path=url),
                           evidence=evidence, remediation=remediation, cwe=cwe, owasp=[A05],
                           sources=["dast:passive-headers"]))

    for name, rule, title, sev, cwe, when in HEADER_CHECKS:
        if when == "https-only" and not is_https:
            continue
        if when == "html" and not is_html:
            continue
        if name not in h:
            add(rule, title, sev, cwe, f"GET {url} -> {status}; header absent.",
                f"Set the {name} header on all responses (via framework middleware or reverse proxy).")
    if is_html and "content-security-policy" not in h and "x-frame-options" not in h:
        add("DAST-CLICKJACKING", "No frame-ancestors CSP or X-Frame-Options", "medium", ["CWE-1021"],
            f"GET {url} -> {status}; neither header present.", "Set CSP frame-ancestors 'none' (or 'self').")
    csp = " ".join(h.get("content-security-policy", []))
    if csp and ("'unsafe-inline'" in csp or "'unsafe-eval'" in csp or "*" in csp.split()):
        add("DAST-CSP-WEAK", "Content-Security-Policy allows unsafe sources", "low", ["CWE-693"],
            f"CSP: {csp[:300]}", "Remove 'unsafe-inline'/'unsafe-eval'/wildcards; use nonces or hashes.", "confirmed")
    acao = h.get("access-control-allow-origin", [])
    if "*" in acao and "true" in [v.lower() for v in h.get("access-control-allow-credentials", [])]:
        add("DAST-CORS-WILDCARD-CREDS", "CORS wildcard with credentials", "high", ["CWE-942"],
            "Access-Control-Allow-Origin: * with Allow-Credentials: true", "Use an explicit origin allowlist.", "confirmed")
    for v in h.get("server", []) + h.get("x-powered-by", []):
        if any(ch.isdigit() for ch in v):
            add("DAST-VERSION-DISCLOSURE", "Server/framework version disclosed", "info", ["CWE-200"],
                f"Header value: {v}", "Suppress version banners (server_tokens off, remove X-Powered-By).", "confirmed")
    for cookie in h.get("set-cookie", []):
        low = cookie.lower()
        name = cookie.split("=", 1)[0]
        missing = [f for f in ("httponly", "samesite") if f not in low]
        if is_https and "secure" not in low:
            missing.append("secure")
        if missing:
            add("DAST-COOKIE-FLAGS", f"Cookie '{name}' missing {', '.join(missing)}", "medium" if "secure" in missing or "httponly" in missing else "low",
                ["CWE-614", "CWE-1004"], f"Set-Cookie: {name}=… (value omitted)",
                "Set Secure, HttpOnly and SameSite on session/auth cookies.", "confirmed")
    return out


def zap_baseline(url: str, raw: str, timeout: int) -> List[Finding]:
    if not shutil.which("zap-baseline.py"):
        raise FileNotFoundError("zap-baseline.py not installed")
    out = os.path.join(raw, "zap-baseline.json")
    subprocess.run(["zap-baseline.py", "-t", url, "-J", out, "-I"], capture_output=True, timeout=timeout)
    with open(out, encoding="utf-8") as fh:
        data = json.load(fh)
    sev = {"3": "high", "2": "medium", "1": "low", "0": "info"}
    res = []
    for site in data.get("site", []):
        for a in site.get("alerts", []):
            inst = (a.get("instances") or [{}])[0]
            res.append(Finding(rule_id=f"zap:{a.get('pluginid')}", title=a.get("alert", "ZAP alert"),
                               severity=sev.get(str(a.get("riskcode")), "info"), category="dast",
                               status="unverified", confidence="medium",
                               location=Location(path=inst.get("uri", url)),
                               evidence=(inst.get("evidence") or "")[:300],
                               description=(a.get("desc") or "")[:1500], remediation=(a.get("solution") or "")[:1500],
                               cwe=[f"CWE-{a['cweid']}"] if str(a.get("cweid", "")).isdigit() and a["cweid"] != "-1" else [],
                               sources=["zap-baseline"]))
    return res
