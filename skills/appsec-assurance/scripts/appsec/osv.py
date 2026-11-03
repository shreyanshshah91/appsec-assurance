"""Built-in, opt-in SCA using the public OSV.dev API (no tool install needed).

Privacy note: this sends package names and versions (never source code) to
api.osv.dev. It is OFF by default; enable with --osv-api or "osv_api": true
after the user agrees.
"""

import json
import os
import re
import urllib.request
from typing import Callable, Dict, List, Optional, Tuple

from . import cvss
from .findings import Finding, Location, normalize_severity
from .walker import read_text

API = "https://api.osv.dev/v1"
Pkg = Tuple[str, str, str, str]  # ecosystem, name, version, manifest


def _http(url: str, payload: Optional[Dict] = None, timeout: int = 30) -> Dict:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET",
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "appsec-assurance"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec - fixed https host
        return json.loads(resp.read().decode("utf-8"))


def collect_packages(root: str, files: List[str]) -> List[Pkg]:
    pkgs: List[Pkg] = []
    for rel in files:
        base = os.path.basename(rel)
        try:
            if base == "package-lock.json":
                data = json.loads(read_text(root, rel))
                for path, meta in (data.get("packages") or {}).items():
                    if path and meta.get("version") and "node_modules/" in path:
                        name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
                        pkgs.append(("npm", name, meta["version"], rel))
                for name, meta in (data.get("dependencies") or {}).items() if not data.get("packages") else []:
                    if meta.get("version"):
                        pkgs.append(("npm", name, meta["version"], rel))
            elif re.match(r"requirements[\w.\-]*\.txt$", base):
                for line in read_text(root, rel).splitlines():
                    m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)(\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.\-+!]+)", line)
                    if m:
                        pkgs.append(("PyPI", m.group(1), m.group(3), rel))
            elif base == "Pipfile.lock":
                data = json.loads(read_text(root, rel))
                for sect in ("default", "develop"):
                    for name, meta in (data.get(sect) or {}).items():
                        v = str(meta.get("version", "")).lstrip("=")
                        if v:
                            pkgs.append(("PyPI", name, v, rel))
            elif base in ("poetry.lock", "Cargo.lock", "uv.lock"):
                eco = "crates.io" if base == "Cargo.lock" else "PyPI"
                text = read_text(root, rel)
                for block in text.split("[[package]]")[1:]:
                    n = re.search(r'^name\s*=\s*"([^"]+)"', block, re.M)
                    v = re.search(r'^version\s*=\s*"([^"]+)"', block, re.M)
                    if n and v:
                        pkgs.append((eco, n.group(1), v.group(1), rel))
            elif base == "go.mod":
                for m in re.finditer(r"^\s*(?:require\s+)?([\w.\-]+\.[\w.\-/]+)\s+(v[\w.\-+]+)", read_text(root, rel), re.M):
                    pkgs.append(("Go", m.group(1), m.group(2), rel))
            elif base == "Gemfile.lock":
                for m in re.finditer(r"^    ([A-Za-z0-9_.\-]+) \(([^)\s]+)\)$", read_text(root, rel), re.M):
                    pkgs.append(("RubyGems", m.group(1), m.group(2), rel))
            elif base == "composer.lock":
                data = json.loads(read_text(root, rel))
                for p in (data.get("packages") or []) + (data.get("packages-dev") or []):
                    pkgs.append(("Packagist", p["name"], str(p["version"]).lstrip("v"), rel))
        except (OSError, ValueError, KeyError):
            continue
    return sorted(set(pkgs))


def _severity(vuln: Dict) -> Tuple[str, Optional[float], str]:
    vector = ""
    for s in vuln.get("severity", []) or []:
        if s.get("type") == "CVSS_V3" and str(s.get("score", "")).startswith("CVSS:3"):
            vector = s["score"]
            try:
                score, rating = cvss.score_and_rating(vector)
                return rating, score, vector
            except cvss.CVSSError:
                pass
    for src in [vuln.get("database_specific") or {}] + [(a.get("database_specific") or {}) for a in vuln.get("affected", [])]:
        if isinstance(src.get("severity"), str):
            return normalize_severity(src["severity"]), None, vector
    return "medium", None, vector


def _fixed_versions(vuln: Dict, name: str) -> List[str]:
    fixed = set()
    for a in vuln.get("affected", []) or []:
        if (a.get("package") or {}).get("name", "").lower() != name.lower():
            continue
        for r in a.get("ranges", []) or []:
            for e in r.get("events", []) or []:
                if "fixed" in e:
                    fixed.add(e["fixed"])
    return sorted(fixed)


def scan(root: str, files: List[str], http: Callable = _http, detail_cap: int = 300) -> Tuple[List[Finding], int]:
    pkgs = collect_packages(root, files)
    if not pkgs:
        return [], 0
    hits: List[Tuple[Pkg, str]] = []
    for i in range(0, len(pkgs), 1000):
        chunk = pkgs[i:i + 1000]
        q = {"queries": [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v, _ in chunk]}
        res = http(f"{API}/querybatch", q)
        for pkg, r in zip(chunk, res.get("results", [])):
            for v in (r or {}).get("vulns", []) or []:
                hits.append((pkg, v["id"]))
    details: Dict[str, Dict] = {}
    for vid in sorted({h[1] for h in hits})[:detail_cap]:
        details[vid] = http(f"{API}/vulns/{vid}")
    out = []
    for (eco, name, ver, manifest), vid in hits:
        d = details.get(vid, {"id": vid})
        sev, score, vector = _severity(d)
        fixed = _fixed_versions(d, name)
        cwes = sorted({c for c in (d.get("database_specific") or {}).get("cwe_ids", []) or []})
        aliases = [a for a in d.get("aliases", []) if a.startswith("CVE-")]
        out.append(Finding(
            rule_id=f"osv:{vid}", title=f"{name} {ver} ({eco}) affected by {vid}" + (f" / {aliases[0]}" if aliases else ""),
            severity=sev, category="vulnerable-dependency", status="unverified", confidence="high",
            location=Location(path=manifest, snippet=f"{name}@{ver}"),
            description=(d.get("summary") or d.get("details") or "")[:1500],
            evidence=f"OSV.dev reports {vid} affects {name} {ver}. Reachability not analyzed.",
            remediation=f"Upgrade {name} to {' or '.join(fixed)} or later." if fixed else "No fixed version listed; evaluate exposure, mitigations or replacement.",
            cwe=cwes, owasp=["A06:2021"], references=[f"https://osv.dev/vulnerability/{vid}"],
            cvss_vector=vector, cvss_score=score, sources=["osv-api"]))
    return out, len(pkgs)
