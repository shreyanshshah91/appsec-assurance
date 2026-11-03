"""External scanner adapters.

Each adapter declares when it applies, whether it needs network access, the
command(s) to run, and how to parse output. Most tools emit SARIF, which is
ingested generically. Adapters never install anything; a missing binary is
recorded as `unavailable` in the coverage ledger with an install hint.
"""

import glob
import json
import os
import shutil
import subprocess
from typing import Callable, Dict, List, Optional, Tuple

from ..findings import Finding, Location, normalize_severity
from ..sarif import ingest as ingest_sarif


class Adapter:
    def __init__(self, name: str, binary: str, area: str, install: str,
                 applies: Callable[[Dict], bool] = lambda s: True, network: bool = False,
                 secret_tool: bool = False, deep_only: bool = False):
        self.name, self.binary, self.area, self.install = name, binary, area, install
        self.applies, self.network, self.secret_tool = applies, network, secret_tool
        self.deep_only = deep_only

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def commands(self, root: str, raw: str, cfg: Dict, stack: Dict) -> List[Tuple[List[str], str, bool]]:
        """Return [(argv, output_path, capture_stdout_to_output)]."""
        raise NotImplementedError

    def ok_codes(self) -> Tuple[int, ...]:
        return (0, 1)  # most scanners exit 1 when they find issues

    def parse(self, output_path: str, root: str) -> List[Finding]:
        return ingest_sarif(output_path, self.name, root, secret_tool=self.secret_tool)

    def run(self, root: str, raw: str, cfg: Dict, stack: Dict, timeout: int, log) -> List[Finding]:
        findings: List[Finding] = []
        for argv, out_path, capture in self.commands(root, raw, cfg, stack):
            log.event("tool.exec", tool=self.name, argv=argv, network=self.network)
            if os.path.exists(out_path):
                os.remove(out_path)  # never parse a stale result from a previous run
            res = subprocess.run(argv, cwd=root, capture_output=True, timeout=timeout)
            if capture:
                with open(out_path, "wb") as fh:
                    fh.write(res.stdout)
            if res.returncode not in self.ok_codes() and not (os.path.isfile(out_path) and os.path.getsize(out_path) > 0):
                raise RuntimeError(f"exit {res.returncode}: {res.stderr.decode('utf-8', 'replace')[-500:]}")
            if os.path.isfile(out_path) and os.path.getsize(out_path) > 0:
                findings.extend(self.parse(out_path, root))
        return findings


class SarifAdapter(Adapter):
    def __init__(self, *a, argv: Callable[[str, str, Dict, Dict], List[List[str]]], stdout: bool = False, **kw):
        super().__init__(*a, **kw)
        self._argv, self._stdout = argv, stdout

    def commands(self, root, raw, cfg, stack):
        cmds = self._argv(root, raw, cfg, stack)
        out = []
        for i, argv in enumerate(cmds):
            path = os.path.join(raw, f"{self.name}{'-' + str(i) if i else ''}.sarif")
            argv = [a.replace("{OUT}", path) for a in argv]
            out.append((argv, path, self._stdout))
        return out


def _has(stack: Dict, key: str, *vals: str) -> bool:
    return any(v in stack.get(key, []) or v in stack.get("languages", {}) for v in vals)


def _semgrep_argv(root, raw, cfg, stack):
    configs = (cfg.get("tools", {}).get("semgrep", {}) or {}).get("config", ["p/default"])
    argv = ["semgrep", "scan", "--sarif", "--output", "{OUT}", "--metrics=off", "--quiet", "--disable-version-check"]
    for c in configs:
        argv += ["--config", c]
    return [argv + ["."]]


def _gitleaks_argv(root, raw, cfg, stack):
    argv = ["gitleaks", "detect", "--source", ".", "--no-banner", "--redact",
            "--report-format", "sarif", "--report-path", "{OUT}", "--exit-code", "0"]
    if not os.path.isdir(os.path.join(root, ".git")) or not cfg["profile"].get("git_history"):
        argv.append("--no-git")
    return [argv]


def _dockerfiles(root):
    hits = []
    for pat in ("**/Dockerfile", "**/Dockerfile.*", "**/*.Dockerfile"):
        hits += glob.glob(os.path.join(glob.escape(root), pat), recursive=True)
    return sorted({os.path.relpath(h, root) for h in hits if "node_modules" not in h})


class HadolintAdapter(Adapter):
    def commands(self, root, raw, cfg, stack):
        out = []
        for i, df in enumerate(_dockerfiles(root)):
            out.append((["hadolint", "-f", "sarif", "--no-fail", df], os.path.join(raw, f"hadolint-{i}.sarif"), True))
        return out


class JsonAuditAdapter(Adapter):
    """npm audit / pip-audit JSON output (no SARIF available)."""

    def commands(self, root, raw, cfg, stack):
        out_path = os.path.join(raw, f"{self.name}.json")
        if self.name == "npm-audit":
            if not os.path.isfile(os.path.join(root, "package-lock.json")):
                return []
            return [(["npm", "audit", "--json", "--package-lock-only"], out_path, True)]
        cmds = []
        for i, req in enumerate(sorted(glob.glob(os.path.join(glob.escape(root), "requirements*.txt")))):
            p = os.path.join(raw, f"pip-audit-{i}.json")
            cmds.append((["pip-audit", "-r", os.path.relpath(req, root), "-f", "json", "--progress-spinner", "off"], p, True))
        return cmds

    def parse(self, output_path, root):
        with open(output_path, encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        out = []
        if self.name == "npm-audit":
            for name, v in sorted((data.get("vulnerabilities") or {}).items()):
                vias = [x for x in v.get("via", []) if isinstance(x, dict)]
                if not vias:
                    continue  # transitive-only entry; the root advisory is reported separately
                for via in vias:
                    out.append(_dep_finding("npm-audit", name, v.get("range", ""), via.get("title", "advisory"),
                                            normalize_severity(via.get("severity")), via.get("url", ""),
                                            "package-lock.json", [c for c in via.get("cwe", []) or []],
                                            fix="Upgrade per `npm audit fix` guidance" if v.get("fixAvailable") else "No fix available; assess exposure or replace the package."))
        else:
            deps = data if isinstance(data, list) else data.get("dependencies", [])
            for d in deps:
                for vuln in d.get("vulns", []):
                    fixv = ", ".join(vuln.get("fix_versions", []))
                    out.append(_dep_finding("pip-audit", d.get("name"), d.get("version", ""), vuln.get("id"),
                                            "high" if vuln.get("id", "").startswith(("GHSA", "CVE")) else "medium",
                                            f"https://osv.dev/vulnerability/{vuln.get('id')}", "requirements.txt", [],
                                            fix=f"Upgrade to {fixv}" if fixv else "No fixed version published.",
                                            desc=vuln.get("description", "")))
        return out


def _dep_finding(tool, name, version, title, severity, url, manifest, cwes, fix, desc=""):
    return Finding(rule_id=f"{tool}:{title}", title=f"Vulnerable dependency {name} {version}: {title}"[:200],
                   severity=severity, category="vulnerable-dependency", status="unverified", confidence="high",
                   location=Location(path=manifest, snippet=f"{name}@{version}"), description=desc[:2000],
                   evidence=f"Reported by {tool}.", remediation=fix, cwe=cwes, owasp=["A06:2021"],
                   references=[url] if url else [], sources=[tool])


REGISTRY: List[Adapter] = [
    SarifAdapter("semgrep", "semgrep", "sast", "pipx install semgrep  (or brew install semgrep)",
                 network=True, argv=_semgrep_argv),
    SarifAdapter("gitleaks", "gitleaks", "secrets", "brew install gitleaks  (or see github.com/gitleaks/gitleaks)",
                 secret_tool=True, argv=_gitleaks_argv),
    SarifAdapter("osv-scanner", "osv-scanner", "sca", "brew install osv-scanner  (or go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest)",
                 network=True, applies=lambda s: bool(s.get("package_managers")),
                 argv=lambda r, raw, c, s: [["osv-scanner", "scan", "source", "-r", "--format", "sarif", "--output", "{OUT}", "."]]),
    SarifAdapter("trivy", "trivy", "sca+iac", "brew install trivy", network=True,
                 argv=lambda r, raw, c, s: [["trivy", "fs", "--quiet", "--scanners", "vuln,misconfig", "--format", "sarif", "--output", "{OUT}", "."]]),
    SarifAdapter("bandit", "bandit", "sast", "pipx install 'bandit[sarif]'", applies=lambda s: _has(s, "languages", "python"),
                 argv=lambda r, raw, c, s: [["bandit", "-r", ".", "-f", "sarif", "-o", "{OUT}", "-q", "-x", "./.venv,./venv,./node_modules,./tests"]]),
    SarifAdapter("gosec", "gosec", "sast", "go install github.com/securego/gosec/v2/cmd/gosec@latest", applies=lambda s: _has(s, "languages", "go"),
                 argv=lambda r, raw, c, s: [["gosec", "-quiet", "-no-fail", "-fmt", "sarif", "-out", "{OUT}", "./..."]]),
    SarifAdapter("govulncheck", "govulncheck", "sca", "go install golang.org/x/vuln/cmd/govulncheck@latest", network=True,
                 applies=lambda s: _has(s, "languages", "go"), stdout=True,
                 argv=lambda r, raw, c, s: [["govulncheck", "-format", "sarif", "./..."]]),
    SarifAdapter("brakeman", "brakeman", "sast", "gem install brakeman", applies=lambda s: _has(s, "frameworks", "rails"),
                 argv=lambda r, raw, c, s: [["brakeman", "-q", "--no-pager", "--no-exit-on-warn", "-f", "sarif", "-o", "{OUT}"]]),
    SarifAdapter("checkov", "checkov", "iac", "pipx install checkov",
                 applies=lambda s: bool(s.get("iac") or s.get("containers") or s.get("ci")), stdout=True,
                 argv=lambda r, raw, c, s: [["checkov", "-d", ".", "-o", "sarif", "--quiet", "--compact", "--soft-fail"]]),
    SarifAdapter("zizmor", "zizmor", "cicd", "pipx install zizmor  (or brew install zizmor)",
                 applies=lambda s: "github-actions" in s.get("ci", []), stdout=True,
                 argv=lambda r, raw, c, s: [["zizmor", "--format", "sarif", "--offline", ".github/workflows"]]),
    HadolintAdapter("hadolint", "hadolint", "iac", "brew install hadolint", applies=lambda s: "docker" in s.get("containers", [])),
    JsonAuditAdapter("npm-audit", "npm", "sca", "ships with Node.js", network=True, applies=lambda s: "npm" in s.get("package_managers", [])),
    JsonAuditAdapter("pip-audit", "pip-audit", "sca", "pipx install pip-audit", network=True, applies=lambda s: "pip" in s.get("package_managers", [])),
]


def get(name: str) -> Optional[Adapter]:
    return next((a for a in REGISTRY if a.name == name), None)
