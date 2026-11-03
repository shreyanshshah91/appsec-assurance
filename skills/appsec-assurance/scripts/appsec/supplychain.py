"""Structural supply-chain checks that regex rules cannot express: missing
lockfiles, typosquat candidates, git-tracked env files, and (deep mode)
install scripts across the installed dependency tree. Nothing here executes
package code."""

import json
import os
import re
import subprocess
from typing import Dict, List, Tuple

from .findings import Finding, Location
from .walker import read_text

A06, A08, A05 = "A06:2021", "A08:2021", "A05:2021"

# Popular package names used as typosquat anchors. Deliberately small and
# conservative; extend via PRs.
POPULAR = {
    "npm": ["express", "react", "react-dom", "lodash", "axios", "moment", "request", "chalk",
            "commander", "debug", "dotenv", "webpack", "typescript", "next", "vue", "jquery",
            "body-parser", "cors", "jsonwebtoken", "mongoose", "bcrypt", "uuid", "yargs",
            "eslint", "prettier", "jest", "mocha", "socket.io", "redis", "pg", "mysql2",
            "sequelize", "nodemon", "cross-env", "colors", "async", "underscore", "bluebird",
            "electron", "puppeteer", "ws", "minimist", "glob", "rimraf", "semver", "helmet"],
    "pypi": ["requests", "numpy", "pandas", "django", "flask", "fastapi", "urllib3", "boto3",
             "setuptools", "pyyaml", "cryptography", "pillow", "sqlalchemy", "jinja2",
             "pytest", "scipy", "matplotlib", "beautifulsoup4", "selenium", "celery",
             "redis", "psycopg2", "pymongo", "uvicorn", "gunicorn", "pydantic", "httpx",
             "aiohttp", "colorama", "python-dateutil", "six", "certifi", "idna", "tensorflow",
             "torch", "scikit-learn", "openai", "anthropic", "paramiko", "pyjwt", "bcrypt"],
}

# Legitimate, popular packages that sit one edit away from another popular name.
KNOWN_GOOD = {
    "npm": {"preact", "pug", "vuex", "ms", "ws", "pg", "chai", "nock", "got", "ora", "csv", "ejs", "yup",
            "zod", "joi", "qs", "ini", "acorn", "redux", "react-is", "debug", "node-fetch", "globby"},
    "pypi": {"scapy", "boto", "six", "httpie", "requests-oauthlib", "flask-cors", "jinja", "pytz",
             "attrs", "pandas-stubs", "torchvision", "pyjwt", "pyyaml", "celery", "click"},
}

INSTALL_HOOKS = ("preinstall", "install", "postinstall")
SUSPICIOUS_SCRIPT = re.compile(r"curl|wget|https?://|node\s+-e|eval|base64|\|\s*(ba)?sh|powershell|/dev/tcp|\bnc\s")


def _lev1(a: str, b: str) -> bool:
    """True if edit distance(a, b) == 1 or a is b with one adjacent transposition."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]
    s, l = (a, b) if len(a) < len(b) else (b, a)
    i = j = 0
    skipped = False
    while i < len(s) and j < len(l):
        if s[i] != l[j]:
            if skipped:
                return False
            skipped = True
            j += 1
            continue
        i += 1
        j += 1
    return True


def typosquat_candidate(name: str, ecosystem: str) -> str:
    n = name.lower()
    popular = POPULAR.get(ecosystem, [])
    if n in popular or n in KNOWN_GOOD.get(ecosystem, set()) or n.startswith("@types/"):
        return ""
    norm = n.replace("_", "-").replace(".", "-")
    for p in popular:
        if norm == p.replace("_", "-") and n != p:
            continue  # pip normalizes separators; same package
        if _lev1(norm, p) or norm in (p + "s", p + "-js", p + "js", "python-" + p, p + "-python", "py" + p):
            return p
    return ""


def _finding(rule_id, title, severity, confidence, status, path, line, snippet, evidence,
             remediation, cwe, owasp, category="supply-chain") -> Finding:
    return Finding(rule_id=rule_id, title=title, severity=severity, confidence=confidence,
                   category=category, status=status,
                   location=Location(path=path, start_line=line, end_line=line, snippet=snippet),
                   evidence=evidence, remediation=remediation, cwe=cwe, owasp=owasp,
                   sources=["builtin:supply-chain-structural"])


def check_lockfiles(stack: Dict) -> List[Finding]:
    out = []
    for mgr in stack.get("missing_lockfiles", []):
        manifest = next((m for m in stack.get("manifests", []) if _mgr_of(m) == mgr), mgr)
        out.append(_finding(
            "SC-NO-LOCKFILE", f"No lockfile for {mgr} dependencies", "low", "high",
            "missing-control", manifest, 0, "", f"Manifest {manifest} found without a {mgr} lockfile.",
            "Commit a lockfile so builds are reproducible and dependency integrity hashes are enforced.",
            ["CWE-1104", "CWE-829"], [A06, A08]))
    return out


def _mgr_of(manifest: str) -> str:
    from .detect import MANIFESTS
    return MANIFESTS.get(os.path.basename(manifest), "")


def declared_dependencies(root: str, files: List[str]) -> List[Tuple[str, str, str, int]]:
    """[(ecosystem, name, manifest_path, line)] from package.json and requirements files."""
    deps = []
    for rel in files:
        base = os.path.basename(rel)
        try:
            if base == "package.json":
                text = read_text(root, rel)
                data = json.loads(text)
                for sect in ("dependencies", "devDependencies", "optionalDependencies"):
                    for name in (data.get(sect) or {}):
                        line = _line_of(text, f'"{name}"')
                        deps.append(("npm", name, rel, line))
            elif re.match(r"requirements[\w.\-]*\.txt$", base):
                text = read_text(root, rel)
                for i, raw in enumerate(text.splitlines(), 1):
                    line = raw.split("#", 1)[0].strip()
                    m = re.match(r"([A-Za-z0-9][A-Za-z0-9_.\-]*)", line)
                    if m and not line.startswith("-"):
                        deps.append(("pypi", m.group(1), rel, i))
        except (OSError, ValueError):
            continue
    return deps


def _line_of(text: str, needle: str) -> int:
    idx = text.find(needle)
    return text.count("\n", 0, idx) + 1 if idx >= 0 else 0


def check_typosquats(root: str, files: List[str]) -> List[Finding]:
    out = []
    for eco, name, path, line in declared_dependencies(root, files):
        target = typosquat_candidate(name, eco)
        if target:
            out.append(_finding(
                "SC-TYPOSQUAT-CANDIDATE", f"Dependency '{name}' resembles popular package '{target}'",
                "medium", "low", "suspected", path, line, name,
                f"Name is one edit away from '{target}' ({eco}). This is a heuristic, not proof of malice.",
                "Verify the package's publisher, repository, download history and creation date; replace with the intended package if it is a typo.",
                ["CWE-829"], [A08]))
    return out


def check_tracked_env_files(root: str) -> Tuple[List[Finding], str]:
    if not os.path.isdir(os.path.join(root, ".git")):
        return [], "not a git repository"
    try:
        res = subprocess.run(["git", "-C", root, "ls-files", "-z"], capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        return [], f"git unavailable: {e}"
    if res.returncode != 0:
        return [], "git ls-files failed"
    out = []
    pat = re.compile(r"(^|/)(\.env(\.[\w-]+)?|[\w-]+\.env|.*\.tfstate|id_rsa|id_ed25519|.*\.p12|.*\.pfx|\.npmrc|\.pypirc)$")
    safe = re.compile(r"\.(example|sample|template|dist)$")
    for rel in sorted(res.stdout.decode("utf-8", "replace").split("\0")):
        if rel and pat.search(rel) and not safe.search(rel):
            out.append(_finding(
                "SEC-SENSITIVE-FILE-TRACKED", f"Sensitive file tracked by git: {rel}", "high", "high",
                "confirmed", rel, 0, "", "`git ls-files` lists this file, so it is in the repository and its history.",
                "Remove it from the index (git rm --cached), add to .gitignore, rotate any secrets it held, and purge history if the repo was ever shared.",
                ["CWE-538", "CWE-312"], [A05], category="secrets"))
    return out, ""


def check_dependency_tree(root: str, limit: int = 5000) -> Tuple[List[Finding], int]:
    """Deep mode: statically read install hooks of installed npm packages."""
    nm = os.path.join(root, "node_modules")
    if not os.path.isdir(nm):
        return [], 0
    pkgs = []
    for entry in sorted(os.listdir(nm)):
        p = os.path.join(nm, entry)
        if entry.startswith("@") and os.path.isdir(p):
            pkgs.extend(os.path.join(p, s) for s in sorted(os.listdir(p)))
        elif not entry.startswith("."):
            pkgs.append(p)
    out, with_hooks, scanned = [], [], 0
    for p in pkgs[:limit]:
        pj = os.path.join(p, "package.json")
        if not os.path.isfile(pj):
            continue
        scanned += 1
        try:
            with open(pj, encoding="utf-8", errors="replace") as fh:
                pj_text = fh.read()
            data = json.loads(pj_text)
        except (OSError, ValueError):
            continue
        scripts = data.get("scripts") or {}
        rel = os.path.relpath(pj, root).replace(os.sep, "/")
        for hook in INSTALL_HOOKS:
            cmd = scripts.get(hook)
            if not isinstance(cmd, str):
                continue
            with_hooks.append(f"{data.get('name', rel)}:{hook}")
            if SUSPICIOUS_SCRIPT.search(cmd):
                out.append(_finding(
                    "SC-DEP-SUSPICIOUS-INSTALL-HOOK",
                    f"Installed dependency {data.get('name', '?')} has a suspicious {hook} script",
                    "high", "medium", "suspected", rel, _line_of(pj_text, f'"{hook}"'),
                    cmd[:200], "Install hook contains network, eval, encoding or shell-pipe tokens. Not executed.",
                    "Inspect the package source statically, check advisories (OSV/GitHub), pin a known-good version, and install with --ignore-scripts.",
                    ["CWE-506"], [A08], category="malware-indicator"))
    if with_hooks:
        out.append(_finding(
            "SC-DEP-INSTALL-HOOKS-SUMMARY", f"{len(with_hooks)} installed npm packages run install hooks",
            "info", "high", "unverified", "node_modules", 0, "",
            "Packages: " + ", ".join(with_hooks[:50]) + (" …" if len(with_hooks) > 50 else ""),
            "Review necessity; consider `npm ci --ignore-scripts` plus an explicit allowlist (e.g. @lavamoat/allow-scripts).",
            ["CWE-829"], [A08]))
    return out, scanned


_FROM = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+(?:AS|as)\s+(\S+))?\s*$")


def check_docker_base_images(root: str, files: List[str]) -> List[Finding]:
    """IAC-DOCKER-UNPINNED-BASE, done structurally so multi-stage aliases
    (`FROM builder`) and registry ports (`registry:5000/app`) are handled."""
    out = []
    for rel in files:
        base = os.path.basename(rel)
        if not (base == "Dockerfile" or base.startswith("Dockerfile.") or base.endswith((".Dockerfile", ".dockerfile")) or base == "Containerfile"):
            continue
        try:
            text = read_text(root, rel)
        except (OSError, ValueError):
            continue
        aliases = set()
        for ln, line in enumerate(text.split("\n"), 1):
            m = _FROM.match(line.rstrip("\r"))
            if not m:
                continue
            image, alias = m.group(1), m.group(2)
            if alias:
                aliases.add(alias.lower())
            if image.lower() in aliases or image == "scratch" or "$" in image or "@sha256:" in image:
                continue
            last = image.rsplit("/", 1)[-1]
            tag = last.split(":", 1)[1] if ":" in last else ""
            if tag and tag != "latest":
                continue
            out.append(_finding(
                "IAC-DOCKER-UNPINNED-BASE", "Base image unpinned or :latest", "low", "high", "unverified",
                rel, ln, line.strip(), f"Image '{image}' has {'tag latest' if tag else 'no tag'} and no digest.",
                "Pin base images to a version tag and digest (image:tag@sha256:...); update via Dependabot/Renovate.",
                ["CWE-1357"], [A08], category="container"))
    return out
