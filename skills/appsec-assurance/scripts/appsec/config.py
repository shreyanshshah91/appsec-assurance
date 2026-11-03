"""Configuration loading. Precedence: CLI flag > .appsec/config.json > mode profile."""

import copy
import json
import os
from typing import Any, Dict, Optional

MODES = ("quick", "comprehensive", "deep", "remediate", "continuous")

DEFAULT_EXCLUDES = [
    ".git/*", "node_modules/*", "*/node_modules/*", "vendor/*", "*/vendor/*",
    "dist/*", "build/*", "target/*", ".next/*", "out/*", "coverage/*",
    ".venv/*", "venv/*", "*/.venv/*", "__pycache__/*", "*/__pycache__/*",
    ".tox/*", ".mypy_cache/*", ".pytest_cache/*", ".appsec/out/*", ".appsec/*/raw/*",
    ".terraform/*", "*.min.js", "*.map", "*.lock.json.bak",
]

DEFAULTS: Dict[str, Any] = {
    "mode": "comprehensive",
    "fail_on": "high",
    "exclude": [],
    "include_default_excludes": True,
    "max_file_size_kb": 1024,
    "rule_packs": {"enabled": ["all"], "disabled": []},
    "disabled_rules": [],
    "severity_overrides": {},
    "custom_rule_dirs": [],
    "tools": {"enabled": ["auto"], "disabled": [], "timeout_seconds": 900,
              "semgrep": {"config": ["p/default"]}},
    "allow_network_tools": True,
    "standards": ["owasp-top10-2021", "owasp-api-2023", "asvs-5", "cwe"],
    "report": {"formats": ["md", "json", "sarif"]},
}

# What each mode turns on. Remediate and continuous reuse a scan profile.
PROFILES: Dict[str, Dict[str, Any]] = {
    "quick": {"min_confidence": "medium", "tools": ["gitleaks", "osv-scanner"],
              "dependency_tree_scan": False, "git_history": False},
    "comprehensive": {"min_confidence": "low", "tools": "all",
                      "dependency_tree_scan": False, "git_history": False},
    "deep": {"min_confidence": "low", "tools": "all",
             "dependency_tree_scan": True, "git_history": True},
    "remediate": {"min_confidence": "low", "tools": "all",
                  "dependency_tree_scan": False, "git_history": False},
    "continuous": {"min_confidence": "medium", "tools": "all",
                   "dependency_tree_scan": False, "git_history": False},
}


def _deep_merge(base: Dict, over: Dict) -> Dict:
    out = copy.deepcopy(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def find_config(root: str) -> Optional[str]:
    for name in (".appsec/config.json", ".appsec.json", ".appsec/config.yml",
                 ".appsec/config.yaml"):
        p = os.path.join(root, name)
        if os.path.isfile(p):
            return p
    return None


def load(root: str, path: Optional[str] = None) -> Dict[str, Any]:
    path = path or find_config(root)
    user: Dict[str, Any] = {}
    if path:
        with open(path, encoding="utf-8") as fh:
            if path.endswith((".yml", ".yaml")):
                try:
                    import yaml  # type: ignore
                except ImportError as e:
                    raise SystemExit(f"{path}: YAML config needs PyYAML; use JSON instead") from e
                user = yaml.safe_load(fh) or {}
            else:
                user = json.load(fh)
        if not isinstance(user, dict):
            raise SystemExit(f"{path}: config must be an object")
        unknown = set(user) - set(DEFAULTS) - {"$schema", "_comment"}
        if unknown:
            raise SystemExit(f"{path}: unknown config keys: {', '.join(sorted(unknown))}")
    cfg = _deep_merge(DEFAULTS, user)
    cfg["_path"] = path
    _validate(cfg, path or "config")
    return cfg


def _validate(cfg: Dict[str, Any], where: str) -> None:
    from .findings import SEVERITIES
    errs = []
    if cfg.get("mode") not in MODES:
        errs.append(f"mode must be one of {', '.join(MODES)}")
    if cfg.get("fail_on") not in SEVERITIES:
        errs.append(f"fail_on must be one of {', '.join(SEVERITIES)}")
    for rid, sev in (cfg.get("severity_overrides") or {}).items():
        if sev not in SEVERITIES:  # a typo must never silently downgrade a finding
            errs.append(f"severity_overrides.{rid}: {sev!r} is not one of {', '.join(SEVERITIES)}")
    if not isinstance(cfg.get("max_file_size_kb"), int) or cfg["max_file_size_kb"] <= 0:
        errs.append("max_file_size_kb must be a positive integer (kilobytes)")
    for k in ("exclude", "disabled_rules", "custom_rule_dirs"):
        if not isinstance(cfg.get(k), list):
            errs.append(f"{k} must be a list")
    if errs:
        raise SystemExit(f"{where}: invalid configuration:\n  " + "\n  ".join(errs))


def resolve(cfg: Dict[str, Any], mode: Optional[str]) -> Dict[str, Any]:
    mode = mode or cfg.get("mode", "comprehensive")
    if mode not in MODES:
        raise SystemExit(f"unknown mode {mode!r}; choose from {', '.join(MODES)}")
    cfg = dict(cfg)
    cfg["mode"] = mode
    cfg["profile"] = PROFILES[mode]
    excludes = list(cfg.get("exclude", []))
    if cfg.get("include_default_excludes", True):
        excludes = DEFAULT_EXCLUDES + excludes
    cfg["effective_excludes"] = excludes
    return cfg
