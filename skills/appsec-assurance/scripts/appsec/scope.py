"""Authorization and scope gate for any activity beyond local static analysis.

Exit codes for `scope-check`: 0 allowed, 3 denied. The gate is conservative:
anything not explicitly listed is out of scope.
"""

import datetime
import fnmatch
import ipaddress
import json
import urllib.parse
from typing import Dict, Tuple

ACTIVITIES = ("static", "dependency-lookup", "dast-passive", "dast-active", "poc", "auth-testing")
FORBIDDEN_ALWAYS = ("dos", "load-test", "social-engineering", "phishing", "malware-execution",
                    "persistence", "data-exfiltration", "credential-stuffing", "physical")
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal"}
PASSIVE = {"static", "dependency-lookup", "dast-passive"}


def load(path: str) -> Dict:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    for k in ("authorized_by", "targets"):
        if k not in data:
            raise ValueError(f"scope file missing required key {k!r}")
    return data


def _is_local(host: str) -> bool:
    if host in LOCAL_HOSTS or host.endswith(".localhost") or host.endswith(".test"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _host_matches(host: str, pattern: str) -> bool:
    try:
        return ipaddress.ip_address(host) in ipaddress.ip_network(pattern, strict=False)
    except ValueError:
        return fnmatch.fnmatch(host.lower(), pattern.lower())


def check(scope: Dict, target: str, activity: str, today: datetime.date = None) -> Tuple[bool, str]:
    today = today or datetime.date.today()
    if activity in FORBIDDEN_ALWAYS:
        return False, f"activity '{activity}' is never permitted by this skill"
    if activity not in ACTIVITIES:
        return False, f"unknown activity '{activity}' (known: {', '.join(ACTIVITIES)})"
    if scope.get("valid_until"):
        try:
            if today > datetime.date.fromisoformat(scope["valid_until"]):
                return False, f"scope expired on {scope['valid_until']}"
        except ValueError:
            return False, "valid_until is not an ISO date"
    if activity not in scope.get("allowed_activities", ["static"]):
        return False, f"activity '{activity}' not in allowed_activities"

    parsed = urllib.parse.urlparse(target if "://" in target else f"http://{target}")
    host = (parsed.hostname or "").strip("[]")
    if not host:
        return False, "target has no host"
    for ex in scope.get("excluded", []):
        if _host_matches(host, ex) or fnmatch.fnmatch(target, ex):
            return False, f"target matches exclusion {ex!r}"
    for t in scope.get("targets", []):
        pat = t.get("host") or urllib.parse.urlparse(t.get("url", "")).hostname or ""
        if not pat or not _host_matches(host, pat):
            continue
        if t.get("ports") and (parsed.port or (443 if parsed.scheme == "https" else 80)) not in t["ports"]:
            continue
        env = t.get("environment", "unknown")
        if activity not in t.get("activities", scope.get("allowed_activities", [])):
            return False, f"activity '{activity}' not allowed for target {pat}"
        if env == "production":
            if not t.get("production_confirmed"):
                return False, "production target requires production_confirmed: true"
            if activity not in PASSIVE:
                return False, "only passive activities are permitted against production"
        if not _is_local(host) and activity not in PASSIVE and env not in ("local", "staging", "test", "dev", "ci"):
            return False, f"non-local target with environment '{env}' - active testing needs a declared non-production environment"
        return True, f"allowed: {activity} on {host} ({env}); authorized by {scope['authorized_by']}"
    return False, f"host {host} is not listed in scope targets"
