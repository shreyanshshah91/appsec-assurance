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


NON_PRODUCTION = {"local", "dev", "development", "test", "testing", "qa", "staging", "stage",
                  "ci", "sandbox", "preview", "uat"}


def _is_local(host: str) -> bool:
    if host in LOCAL_HOSTS or host.endswith(".localhost") or host.endswith(".test"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _norm_host(h: str) -> str:
    return (h or "").strip().strip("[]").rstrip(".").lower()


def _host_matches(host: str, pattern: str) -> bool:
    pattern = _norm_host(pattern)
    try:
        return ipaddress.ip_address(host) in ipaddress.ip_network(pattern, strict=False)
    except ValueError:
        return fnmatch.fnmatchcase(host, pattern)


def _parse(target: str):
    """Return (scheme, host, port, path) or raise ValueError. Userinfo is rejected:
    credentials never belong in a target, and `user@host` tricks confuse matching."""
    parsed = urllib.parse.urlparse(target if "://" in target else f"http://{target}")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise ValueError("targets must not contain credentials (user:pass@)")
    scheme = (parsed.scheme or "http").lower()
    host = _norm_host(parsed.hostname or "")
    if not host:
        raise ValueError("target has no host")
    port = parsed.port or (443 if scheme == "https" else 80)
    return scheme, host, port, parsed.path or "/"


def environment_class(env: str) -> str:
    """'production' unless the environment is explicitly a known non-production one."""
    e = (env or "").strip().lower()
    return "non-production" if e in NON_PRODUCTION else "production"


def _excluded(scheme: str, host: str, port: int, path: str, ex: str) -> bool:
    if "://" in ex or "/" in ex.split("://")[-1] and not _looks_cidr(ex):
        try:
            es, eh, ep, epath = _parse(ex)
        except ValueError:
            return True  # unparseable exclusion: fail closed
        explicit_port = urllib.parse.urlparse(ex if "://" in ex else f"http://{ex}").port
        prefix = epath.rstrip("*").rstrip("/") or "/"
        return (_host_matches(host, eh) and (explicit_port is None or explicit_port == port)
                and (prefix == "/" or path == prefix or path.startswith(prefix.rstrip("/") + "/")))
    return _host_matches(host, ex)


def _looks_cidr(s: str) -> bool:
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


def check(scope: Dict, target: str, activity: str, today: datetime.date = None) -> Tuple[bool, str]:
    today = today or datetime.date.today()
    if activity in FORBIDDEN_ALWAYS:
        return False, f"activity '{activity}' is never permitted by this skill"
    if activity not in ACTIVITIES:
        return False, f"unknown activity '{activity}' (known: {', '.join(ACTIVITIES)})"
    if scope.get("valid_until"):
        try:
            if today > datetime.date.fromisoformat(str(scope["valid_until"])):
                return False, f"scope expired on {scope['valid_until']}"
        except ValueError:
            return False, "valid_until is not an ISO date (YYYY-MM-DD)"
    if activity not in scope.get("allowed_activities", ["static"]):
        return False, f"activity '{activity}' not in allowed_activities"
    try:
        scheme, host, port, path = _parse(target)
    except ValueError as e:
        return False, f"invalid target: {e}"
    for ex in scope.get("excluded", []) or []:
        if _excluded(scheme, host, port, path, str(ex)):
            return False, f"target matches exclusion {ex!r}"
    for t in scope.get("targets", []) or []:
        pat = t.get("host") or ""
        if not pat and t.get("url"):
            try:
                pat = _parse(t["url"])[1]
            except ValueError:
                continue
        if not pat or not _host_matches(host, pat):
            continue
        if t.get("ports") and port not in t["ports"]:
            continue
        env = str(t.get("environment", "unknown"))
        if activity not in t.get("activities", scope.get("allowed_activities", [])):
            return False, f"activity '{activity}' not allowed for target {pat}"
        if environment_class(env) == "production":
            if not t.get("production_confirmed"):
                return False, (f"environment '{env}' is treated as production (only "
                               f"{', '.join(sorted(NON_PRODUCTION))} are not); it requires production_confirmed: true")
            if activity not in PASSIVE:
                return False, "only passive activities are permitted against production"
        return True, f"allowed: {activity} on {host}:{port} ({env}); authorized by {scope['authorized_by']}"
    return False, f"host {host} is not listed in scope targets"


def normalize_target(target: str) -> str:
    """Canonical URL used for both the scope check and the request itself."""
    scheme, host, port, path = _parse(target)
    default = 443 if scheme == "https" else 80
    netloc = f"[{host}]" if ":" in host else host
    if port != default:
        netloc += f":{port}"
    q = urllib.parse.urlparse(target if "://" in target else f"http://{target}").query
    return f"{scheme}://{netloc}{path}" + (f"?{q}" if q else "")
