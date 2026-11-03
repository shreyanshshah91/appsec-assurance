"""Coverage ledger. Every check the engine knows about ends up here with a
status, so nothing is skipped silently."""

from typing import Dict, List

STATUSES = ("ran", "skipped", "unavailable", "error", "not-applicable")


class Coverage:
    def __init__(self) -> None:
        self.entries: List[Dict] = []

    def record(self, area: str, check: str, status: str, reason: str = "",
               findings: int = 0, kind: str = "builtin") -> None:
        assert status in STATUSES, status
        self.entries.append({"area": area, "check": check, "kind": kind,
                             "status": status, "reason": reason, "findings": findings})

    def gaps(self) -> List[Dict]:
        return [e for e in self.entries if e["status"] in ("skipped", "unavailable", "error")]

    def to_list(self) -> List[Dict]:
        return sorted(self.entries, key=lambda e: (e["area"], e["kind"], e["check"]))
