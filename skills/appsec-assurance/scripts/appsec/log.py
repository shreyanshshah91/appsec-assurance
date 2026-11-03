"""Append-only JSONL activity log: an auditable record of what the engine did."""

import json
import os
import time
from typing import Any


class ActivityLog:
    def __init__(self, path: str, deterministic: bool = False):
        self.path = path
        self.deterministic = deterministic
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._seq = 0

    def event(self, action: str, **details: Any) -> None:
        self._seq += 1
        rec = {"seq": self._seq, "action": action}
        if not self.deterministic:
            rec["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        rec.update(details)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, sort_keys=True, default=str) + "\n")
