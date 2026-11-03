"""CVSS v3.1 base score calculator (FIRST specification, section 7)."""

import math
from typing import Dict, Tuple

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


class CVSSError(ValueError):
    pass


def _roundup(x: float) -> float:
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def parse(vector: str) -> Dict[str, str]:
    parts = vector.strip().split("/")
    if not parts or parts[0] not in ("CVSS:3.1", "CVSS:3.0"):
        raise CVSSError("vector must start with CVSS:3.1/ (or CVSS:3.0/)")
    metrics = {}
    for p in parts[1:]:
        if ":" not in p:
            raise CVSSError(f"malformed metric {p!r}")
        k, v = p.split(":", 1)
        if k in metrics:
            raise CVSSError(f"duplicate metric {k}")
        metrics[k] = v
    for k in _REQUIRED:
        if k not in metrics:
            raise CVSSError(f"missing base metric {k}")
    return metrics


def base_score(vector: str) -> float:
    m = parse(vector)
    try:
        scope = m["S"]
        if scope not in ("U", "C"):
            raise KeyError("S")
        av, ac, ui = _W["AV"][m["AV"]], _W["AC"][m["AC"]], _W["UI"][m["UI"]]
        pr = _PR[scope][m["PR"]]
        c, i, a = (_W["CIA"][m[k]] for k in ("C", "I", "A"))
    except KeyError as e:
        raise CVSSError(f"invalid value for metric {e.args[0]}") from None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope == "U":
        return _roundup(min(impact + exploitability, 10))
    return _roundup(min(1.08 * (impact + exploitability), 10))


def rating(score: float) -> str:
    if score == 0:
        return "info"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def score_and_rating(vector: str) -> Tuple[float, str]:
    s = base_score(vector)
    return s, rating(s)
