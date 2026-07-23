from __future__ import annotations
from ..models.findings import Finding

WEIGHTS = {
    "dnssec": 20, "dmarc": 20, "spf": 15, "axfr": 15,
    "caa": 10, "ns": 10, "dangling": 10,
}


def grade(score: int) -> str:
    bands = [(95, "A+"), (90, "A"), (80, "B+"), (70, "B"),
             (60, "C"), (50, "D")]
    for cutoff, g in bands:
        if score >= cutoff:
            return g
    return "F"


def score_findings(passed: set[str]) -> tuple[int, str]:
    score = sum(w for k, w in WEIGHTS.items() if k in passed)
    return score, grade(score)