from __future__ import annotations

from typing import Any, Dict, List, Tuple

WEIGHTS = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


def score(findings: List[Dict[str, Any]]) -> Tuple[int, Dict[str, Any]]:
    counts = {k: 0 for k in WEIGHTS.keys()}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        if sev not in counts:
            sev = "info"
        counts[sev] += 1

    risk_score = sum(counts[sev] * WEIGHTS[sev] for sev in counts.keys())
    summary = {
        "counts": counts,
        "weights": WEIGHTS,
        "risk_score": risk_score,
    }
    return int(risk_score), summary

