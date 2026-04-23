from __future__ import annotations

from typing import Dict, Tuple


def decide(*, risk_score: int, threshold: int) -> Tuple[str, Dict]:
    decision = "PASS" if int(risk_score) <= int(threshold) else "FAIL"
    return decision, {"threshold": int(threshold), "decision": decision}

