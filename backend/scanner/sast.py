from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any, Dict, List

from .common import Finding, iter_text_files, read_text_lines, stable_id
from .runner import run_cmd, which


_FALLBACK_PATTERNS = [
    ("Use of eval()", "high", re.compile(r"\beval\s*\("), "Avoid `eval()`; parse/validate inputs and use safe APIs."),
    ("Use of exec()", "high", re.compile(r"\bexec\s*\("), "Avoid `exec()`; it enables arbitrary code execution."),
    ("Pickle deserialization", "high", re.compile(r"\bpickle\.loads\s*\("), "Avoid untrusted pickle; use JSON or safe formats."),
    ("Shell=True in subprocess", "high", re.compile(r"subprocess\.(Popen|run|call)\s*\(.*shell\s*=\s*True"), "Avoid `shell=True`; pass args as a list."),
    ("Debug mode enabled", "medium", re.compile(r"debug\s*=\s*True"), "Disable debug mode in production."),
]


def _severity_from_bandit(value: str) -> str:
    v = (value or "").upper()
    if v == "HIGH":
        return "high"
    if v == "MEDIUM":
        return "medium"
    if v == "LOW":
        return "low"
    return "info"


def _run_bandit(root: Path) -> List[Dict[str, Any]]:
    bandit_cmd = which("bandit")
    args = [bandit_cmd] if bandit_cmd else [sys.executable, "-m", "bandit"]
    # Bandit outputs JSON; return code 1 can mean issues found. We still parse output.
    res = run_cmd([*args, "-r", str(root), "-f", "json", "-q"], timeout_s=240)
    data = res.json()
    if not isinstance(data, dict):
        return []
    results = data.get("results") or []
    findings: List[Dict[str, Any]] = []
    for item in results:
        if not isinstance(item, dict):
            continue
        filename = item.get("filename") or ""
        rel = filename
        try:
            rel = str(Path(filename).resolve().relative_to(root.resolve())).replace("\\", "/")
        except Exception:
            rel = filename.replace("\\", "/")
        line = item.get("line_number")
        test_name = item.get("test_name") or "bandit"
        issue_text = item.get("issue_text") or "Bandit finding"
        sev = _severity_from_bandit(item.get("issue_severity") or "")
        findings.append(
            Finding(
                id=stable_id("bandit", rel, str(line or 0), test_name),
                title=f"{issue_text} ({test_name})",
                severity=sev,
                scanner="sast",
                file=rel if rel else None,
                line=int(line) if isinstance(line, int) else None,
                details=(item.get("code") or "").strip()[:240] or None,
                recommendation="Review this finding and apply the suggested secure coding practice.",
            ).as_dict()
        )
    return findings


def _run_fallback(root: Path) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for path in iter_text_files(root):
        lines = read_text_lines(path)
        if not lines:
            continue
        for idx, line in enumerate(lines, 1):
            for title, severity, rx, rec in _FALLBACK_PATTERNS:
                if rx.search(line):
                    findings.append(
                        Finding(
                            id=stable_id("sast_fallback", str(path), str(idx), title),
                            title=title,
                            severity=severity,
                            scanner="sast",
                            file=str(path.relative_to(root)).replace("\\", "/"),
                            line=idx,
                            details=line.strip()[:240],
                            recommendation=rec,
                        ).as_dict()
                    )
    return findings


def run(root: Path) -> List[Dict]:
    findings = _run_bandit(root)
    if findings:
        return findings
    return _run_fallback(root)
