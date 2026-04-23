from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List

from .common import Finding, iter_text_files, read_text_lines, stable_id


_AWS_ACCESS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_GENERIC_SECRET = re.compile(r"(?i)\b(api[_-]?key|secret|password|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_./+=-]{8,})")


def run(root: Path) -> List[Dict]:
    findings: List[Dict] = []
    for path in iter_text_files(root):
        lines = read_text_lines(path)
        if not lines:
            continue
        for idx, line in enumerate(lines, 1):
            if _AWS_ACCESS_KEY.search(line):
                findings.append(
                    Finding(
                        id=stable_id("sec", str(path), str(idx), "aws_access_key"),
                        title="Possible AWS Access Key exposed",
                        severity="critical",
                        scanner="secrets",
                        file=str(path.relative_to(root)).replace("\\", "/"),
                        line=idx,
                        details=line.strip()[:240],
                        recommendation="Remove secret from code, rotate credentials, and use a secrets manager.",
                    ).as_dict()
                )
            m = _GENERIC_SECRET.search(line)
            if m:
                findings.append(
                    Finding(
                        id=stable_id("sec", str(path), str(idx), m.group(1)),
                        title=f"Possible hardcoded secret: {m.group(1)}",
                        severity="high",
                        scanner="secrets",
                        file=str(path.relative_to(root)).replace("\\", "/"),
                        line=idx,
                        details=line.strip()[:240],
                        recommendation="Use environment variables or a secrets manager; avoid committing secrets.",
                    ).as_dict()
                )
    return findings

