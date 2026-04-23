from __future__ import annotations

import fnmatch
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional


SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    severity: str
    scanner: str
    file: Optional[str] = None
    line: Optional[int] = None
    details: Optional[str] = None
    recommendation: Optional[str] = None

    def as_dict(self) -> Dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "scanner": self.scanner,
            "file": self.file,
            "line": self.line,
            "details": self.details,
            "recommendation": self.recommendation,
        }


def stable_id(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8", errors="ignore"))
        h.update(b"\x00")
    return h.hexdigest()[:16]


def iter_text_files(root: Path, *, max_size_bytes: int = 800_000) -> Iterator[Path]:
    ignore_patterns: List[str] = []
    ignore_file = root / ".secureciignore"
    try:
        if ignore_file.exists():
            for raw in ignore_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                ignore_patterns.append(line.replace("\\", "/"))
    except OSError:
        ignore_patterns = []

    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.name.lower() in {".ds_store"}:
            continue
        if any(part in {".git", "node_modules", ".venv", "venv", "dist", "build", ".workdir"} for part in p.parts):
            continue
        if ignore_patterns:
            rel = str(p.relative_to(root)).replace("\\", "/")
            if any(fnmatch.fnmatchcase(rel, pat) for pat in ignore_patterns):
                continue
        try:
            if p.stat().st_size > max_size_bytes:
                continue
        except OSError:
            continue
        yield p


def read_text_lines(path: Path) -> Optional[List[str]]:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    # Basic binary detection: if a lot of NUL bytes, skip.
    if data.count(b"\x00") > 0:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = data.decode("latin-1")
        except Exception:
            return None
    return text.splitlines()


def severity_counts(findings: Iterable[Dict]) -> Dict[str, int]:
    counts = {k: 0 for k in SEVERITIES}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        if sev not in counts:
            sev = "info"
        counts[sev] += 1
    return counts
