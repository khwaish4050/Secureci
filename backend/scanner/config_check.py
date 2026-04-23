from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List

from .common import Finding, read_text_lines, stable_id


def _check_dockerfile(root: Path) -> List[Dict]:
    dockerfile = root / "Dockerfile"
    if not dockerfile.exists():
        return []
    lines = read_text_lines(dockerfile) or []
    has_user = any(re.match(r"(?i)^\s*USER\s+", ln) for ln in lines)
    findings: List[Dict] = []
    if not has_user:
        findings.append(
            Finding(
                id=stable_id("cfg", "dockerfile", "no_user"),
                title="Dockerfile does not specify a non-root USER",
                severity="medium",
                scanner="config",
                file="Dockerfile",
                recommendation="Add a non-root user and set `USER appuser` to reduce container impact.",
            ).as_dict()
        )
    return findings


def _check_k8s_yaml(root: Path) -> List[Dict]:
    findings: List[Dict] = []
    for path in root.rglob("*.yml"):
        findings.extend(_check_one_yaml(root, path))
    for path in root.rglob("*.yaml"):
        findings.extend(_check_one_yaml(root, path))
    return findings


def _check_one_yaml(root: Path, path: Path) -> List[Dict]:
    lines = read_text_lines(path)
    if not lines:
        return []
    rel = str(path.relative_to(root)).replace("\\", "/")
    findings: List[Dict] = []
    for idx, line in enumerate(lines, 1):
        if re.search(r"(?i)\bprivileged\s*:\s*true\b", line):
            findings.append(
                Finding(
                    id=stable_id("cfg", rel, str(idx), "privileged"),
                    title="Kubernetes container is privileged",
                    severity="high",
                    scanner="config",
                    file=rel,
                    line=idx,
                    details=line.strip()[:240],
                    recommendation="Avoid privileged containers; use least privilege and Pod Security settings.",
                ).as_dict()
            )
        if re.search(r"(?i)\bhostNetwork\s*:\s*true\b", line):
            findings.append(
                Finding(
                    id=stable_id("cfg", rel, str(idx), "hostNetwork"),
                    title="Kubernetes pod uses hostNetwork",
                    severity="medium",
                    scanner="config",
                    file=rel,
                    line=idx,
                    details=line.strip()[:240],
                    recommendation="Avoid host networking unless strictly necessary.",
                ).as_dict()
            )
        if re.search(r"(?i)\brunAsNonRoot\s*:\s*false\b", line):
            findings.append(
                Finding(
                    id=stable_id("cfg", rel, str(idx), "runAsNonRoot_false"),
                    title="Kubernetes securityContext allows root",
                    severity="medium",
                    scanner="config",
                    file=rel,
                    line=idx,
                    details=line.strip()[:240],
                    recommendation="Set `runAsNonRoot: true` and configure a non-root user.",
                ).as_dict()
            )
    return findings


def run(root: Path) -> List[Dict]:
    findings: List[Dict] = []
    findings.extend(_check_dockerfile(root))
    findings.extend(_check_k8s_yaml(root))
    return findings

