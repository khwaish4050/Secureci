from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .common import Finding, stable_id
from .runner import run_cmd, which


def _parse_requirements(req_path: Path) -> List[Tuple[str, str]]:
    items: List[Tuple[str, str]] = []
    for raw in req_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Very loose parse: pkg==1.2.3 / pkg>=1.0 / pkg
        m = re.match(r"^([A-Za-z0-9_.-]+)\s*([=<>!~]{1,2}.*)?$", line)
        if not m:
            continue
        name = m.group(1)
        spec = (m.group(2) or "").strip()
        items.append((name, spec))
    return items


def _load_package_json(path: Path) -> Optional[Dict]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def run(root: Path) -> List[Dict]:
    findings: List[Dict] = []

    # If pip-audit is available and requirements.txt exists, prefer it.
    req = root / "requirements.txt"
    if req.exists():
        pip_audit_cmd = which("pip-audit")
        args = [pip_audit_cmd] if pip_audit_cmd else [sys.executable, "-m", "pip_audit"]
        res = run_cmd([*args, "-r", str(req), "-f", "json"], timeout_s=240)
        data = res.json()
        if isinstance(data, list):
            for pkg in data:
                if not isinstance(pkg, dict):
                    continue
                name = pkg.get("name") or "unknown"
                version = pkg.get("version") or ""
                vulns = pkg.get("vulns") or []
                for v in vulns:
                    if not isinstance(v, dict):
                        continue
                    vid = v.get("id") or "vuln"
                    desc = (v.get("description") or "").strip()
                    fixes = v.get("fix_versions") or []
                    fix = ""
                    if isinstance(fixes, list) and fixes:
                        fix = f" Fix: {', '.join(str(x) for x in fixes[:4])}"
                    findings.append(
                        Finding(
                            id=stable_id("pip-audit", name, version, vid),
                            title=f"Vulnerable dependency: {name} {version} ({vid})",
                            severity="high",
                            scanner="dependency",
                            file="requirements.txt",
                            details=(desc[:240] + fix).strip() or None,
                            recommendation="Upgrade to a fixed version and re-run the scan.",
                        ).as_dict()
                    )
        for name, spec in _parse_requirements(req):
            if not spec:
                findings.append(
                    Finding(
                        id=stable_id("dep", "pip", name),
                        title=f"Unpinned Python dependency: {name}",
                        severity="medium",
                        scanner="dependency",
                        file="requirements.txt",
                        details=f"{name} has no version pin.",
                        recommendation="Pin exact versions (e.g., `pkg==1.2.3`) and review updates regularly.",
                    ).as_dict()
                )
            elif "*" in spec or "latest" in spec.lower():
                findings.append(
                    Finding(
                        id=stable_id("dep", "pip", name, spec),
                        title=f"Non-deterministic Python dependency: {name}",
                        severity="medium",
                        scanner="dependency",
                        file="requirements.txt",
                        details=f"{name}{spec}",
                        recommendation="Avoid wildcards/latest; pin versions to keep builds reproducible.",
                    ).as_dict()
                )

    pkg = root / "package.json"
    if pkg.exists():
        data = _load_package_json(pkg) or {}
        deps = {}
        deps.update(data.get("dependencies") or {})
        deps.update(data.get("devDependencies") or {})
        for name, spec in deps.items():
            if not isinstance(spec, str):
                continue
            if spec.strip() in {"*", "latest"} or spec.strip().startswith("^") or spec.strip().startswith("~"):
                findings.append(
                    Finding(
                        id=stable_id("dep", "npm", name, spec),
                        title=f"Loosely pinned npm dependency: {name}",
                        severity="low",
                        scanner="dependency",
                        file="package.json",
                        details=f"{name}: {spec}",
                        recommendation="Prefer lockfiles and consider pinning exact versions for critical builds.",
                    ).as_dict()
                )

        # If npm is present and a lockfile exists, try npm audit for real vulns.
        if which("npm") and (root / "package-lock.json").exists():
            res = run_cmd(["npm", "audit", "--json"], timeout_s=300)
            data = res.json()
            advisories = None
            # npm v7+ uses "vulnerabilities"; older uses "advisories"
            if isinstance(data, dict):
                if isinstance(data.get("advisories"), dict):
                    advisories = list(data["advisories"].values())
                elif isinstance(data.get("vulnerabilities"), dict):
                    advisories = []
                    for dep_name, meta in data["vulnerabilities"].items():
                        if not isinstance(meta, dict):
                            continue
                        sev = (meta.get("severity") or "low").lower()
                        via = meta.get("via") or []
                        if not isinstance(via, list):
                            via = []
                        for v in via:
                            if isinstance(v, dict):
                                advisories.append(
                                    {
                                        "module_name": dep_name,
                                        "severity": sev,
                                        "title": v.get("title") or "npm audit finding",
                                        "url": v.get("url") or "",
                                    }
                                )
            if isinstance(advisories, list):
                for adv in advisories:
                    if not isinstance(adv, dict):
                        continue
                    sev = (adv.get("severity") or "low").lower()
                    if sev not in {"critical", "high", "medium", "low"}:
                        sev = "low"
                    module = adv.get("module_name") or "dependency"
                    title = adv.get("title") or "npm audit finding"
                    url = adv.get("url") or ""
                    findings.append(
                        Finding(
                            id=stable_id("npm-audit", module, title, url),
                            title=f"{title} ({module})",
                            severity=sev,
                            scanner="dependency",
                            file="package.json",
                            details=url[:240] or None,
                            recommendation="Run `npm audit fix` (carefully) and update lockfile.",
                        ).as_dict()
                    )

    return findings
