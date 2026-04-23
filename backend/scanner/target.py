from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


_GIT_URL_RE = re.compile(r"^(https?://|git@).+")


@dataclass(frozen=True)
class PreparedTarget:
    target: str
    kind: str  # "path" | "git"
    path: Path
    cleanup_path: Optional[Path]


def is_git_url(value: str) -> bool:
    return bool(_GIT_URL_RE.match(value.strip()))


def prepare_target(*, scan_id: str, target: str, workdir: Path) -> PreparedTarget:
    target = target.strip()
    if not target:
        raise ValueError("target is required")

    if os.path.exists(target):
        p = Path(target).resolve()
        if not p.is_dir():
            raise ValueError("target path must be a directory")
        return PreparedTarget(target=target, kind="path", path=p, cleanup_path=None)

    if is_git_url(target):
        checkout_dir = (workdir / "checkouts" / scan_id).resolve()
        if checkout_dir.exists():
            shutil.rmtree(checkout_dir, ignore_errors=True)
        checkout_dir.parent.mkdir(parents=True, exist_ok=True)

        # Prefer a shallow clone for speed.
        subprocess.run(
            ["git", "clone", "--depth", "1", target, str(checkout_dir)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return PreparedTarget(target=target, kind="git", path=checkout_dir, cleanup_path=checkout_dir)

    raise ValueError("target must be an existing local directory path or a git URL")

