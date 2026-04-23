from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class CmdResult:
    ok: bool
    exit_code: int
    stdout: str
    stderr: str

    def json(self) -> Optional[object]:
        try:
            return json.loads(self.stdout)
        except Exception:
            return None


def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


def run_cmd(args: List[str], *, timeout_s: int = 180) -> CmdResult:
    try:
        p = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_s,
        )
        return CmdResult(ok=(p.returncode == 0), exit_code=p.returncode, stdout=p.stdout, stderr=p.stderr)
    except subprocess.TimeoutExpired as e:
        return CmdResult(ok=False, exit_code=124, stdout=e.stdout or "", stderr=(e.stderr or "") + "\nTimed out")
    except Exception as e:
        return CmdResult(ok=False, exit_code=125, stdout="", stderr=str(e))

