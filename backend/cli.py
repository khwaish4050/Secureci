from __future__ import annotations

import argparse
import json
import sys

from backend.app import _default_steps, _run_scan, conn
from backend.database.models import create_scan, get_scan


def cmd_scan(args: argparse.Namespace) -> int:
    scan_id = create_scan(conn, target=args.target, threshold=args.threshold, steps=_default_steps())
    _run_scan(scan_id)
    row = get_scan(conn, scan_id)
    if not row:
        print("Scan not found after run", file=sys.stderr)
        return 2
    payload = {
        "id": row.id,
        "status": row.status,
        "decision": row.decision,
        "risk_score": row.risk_score,
        "threshold": row.threshold,
        "summary": row.summary,
        "findings_count": len(row.findings),
    }
    print(json.dumps(payload, indent=2))
    return 0 if (row.decision or "FAIL") == "PASS" else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="secureci")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="Run a scan synchronously (local use)")
    s.add_argument("--target", required=True, help="Local directory or git URL")
    s.add_argument("--threshold", type=int, default=50)
    s.set_defaults(fn=cmd_scan)

    ns = p.parse_args(argv)
    return int(ns.fn(ns))


if __name__ == "__main__":
    raise SystemExit(main())

