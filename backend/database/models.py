from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  target TEXT NOT NULL,
  status TEXT NOT NULL,
  threshold INTEGER NOT NULL,
  decision TEXT,
  risk_score INTEGER,
  summary_json TEXT,
  findings_json TEXT,
  steps_json TEXT,
  error TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
"""


@dataclass(frozen=True)
class ScanRow:
    id: str
    created_at: int
    updated_at: int
    target: str
    status: str
    threshold: int
    decision: Optional[str]
    risk_score: Optional[int]
    summary: Dict[str, Any]
    findings: List[Dict[str, Any]]
    steps: Dict[str, Any]
    error: Optional[str]


def _utc_epoch_seconds() -> int:
    return int(time.time())


def _json_load(value: Optional[str], default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except Exception:
        return default


def _json_dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def connect(db_path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_SQL)
    conn.commit()


def create_scan(
    conn: sqlite3.Connection,
    *,
    target: str,
    threshold: int,
    steps: Dict[str, Any],
) -> str:
    scan_id = str(uuid.uuid4())
    now = _utc_epoch_seconds()
    conn.execute(
        """
        INSERT INTO scans(id, created_at, updated_at, target, status, threshold, steps_json, summary_json, findings_json)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            now,
            now,
            target,
            "queued",
            int(threshold),
            _json_dump(steps),
            _json_dump({}),
            _json_dump([]),
        ),
    )
    conn.commit()
    return scan_id


def update_scan(
    conn: sqlite3.Connection,
    *,
    scan_id: str,
    status: Optional[str] = None,
    decision: Optional[str] = None,
    risk_score: Optional[int] = None,
    summary: Optional[Dict[str, Any]] = None,
    findings: Optional[List[Dict[str, Any]]] = None,
    steps: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None,
) -> None:
    now = _utc_epoch_seconds()
    fields: List[str] = ["updated_at=?"]
    values: List[Any] = [now]

    if status is not None:
        fields.append("status=?")
        values.append(status)
    if decision is not None:
        fields.append("decision=?")
        values.append(decision)
    if risk_score is not None:
        fields.append("risk_score=?")
        values.append(int(risk_score))
    if summary is not None:
        fields.append("summary_json=?")
        values.append(_json_dump(summary))
    if findings is not None:
        fields.append("findings_json=?")
        values.append(_json_dump(findings))
    if steps is not None:
        fields.append("steps_json=?")
        values.append(_json_dump(steps))
    if error is not None:
        fields.append("error=?")
        values.append(error)

    values.append(scan_id)
    conn.execute(f"UPDATE scans SET {', '.join(fields)} WHERE id=?", values)
    conn.commit()


def get_scan(conn: sqlite3.Connection, scan_id: str) -> Optional[ScanRow]:
    row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        return None
    return ScanRow(
        id=row["id"],
        created_at=int(row["created_at"]),
        updated_at=int(row["updated_at"]),
        target=row["target"],
        status=row["status"],
        threshold=int(row["threshold"]),
        decision=row["decision"],
        risk_score=row["risk_score"] if row["risk_score"] is None else int(row["risk_score"]),
        summary=_json_load(row["summary_json"], {}),
        findings=_json_load(row["findings_json"], []),
        steps=_json_load(row["steps_json"], {}),
        error=row["error"],
    )


def list_scans(conn: sqlite3.Connection, limit: int = 50) -> List[ScanRow]:
    rows = conn.execute(
        "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?",
        (int(limit),),
    ).fetchall()
    return [
        ScanRow(
            id=row["id"],
            created_at=int(row["created_at"]),
            updated_at=int(row["updated_at"]),
            target=row["target"],
            status=row["status"],
            threshold=int(row["threshold"]),
            decision=row["decision"],
            risk_score=row["risk_score"] if row["risk_score"] is None else int(row["risk_score"]),
            summary=_json_load(row["summary_json"], {}),
            findings=_json_load(row["findings_json"], []),
            steps=_json_load(row["steps_json"], {}),
            error=row["error"],
        )
        for row in rows
    ]

