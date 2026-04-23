from __future__ import annotations

import os
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend.database.models import connect, create_scan, get_scan, init_db, list_scans, update_scan
from backend.reporting.email_alert import send_alert
from backend.reporting.pdf_report import build_pdf
from backend.risk_engine.decision import decide
from backend.risk_engine.scorer import score
from backend.scanner import config_check, dependecy, sast, secrets
from backend.scanner.target import prepare_target


load_dotenv()

APP_ROOT = Path(__file__).resolve().parent
REPO_ROOT = APP_ROOT.parent
WORKDIR = (APP_ROOT / ".workdir").resolve()
DB_PATH = os.environ.get("SECURECI_DB_PATH") or str(WORKDIR / "secureci.sqlite3")

conn = connect(DB_PATH)
init_db(conn)

app = FastAPI(title="SecureCI API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanCreateRequest(BaseModel):
    target: str = Field(..., description="Local directory path or git URL")
    threshold: int = Field(50, ge=0, le=10_000, description="Fail if risk_score > threshold")


class ScanCreateResponse(BaseModel):
    id: str
    status: str


def _default_steps() -> Dict[str, Any]:
    return {
        "sast": {"status": "pending"},
        "dependency": {"status": "pending"},
        "secrets": {"status": "pending"},
        "config": {"status": "pending"},
    }


def _scan_to_dict(row) -> Dict[str, Any]:
    return {
        "id": row.id,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
        "target": row.target,
        "status": row.status,
        "threshold": row.threshold,
        "decision": row.decision,
        "risk_score": row.risk_score,
        "summary": row.summary,
        "findings": row.findings,
        "steps": row.steps,
        "error": row.error,
    }


def _run_scan(scan_id: str) -> None:
    row = get_scan(conn, scan_id)
    if not row:
        return

    steps = dict(row.steps or {})
    update_scan(conn, scan_id=scan_id, status="running", steps=steps)

    prepared = None
    try:
        prepared = prepare_target(scan_id=scan_id, target=row.target, workdir=WORKDIR)
        root = prepared.path

        all_findings: List[Dict[str, Any]] = []

        steps["sast"] = {"status": "running"}
        update_scan(conn, scan_id=scan_id, steps=steps)
        all_findings.extend(sast.run(root))
        steps["sast"] = {"status": "done", "count": len([f for f in all_findings if f.get("scanner") == "sast"])}
        update_scan(conn, scan_id=scan_id, steps=steps)

        steps["dependency"] = {"status": "running"}
        update_scan(conn, scan_id=scan_id, steps=steps)
        dep_findings = dependecy.run(root)
        all_findings.extend(dep_findings)
        steps["dependency"] = {"status": "done", "count": len(dep_findings)}
        update_scan(conn, scan_id=scan_id, steps=steps)

        steps["secrets"] = {"status": "running"}
        update_scan(conn, scan_id=scan_id, steps=steps)
        sec_findings = secrets.run(root)
        all_findings.extend(sec_findings)
        steps["secrets"] = {"status": "done", "count": len(sec_findings)}
        update_scan(conn, scan_id=scan_id, steps=steps)

        steps["config"] = {"status": "running"}
        update_scan(conn, scan_id=scan_id, steps=steps)
        cfg_findings = config_check.run(root)
        all_findings.extend(cfg_findings)
        steps["config"] = {"status": "done", "count": len(cfg_findings)}
        update_scan(conn, scan_id=scan_id, steps=steps)

        risk_score, summary = score(all_findings)
        decision, decision_meta = decide(risk_score=risk_score, threshold=row.threshold)
        summary = {**(summary or {}), **decision_meta}

        update_scan(
            conn,
            scan_id=scan_id,
            status="done",
            decision=decision,
            risk_score=risk_score,
            summary=summary,
            findings=all_findings,
            steps=steps,
        )

        if decision == "FAIL":
            send_alert(scan=_scan_to_dict(get_scan(conn, scan_id)))  # best-effort
    except Exception as e:
        tb = traceback.format_exc()
        update_scan(conn, scan_id=scan_id, status="failed", error=f"{e}\n{tb}", steps=steps)
    finally:
        if prepared and prepared.cleanup_path:
            try:
                import shutil

                shutil.rmtree(prepared.cleanup_path, ignore_errors=True)
            except Exception:
                pass


@app.get("/api/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/api/scans", response_model=ScanCreateResponse)
def create_scan_api(body: ScanCreateRequest, bg: BackgroundTasks) -> ScanCreateResponse:
    steps = _default_steps()
    scan_id = create_scan(conn, target=body.target, threshold=body.threshold, steps=steps)
    bg.add_task(_run_scan, scan_id)
    return ScanCreateResponse(id=scan_id, status="queued")


@app.get("/api/scans")
def list_scans_api(limit: int = 50) -> List[Dict[str, Any]]:
    return [_scan_to_dict(r) for r in list_scans(conn, limit=limit)]


@app.get("/api/scans/{scan_id}")
def get_scan_api(scan_id: str) -> Dict[str, Any]:
    row = get_scan(conn, scan_id)
    if not row:
        raise HTTPException(status_code=404, detail="scan not found")
    return _scan_to_dict(row)


@app.get("/api/scans/{scan_id}/report.pdf")
def get_pdf_report(scan_id: str) -> Response:
    row = get_scan(conn, scan_id)
    if not row:
        raise HTTPException(status_code=404, detail="scan not found")
    if row.status != "done":
        raise HTTPException(status_code=409, detail="scan not completed")
    pdf = build_pdf(scan=_scan_to_dict(row))
    return Response(content=pdf, media_type="application/pdf")


# Serve the dashboard (single-page static UI) from frontend/public if present.
_PUBLIC_DIR = (REPO_ROOT / "frontend" / "public").resolve()
if _PUBLIC_DIR.exists():
    app.mount("/", StaticFiles(directory=str(_PUBLIC_DIR), html=True), name="static")
