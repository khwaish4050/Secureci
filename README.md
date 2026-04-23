SecureCI (General Purpose)
=========================

SecureCI is a lightweight, general-purpose DevSecOps security scanner that you can run locally or wire into CI.

What you get (matches the diagram/modules)
-----------------------------------------
- Integration (Module A): REST API for triggering scans
- Scanning Engine (Module B): basic SAST, dependency hygiene, secret detection, config checks
- Risk Evaluation (Module C): weighted risk scoring (Critical*5, High*4, Medium*3, Low*2, Info*1)
- Decision Engine (Module D): PASS/FAIL based on a threshold
- Reporting (Module E): JSON + PDF report endpoint
- Dashboard: static UI served from `frontend/public`

Run Locally (Windows / PowerShell)
---------------------------------
1) Install backend deps:
   `python -m pip install -r backend/requirements.txt`

2) Start the API (also serves the dashboard):
   `python -m uvicorn backend.app:app --reload --port 8000`

3) Open:
   `http://localhost:8000`

4) In the UI, paste either:
   - a local folder path (fastest), or
   - a git URL (requires `git` installed and on PATH)

API Quick Use
-------------
- Health: `GET /api/health`
- Start scan: `POST /api/scans` with JSON: `{ "target": "...", "threshold": 50 }`
- Poll scan: `GET /api/scans/{id}`
- PDF report: `GET /api/scans/{id}/report.pdf` (only when status is `done`)

Notes
-----
- This is intentionally general-purpose (healthcare is only an example use case).
- The scanners are heuristic and pluggable; you can later swap in real tools (Semgrep, Trivy, etc.) behind the same API.
- Add a `.secureciignore` file in any target repo to exclude paths from scanning (simple glob patterns).
