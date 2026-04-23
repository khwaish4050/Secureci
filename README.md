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

Jenkins (Step-by-Step)
----------------------
1) Start Jenkins (via this repo's Docker Compose):
   - From repo root: `docker compose up -d jenkins`
   - Get the initial admin password: `docker compose logs jenkins --tail 120`

2) Open Jenkins:
   `http://localhost:8080`

3) Install suggested plugins, and ensure these are present:
   - Pipeline
   - Git
   - Credentials Binding (usually included)

4) Create a new Pipeline job:
   - New Item → Pipeline → “Pipeline script from SCM”
   - SCM: Git
   - Repository URL: your GitHub repo
   - Branch: `main`
   - Script Path: `Jenkinsfile`

5) Run “Build Now”.
   - The pipeline runs `python -m backend.cli scan ...` and archives `secureci-result.json`.
   - If SecureCI returns FAIL, Jenkins marks the build as failed.

Terraform (Optional Infrastructure)
-----------------------------------
This repo includes a minimal Terraform example in `terraform/` that provisions a single Ubuntu EC2 instance and runs `docker compose up -d` to start SecureCI on port `8000`.

Commands:
1) `cd terraform`
2) `terraform init`
3) Copy `terraform.tfvars.example` → `terraform.tfvars` and set:
   - `key_name`
   - `allowed_ssh_cidr` (your IP/32)
   - `allowed_app_cidr` (your IP/32)
4) `terraform plan`
5) `terraform apply`

Destroy:
- `terraform destroy`

Ansible (Optional Configuration)
--------------------------------
Use Ansible to (re)configure the EC2 instance after Terraform creates it: install Docker, clone this repo, and start SecureCI.

No local Ansible install needed (runs via Docker):
1) Ensure Terraform has already run:
   - `cd terraform`
   - `terraform apply`
2) Run Ansible:
   - `powershell -ExecutionPolicy Bypass -File ansible\\run.ps1`

Playbook: `ansible/site.yml`
