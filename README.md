# VidyaNexus Full-Stack Prototype

A locally runnable full-stack prototype for SIH Problem Statement 26263. It includes a FastAPI backend, SQLite persistence, role-based demo login, CSV ingestion, explainable validation, human review, consent-gated local record lookup, dashboards, institution intake monitoring, CSV export and audit events.

## Requirements
- Python 3.10+
- Internet is needed only to install Python packages the first time.

## Run on Windows
1. Extract the ZIP.
2. Open the extracted `VidyaNexus_FullStack` folder in VS Code.
3. Open Terminal in that folder and run:
   ```powershell
   py -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt
   uvicorn app.main:app --reload
   ```
4. Open http://127.0.0.1:8000
5. Interactive API docs: http://127.0.0.1:8000/docs

## Demo accounts
- AICTE admin: `admin` / `Vidya@123`
- Institution admin: `college` / `College@123`

Change demo credentials and `APP_SECRET` before any shared deployment. The default database is created as `vidyanexus.db` in this folder. Delete that file to reset the local demo database and its synthetic seed data.

## Implemented internal API
- `POST /api/auth/login`, `GET /api/auth/me`
- `GET/POST /api/institutions`
- `GET/POST /api/students`, `POST /api/students/upload`
- `POST /api/validation/run`, `GET /api/alerts`, `PATCH /api/alerts/{id}/review`
- `POST /api/verification/request`
- `GET /api/dashboard/overview`, `GET /api/reports/students.csv`
- `GET /api/audit`, `GET /api/integrations/status`, `GET /api/health`

## CSV format
Required columns: `student_name,institution_code`. Optional columns: `apaar_ref,programme,category`.

## Validation behavior
- Missing APAAR reference is flagged.
- Repeated APAAR reference is flagged as a potential duplicate, including cross-institution matches.
- Enrolment count is compared with configured approved intake plus supernumerary intake; the alert explicitly requests review of applicable rules.
- Alerts are reviewable by an authorized user; actions are recorded in the audit trail.
- Validation is deterministic and explainable. It does not declare fraud, identity validity or student ineligibility.

## Important integration and security boundary
This prototype does **not** connect to live APAAR/ABC, AICTE, NAD or DigiLocker APIs. Those adapters are shown as not configured. Real integration requires official partner onboarding, API specifications, credentials, permitted scopes, data-sharing approvals, security assessment and legally valid consent/authorization. Do not upload real student data into this demo.

This is a hackathon development prototype, not production-ready government infrastructure. Before production: use PostgreSQL, managed secrets, HTTPS, hardened CORS, secure cookie/token lifecycle, MFA, rate limiting, schema migrations, encrypted backups, formal RBAC policy, privacy impact assessment, penetration testing, retention/deletion controls and institutional approval workflows.
