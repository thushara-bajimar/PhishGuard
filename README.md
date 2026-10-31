# PhishGuard — Explainable AI-Powered Phishing Detection

PhishGuard is a full-stack security analysis application. The frontend now includes the dashboard shell, URL/message scanners, typed analysis-result presentation, scan history, and phishing education views. **The backend currently exposes only its health endpoint; analysis, machine-learning predictions, SQLite persistence, and scan-history endpoints are not implemented yet.** Until those endpoints are available, the UI shows explicit empty/error states rather than fabricated predictions or scan records.

## Project layout

- `frontend/` — React, TypeScript, Vite, and Tailwind CSS
- `frontend/src/components/` — reusable shell, scan table, analysis results, icons, and details dialog
- `frontend/src/pages/` — dashboard, URL/message scanner, history, and education views
- `frontend/src/api.ts` — typed REST client; endpoints other than health are planned contracts and will report API errors until implemented
- `backend/app/` — FastAPI application (health endpoint only at this stage)
- `requirements.txt` — Python dependencies

## Prerequisites

- Node.js 20.19+ or 22.12+ and npm
- Python 3.10+

## Install dependencies

Open a terminal in the project root (`PhishGuard/`):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, use the Python executable directly: `.\.venv\Scripts\python.exe -m pip install -r requirements.txt` and run Uvicorn via `.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --app-dir backend`.

Then install frontend packages from the frontend directory:

```powershell
cd frontend
npm install
```

Optional: copy `frontend/.env.example` to `frontend/.env.local` to override the API base URL. The default is `http://127.0.0.1:8000`.

## Run the applications

Use two terminals.

**Terminal 1 — from the project root (`PhishGuard/`):**

```powershell
.\.venv\Scripts\Activate.ps1
python -m uvicorn app.main:app --reload --app-dir backend
```

The API is available at `http://127.0.0.1:8000`; interactive API documentation is at `http://127.0.0.1:8000/docs`.

**Terminal 2 — from `PhishGuard/frontend/`:**

```powershell
npm run dev
```

Open the printed Vite URL (normally `http://127.0.0.1:5173`). The sidebar checks `GET /api/health` and displays the API connection status. This health endpoint only verifies service availability; it does not analyze messages or URLs.

## Frontend API contract expected by the UI

The frontend is wired to these REST routes, which the backend does not implement yet:

- `POST /api/scans/url` with `{ "url": "..." }`
- `POST /api/scans/message` with `{ "content": "..." }`
- `GET /api/scans` for prior scan records (a list or `{ "items": [], "total": 0 }`)
- `GET /api/scans/{id}` for full result details
- `DELETE /api/scans/{id}` for deleting a stored record

Analysis responses should include `id`, `scan_type`, `created_at`, `risk_score` (0–100), `risk_category` (`low`, `medium`, `high`, or `critical`), `prediction` (`potential_phishing` or `no_phishing_detected`), `indicators` (each with `name`, `description`, and `source` of `model` or `heuristic`), and a `disclaimer`. `model_name` and `model_confidence` are optional. History items use the scan-record fields. The UI distinguishes model indicators from heuristic signals and treats API predictions as assessments—not guarantees.

## Frontend production build

From `PhishGuard/frontend/` run:

```powershell
npm run build
```

## Next implementation milestones

1. Define validated request/response schemas and scan API routes.
2. Add a documented, reproducible training/evaluation workflow and model artifacts before enabling predictions.
3. Add independently labeled heuristic indicators and explain prediction confidence/limitations.
4. Add SQLite persistence, history endpoints, and dashboard aggregates.
5. Add tests for API validation, model behavior, and persistence.

Model output and heuristic indicators must remain distinct in the API and UI. A prediction must never be presented as a guarantee that a URL or message is safe.
