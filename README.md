# PhishGuard — Explainable AI-Powered Phishing Detection

PhishGuard is a full-stack security analysis application. This initial milestone establishes the React/Vite frontend, FastAPI service, and their REST connection. **Phishing analysis, machine-learning predictions, SQLite persistence, and scan-history features are not implemented yet.** The current page makes no detection claims or predictions.

## Project layout

- `frontend/` — React, TypeScript, Vite, and Tailwind CSS
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

Open the printed Vite URL (normally `http://127.0.0.1:5173`) and select **Test API connection**. It calls `GET /api/health`. This health endpoint only verifies service availability; it does not analyze messages or URLs.

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
