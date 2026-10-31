# PhishGuard — Explainable AI-Powered Phishing Detection

PhishGuard is a full-stack security analysis application. The frontend includes the dashboard shell, URL/message scanners, typed analysis-result presentation, scan history, and phishing education views. The backend now has a real Scikit-learn URL model training/inference pipeline and `POST /api/analyze/url`. A trained artifact is deliberately not included: supply a labeled CSV and train it locally. Message analysis, SQLite persistence, and scan-history endpoints remain future work.

## Project layout

- `frontend/` — React, TypeScript, Vite, and Tailwind CSS
- `frontend/src/components/` — reusable shell, scan table, analysis results, icons, and details dialog
- `frontend/src/pages/` — dashboard, URL/message scanner, history, and education views
- `frontend/src/api.ts` — typed REST client for health, URL analysis, message analysis, and scan history
- `backend/app/ml/` — deterministic URL features, CSV-based model training/evaluation, and prediction service
- `backend/app/main.py` — FastAPI health and URL analysis endpoints
- `backend/tests/` — URL feature and request-validation tests
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

## URL dataset and model training

The recommended source is the [UCI Machine Learning Repository’s PhiUSIIL Phishing URL (Website) dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) (dataset 967; CC BY 4.0). The UCI record documents 235,795 instances: 134,850 legitimate and 100,945 phishing URLs. Its label mapping is **1 = legitimate, 0 = phishing**. Cite Prasad and Chandra (2024), DOI [10.1016/j.cose.2023.103545](https://doi.org/10.1016/j.cose.2023.103545).

Download the CSV from the UCI dataset page (or its linked archive), extract it, and place the file at `data/PhiUSIIL_Phishing_URL_Dataset.csv`. The application does not silently download data or train a model. No dataset or trained artifact is checked in.

The trainer requires a CSV with a URL column and a binary label column. Defaults are `URL` and `label`; choose the exact phishing label explicitly. It reads only the raw URL and label columns, intentionally ignoring UCI webpage-derived features so that inference only needs a URL. For a different CSV, pass its actual column names and the positive (phishing) label value.

Run the trainer from the `backend/` directory, with the virtual environment installed as above:

```powershell
..\.venv\Scripts\python.exe -m app.ml.train --data ..\data\PhiUSIIL_Phishing_URL_Dataset.csv --url-column URL --label-column label --phishing-label 0
```

Training extracts URL-only numeric features, removes duplicate normalized URLs (and fails on conflicting duplicate labels), then uses `StratifiedGroupKFold` to hold out registrable domains so the same domain is not in both train and test splits. The feature transformer and `RandomForestClassifier` are saved together to `backend/models/url_phishing_model.joblib`; evaluation metrics are written to the sibling `.metrics.json` file and printed to the terminal. Metrics include phishing-class precision, recall, F1, and a confusion matrix (rows/columns labeled legitimate, phishing). The forest is class-weighted and uses a fixed random seed by default.

Do not treat one split’s metrics as a guarantee of field performance. Dataset age, label quality, duplicate or related domains, attacker changes, regional URL patterns, and the lack of page-content features all limit generalization. The classifier’s `predict_proba` score is **not calibrated**: the API’s risk score is that model score scaled to 0–100, and model confidence is the predicted class score, not a probability that the URL is malicious. The separate indicators are heuristics, not per-feature explanations of the forest.

The model artifact is a locally generated joblib/pickle file. Only load an artifact created by this project from a trusted training run; do not point `PHISHGUARD_MODEL_PATH` at an untrusted file.

## URL analysis endpoint

`POST /api/analyze/url` accepts `{ "url": "https://example.com/path" }` (a bare hostname is also accepted). It returns the prediction, 0–100 risk score/category, heuristic indicators with `source: "heuristic"`, model metadata, and a safety disclaimer. It performs no DNS lookup or page fetch. Before a model is trained, the route returns HTTP 503 with setup guidance rather than fabricating a result.

To test after training, start the API from the project root and run this in another PowerShell terminal. The result is generated by your trained artifact and will depend on it:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/analyze/url -ContentType 'application/json' -Body '{"url":"https://example.com/"}' | ConvertTo-Json -Depth 8
```

## Remaining frontend API routes

The UI is also wired for routes that are not implemented yet:

- `POST /api/scans/message` with `{ "content": "..." }`
- `GET /api/scans` for prior scan records (a list or `{ "items": [], "total": 0 }`)
- `GET /api/scans/{id}` for full result details
- `DELETE /api/scans/{id}` for deleting a stored record

When implemented, analysis responses should include `id`, `scan_type`, `created_at`, `risk_score` (0–100), `risk_category` (`low`, `medium`, `high`, or `critical`), `prediction` (`potential_phishing` or `no_phishing_detected`), `indicators` (each with `name`, `description`, and `source` of `model` or `heuristic`), and a `disclaimer`. The UI distinguishes model predictions from heuristic signals and never treats results as guarantees.

## Run tests

From the `backend/` directory:

```powershell
..\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## Frontend production build

From `PhishGuard/frontend/` run:

```powershell
npm run build
```

## Next implementation milestones

1. Add message/SMS analysis with its own appropriately sourced dataset and trained model.
2. Add SQLite persistence, history endpoints, and dashboard aggregates.
3. Expand evaluation with temporal/external validation and model calibration if risk scores are intended to approximate probabilities.
4. Add persistence and end-to-end API tests.

Model output and heuristic indicators must remain distinct in the API and UI. A prediction must never be presented as a guarantee that a URL or message is safe.
