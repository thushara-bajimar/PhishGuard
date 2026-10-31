# PhishGuard — Explainable AI-Powered Phishing Detection

PhishGuard is a full-stack security analysis application. The backend includes independently trainable Scikit-learn URL and message models, SQLite scan history, dashboard statistics, and REST endpoints. Dataset files and trained artifacts are not included; provide the documented public datasets and train each model locally. Analysis routes return HTTP 503 until the corresponding trained artifact is present.

## Project layout

- `frontend/` — React, TypeScript, Vite, and Tailwind CSS
- `frontend/src/components/` — reusable shell, scan table, analysis results, icons, and details dialog
- `frontend/src/pages/` — dashboard, URL/message scanner, history, and education views
- `frontend/src/api.ts` — typed REST client for health, URL analysis, message analysis, and scan history
- `backend/app/ml/` — URL features and URL/message training, evaluation, and inference services
- `backend/app/services/scan_store.py` — SQLite persistence and best-effort input redaction
- `backend/app/main.py` — FastAPI analysis, history, stats, and health endpoints
- `backend/tests/` — model, API, input validation, and persistence tests
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

## Message dataset and model training

For message classification, this project documents the Kaggle dataset [Phishing Email Detection](https://www.kaggle.com/datasets/subhajournal/phishingemails), file `Phishing_Email.csv`. Kaggle’s dataset card describes two semantic fields: **`Email Text`** (email body text) and **`Email Type`** (message class), and lists an LGPL-3.0 license. The download may also contain an index/extra column; it is ignored. Training requires the two named columns and binary labels, with **`Phishing Email`** as the default positive label; inspect your CSV and choose the exact phishing label if values differ. Respect the source license and Kaggle download terms. This is email data and is not representative evidence for SMS model quality.

Download the CSV from Kaggle and place it at `data/Phishing_Email.csv`. No dataset is downloaded automatically. Train from the `backend/` directory:

```powershell
..\.venv\Scripts\python.exe -m app.ml.message_train --data ..\data\Phishing_Email.csv --text-column "Email Text" --label-column "Email Type" --phishing-label "Phishing Email"
```

The pipeline uses lowercased, Unicode-normalized word TF-IDF with unigram/bigram features, followed by class-weighted Logistic Regression. Exact normalized duplicate messages are deduplicated and grouped so duplicate text cannot cross the stratified train/test split. Training prints phishing-class precision, recall, F1, and a confusion matrix, and saves the real fitted pipeline and metadata to `backend/models/message_phishing_model.joblib` with metrics in the sibling `.metrics.json` file. Vectorizer vocabulary and classifier weights are fitted only on the training partition.

The dataset is email-only and may be stale, noisy, duplicated, or unrepresentative of current campaigns, languages, and SMS. Dataset-derived metrics do not establish deployment performance. Logistic Regression outputs are not calibrated; risk score and model confidence are scores, not reliable real-world probabilities. The separately displayed message indicators (urgency, credential/account requests, threatening language, payment terms, and link-like strings) are rule-based observations—not model explanations. Included links are never visited or resolved.

## SQLite, privacy, and remaining endpoints

On startup, the API creates `data/phishguard.sqlite3` (override its path with `PHISHGUARD_DATABASE_PATH`). Successful URL and message scans are persisted with their result and an input copy redacted for storage. Message redaction masks common email addresses, phone numbers, credential assignments, and URL query values; URL query values are all masked. Redaction is best-effort, not a guarantee of anonymization. Avoid submitting unnecessary personal or secret information and protect the local database file. Request bodies are not logged by application code.

Implemented REST endpoints:

- `POST /api/analyze/url` — URL model analysis; never performs DNS or HTTP requests to the submitted URL.
- `POST /api/analyze/message` — email/SMS text analysis; never opens links in the message.
- `GET /api/history?limit=50&offset=0` — paginated redacted scan list.
- `GET /api/history/{scan_id}` — saved result details (redacted excerpt only, not the full submitted text).
- `DELETE /api/history/{scan_id}` — delete a scan; returns 204 or 404.
- `GET /api/stats` — total, phishing, suspicious, and scan-type counts.
- `GET /api/health` — service availability only; it does not assert that either model is trained.

Message request shape is `{ "content": "..." }`, limited to 30,000 characters. URL requests are limited to 4,096 characters and HTTP(S) or bare hostnames. CORS allows the two local Vite origins by default; set `PHISHGUARD_CORS_ORIGINS` to a comma-separated allowlist when needed. API errors use clear 4xx/5xx JSON details; unexpected errors return a generic message, not a stack trace.

## Run tests

From the `backend/` directory:

```powershell
..\.venv\Scripts\python.exe -m pip install -r ..\requirements-dev.txt
..\.venv\Scripts\python.exe -m pytest -q
```

## Frontend production build

From `PhishGuard/frontend/` run:

```powershell
npm run build
```

## Next implementation milestones

1. Train both models with downloaded datasets and review held-out metrics.
2. Expand evaluation with temporal/external validation and model calibration if risk scores are intended to approximate probabilities.
3. Consider a separate, suitable SMS dataset before representing text-model quality as SMS-specific.

Model output and heuristic indicators must remain distinct in the API and UI. A prediction must never be presented as a guarantee that a URL or message is safe.
