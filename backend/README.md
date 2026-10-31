# PhishGuard API

FastAPI service with `GET /api/health` and the trained-model-backed `POST /api/analyze/url` endpoint. The URL route returns HTTP 503 until a model artifact has been trained from a labeled dataset.

See the repository [README](../README.md) for the official UCI dataset source, CSV requirements, model training/evaluation command, API request example, and limitations.

Start the API from the repository root with `python -m uvicorn app.main:app --reload --app-dir backend`.
