# PhishGuard API

FastAPI service with trained-model-backed URL and message analysis, SQLite history/statistics, and health endpoints. Analysis routes return HTTP 503 until their corresponding model artifacts have been trained from labeled datasets.

See the repository [README](../README.md) for dataset sources and schemas, model training/evaluation commands, API request examples, SQLite privacy behavior, and limitations.

Start the API from the repository root with `python -m uvicorn app.main:app --reload --app-dir backend`.
