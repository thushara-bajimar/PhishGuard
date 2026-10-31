import os
import sqlite3
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.ml.message_predict import MessagePredictionService
from app.ml.message_predict import ModelUnavailableError as MessageModelUnavailableError
from app.ml.predict import ModelUnavailableError as URLModelUnavailableError
from app.ml.predict import URLPredictionService
from app.schemas import (
    AnalysisResponse,
    AnalyzeMessageRequest,
    AnalyzeURLRequest,
    HistoryResponse,
    StatisticsResponse,
)
from app.services.scan_store import ScanStore

scan_store = ScanStore()
url_prediction_service = URLPredictionService()
message_prediction_service = MessagePredictionService()


@asynccontextmanager
async def lifespan(_: FastAPI):
    scan_store.initialize()
    yield

app = FastAPI(
    title="PhishGuard API",
    description="Explainable URL and message phishing assessments backed by locally trained Scikit-learn models.",
    version="0.1.0",
    lifespan=lifespan,
)

cors_origins = [origin.strip() for origin in os.environ.get(
    "PHISHGUARD_CORS_ORIGINS", "http://127.0.0.1:5173,http://localhost:5173"
).split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def unexpected_error_handler(_: Request, __: Exception) -> JSONResponse:
    """Never return implementation details or submitted content to API clients."""
    return JSONResponse(status_code=500, content={"detail": "An unexpected server error occurred."})


@app.get("/api/health", tags=["system"])
def health_check() -> dict[str, str]:
    """Report API availability; this endpoint performs no detection."""
    return {"status": "ok", "service": "phishguard-api"}


@app.post(
    "/api/analyze/url",
    response_model=AnalysisResponse,
    tags=["analysis"],
    summary="Analyze a URL with the trained phishing model",
    responses={503: {"description": "The local trained model artifact is not available."}},
)
def analyze_url(request: AnalyzeURLRequest) -> AnalysisResponse:
    """Return a model score and separately sourced URL heuristic indicators."""
    try:
        result = url_prediction_service.analyze(request.url)
        return AnalysisResponse.model_validate(scan_store.save(result, request.url))
    except URLModelUnavailableError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(error),
        ) from error
    except sqlite3.Error as error:
        raise HTTPException(status_code=503, detail="Scan storage is temporarily unavailable.") from error


@app.post(
    "/api/analyze/message",
    response_model=AnalysisResponse,
    tags=["analysis"],
    summary="Analyze email or SMS text with the trained message classifier",
    responses={503: {"description": "The local trained message-model artifact is not available."}},
)
def analyze_message(request: AnalyzeMessageRequest) -> AnalysisResponse:
    """Classify submitted message text without logging it or visiting included links."""
    try:
        result = message_prediction_service.analyze(request.content)
        return AnalysisResponse.model_validate(scan_store.save(result, request.content))
    except MessageModelUnavailableError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except sqlite3.Error as error:
        raise HTTPException(status_code=503, detail="Scan storage is temporarily unavailable.") from error


@app.get("/api/history", response_model=HistoryResponse, tags=["history"])
def list_history(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> HistoryResponse:
    try:
        items, total = scan_store.list_scans(limit=limit, offset=offset)
        return HistoryResponse(items=items, total=total, limit=limit, offset=offset)
    except sqlite3.Error as error:
        raise HTTPException(status_code=503, detail="Scan history is temporarily unavailable.") from error


@app.get("/api/history/{scan_id}", response_model=AnalysisResponse, tags=["history"])
def get_history_item(scan_id: str) -> AnalysisResponse:
    try:
        result = scan_store.get(scan_id)
    except sqlite3.Error as error:
        raise HTTPException(status_code=503, detail="Scan history is temporarily unavailable.") from error
    if result is None:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    return AnalysisResponse.model_validate(result)


@app.delete("/api/history/{scan_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["history"])
def delete_history_item(scan_id: str) -> None:
    try:
        deleted = scan_store.delete(scan_id)
    except sqlite3.Error as error:
        raise HTTPException(status_code=503, detail="Scan history is temporarily unavailable.") from error
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan record not found.")


@app.get("/api/stats", response_model=StatisticsResponse, tags=["statistics"])
def get_statistics() -> StatisticsResponse:
    try:
        return StatisticsResponse.model_validate(scan_store.statistics())
    except sqlite3.Error as error:
        raise HTTPException(status_code=503, detail="Scan statistics are temporarily unavailable.") from error
