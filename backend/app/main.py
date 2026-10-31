from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

from app.ml.predict import ModelUnavailableError, URLPredictionService
from app.schemas import AnalyzeURLRequest, URLAnalysisResponse

app = FastAPI(
    title="PhishGuard API",
    description="Explainable URL phishing assessment backed by a locally trained Scikit-learn model.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

url_prediction_service = URLPredictionService()


@app.get("/api/health", tags=["system"])
def health_check() -> dict[str, str]:
    """Report API availability; this endpoint performs no detection."""
    return {"status": "ok", "service": "phishguard-api"}


@app.post(
    "/api/analyze/url",
    response_model=URLAnalysisResponse,
    tags=["analysis"],
    summary="Analyze a URL with the trained phishing model",
    responses={503: {"description": "The local trained model artifact is not available."}},
)
def analyze_url(request: AnalyzeURLRequest) -> URLAnalysisResponse:
    """Return a model score and separately sourced URL heuristic indicators."""
    try:
        return URLAnalysisResponse.model_validate(url_prediction_service.analyze(request.url))
    except ModelUnavailableError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(error),
        ) from error
