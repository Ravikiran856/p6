"""
PackGuard FastAPI backend.

Run locally:
    cd packguard_backend
    pip install -r requirements.txt
    python ml/train_model.py          # first-time: generate ML artifact
    uvicorn main:app --reload --port 8000

Rate limiting (slowapi):
    Global middleware applies per-IP limits. Per-route limits are declared
    on scan/auth/report endpoints — see app/core/rate_limit.py for the
    production placement discussion (relevant for IEEE paper).
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.logging_config import setup_logging
from app.core.rate_limit import limiter
from app.deps import get_risk_model


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    setup_logging(settings.debug)
    # Eager-load ML model at startup (not per-request)
    get_risk_model()
    yield


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": str(exc.errors()),
                }
            },
        )

    @app.exception_handler(Exception)
    async def generic_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "An unexpected error occurred",
                }
            },
        )

    app.include_router(api_router, prefix=settings.api_v1_prefix)

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def web_ui():
        # Serve PackGuard interactive web application
        html_file = Path(__file__).resolve().parent.parent / "packguard_web.html"
        if html_file.exists():
            return HTMLResponse(content=html_file.read_text(encoding="utf-8"))
        return HTMLResponse(
            content="<h1>PackGuard Backend</h1><p>Visit <a href='/docs'>Swagger API Docs</a></p>"
        )

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
