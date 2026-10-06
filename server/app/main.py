import os
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.routers import analyze, audit

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Sentinel-AI: Real-Time Zero-Trust AI Privacy, Threat Detection & Governance Gateway",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Robust CORS Configuration: Supports local Vite dev, localhost ports, and all Vercel deployments
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_origin_regex=settings.CORS_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# Register API Routers
app.include_router(analyze.router, prefix=settings.API_V1_STR)
app.include_router(audit.router, prefix=settings.API_V1_STR)


@app.get("/health", tags=["Health & Diagnostics"])
async def health_check():
    """
    Dedicated health check endpoint for Render, cloud monitors, and container probes.
    """
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
    }


@app.get("/", tags=["Root"])
async def root():
    return {
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "description": settings.DESCRIPTION,
        "docs": "/docs",
        "health": "/health",
        "endpoints": {
            "scan": f"{settings.API_V1_STR}/scan",
            "detokenize": f"{settings.API_V1_STR}/detokenize",
            "audit_logs": f"{settings.API_V1_STR}/audit-logs",
            "metrics": f"{settings.API_V1_STR}/metrics",
            "presets": f"{settings.API_V1_STR}/presets",
        },
    }


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("app.main:app", host="0.0.0.0", port=port, reload=True)
