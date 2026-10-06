from typing import List, Optional
from fastapi import APIRouter, Query
from app.models.schemas import AuditLogEntry, MetricsResponse
from app.core.audit_store import audit_store

router = APIRouter(prefix="", tags=["Audit & Telemetry Logs"])


@router.get("/audit-logs", response_model=List[AuditLogEntry])
async def get_audit_logs(
    limit: int = Query(50, ge=1, le=500, description="Max logs to return"),
    decision: Optional[str] = Query(None, description="Filter by decision: ALLOW, SANITIZE_AND_FORWARD, QUARANTINE_BLOCKED"),
):
    """
    Retrieves chronological tamper-evident audit logs with client IP hash,
    detected vulnerability vectors, latency, and enforcement actions.
    """
    return audit_store.get_logs(limit=limit, decision=decision)


@router.get("/metrics", response_model=MetricsResponse)
async def get_gateway_metrics():
    """
    Returns high-level governance telemetry metrics:
    total scans, blocked threats, redacted PII entities, and trust distribution.
    """
    return audit_store.get_metrics()


@router.delete("/audit-logs/clear")
async def clear_audit_logs():
    """
    Resets the in-memory telemetry log. Useful for live demo resets.
    """
    audit_store.clear()
    return {"message": "Audit logs cleared successfully", "status": "ok"}
