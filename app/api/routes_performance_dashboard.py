from __future__ import annotations

from fastapi import APIRouter, Query

from app.api.performance_telemetry import (
    PERFORMANCE_DEFAULT_YEAR,
    get_performance_dashboard,
)


router = APIRouter(prefix="/api/performance-dashboard", tags=["performance-dashboard"])


@router.get("")
async def performance_dashboard(
    year: int = Query(PERFORMANCE_DEFAULT_YEAR, ge=2000, le=2100),
):
    return get_performance_dashboard(year)
