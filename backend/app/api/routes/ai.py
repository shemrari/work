import logging
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Query

from app.services.anomaly_analysis import AnomalyServiceError, analyze_latest_wazuh_alerts

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/ai", tags=["ai"])


@router.get("/anomalies")
async def detect_anomalies(limit: int = Query(500, ge=1, le=500)) -> Dict[str, Any]:
    try:
        return await analyze_latest_wazuh_alerts(limit)
    except AnomalyServiceError as error:
        logger.error("Wazuh anomaly analysis request failed: %s", error.detail)
        raise HTTPException(status_code=error.status_code, detail=error.detail) from error
    except Exception as error:
        logger.exception("Anomaly analysis failed")
        raise HTTPException(status_code=500, detail="Anomaly analysis failed") from error
