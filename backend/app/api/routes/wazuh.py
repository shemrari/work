from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional
import logging
import httpx

import app.services.wazuh_client
import app.services.wazuh_indexer_client
wazuh_client = app.services.wazuh_client.wazuh_client
wazuh_indexer_client = app.services.wazuh_indexer_client.wazuh_indexer_client

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/wazuh", tags=["wazuh"])


def _upstream_error(error: Exception, service: str) -> HTTPException:
    logger.exception("Request to %s failed", service)
    if isinstance(error, httpx.TimeoutException):
        return HTTPException(status_code=504, detail=f"{service} request timed out")
    if isinstance(error, httpx.HTTPStatusError):
        return HTTPException(
            status_code=502,
            detail=f"{service} returned HTTP {error.response.status_code}",
        )
    if isinstance(error, httpx.RequestError):
        return HTTPException(status_code=502, detail=f"{service} is unavailable")
    return HTTPException(status_code=502, detail=f"Could not retrieve data from {service}")


@router.get("/status")
async def wazuh_status():
    """
    Check the status of Wazuh Manager API and Wazuh Indexer.
    Returns whether both services are reachable.
    """
    try:
        # Check Wazuh Manager API
        manager_healthy = await wazuh_client.health_check()

        # Check Wazuh Indexer
        indexer_healthy = await wazuh_indexer_client.health_check()

        return {
            "wazuh_manager_api": "healthy" if manager_healthy else "unhealthy",
            "wazuh_indexer": "healthy" if indexer_healthy else "unhealthy",
            "status": "healthy" if (manager_healthy and indexer_healthy) else "unhealthy"
        }
    except Exception as e:
        logger.error(f"Error checking Wazuh status: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/agents")
async def get_wazuh_agents(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    sort: str = "-name",
    search: Optional[str] = None,
    select: Optional[str] = None,
    agent_id: Optional[str] = None,
    status: Optional[str] = None,
):
    try:
        return await wazuh_client.get_agents(
            limit=limit,
            offset=offset,
            sort=sort,
            search=search,
            select=select,
            agent_id=agent_id,
            status=status,
        )
    except Exception as error:
        raise _upstream_error(error, "Wazuh Manager API") from error


@router.get("/alerts")
async def get_wazuh_alerts(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    sort: str = "-@timestamp",
    rule_id: Optional[str] = None,
    rule_level: Optional[str] = None,
    agent_id: Optional[str] = None,
    agent_name: Optional[str] = None,
    srcip: Optional[str] = None,
    dstip: Optional[str] = None,
    timestamp_gte: Optional[str] = None,
    timestamp_lte: Optional[str] = None,
    query: Optional[str] = None,
):
    try:
        return await wazuh_indexer_client.get_alerts(
            limit=limit,
            offset=offset,
            sort=sort,
            rule_id=rule_id,
            rule_level=rule_level,
            agent_id=agent_id,
            agent_name=agent_name,
            source_ip=srcip,
            destination_ip=dstip,
            timestamp_gte=timestamp_gte,
            timestamp_lte=timestamp_lte,
            query=query,
        )
    except Exception as error:
        raise _upstream_error(error, "Wazuh Indexer") from error