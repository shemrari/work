from typing import Any, Dict

import httpx

from app.services.anomaly_detector import analyze_alerts
from app.services.wazuh_indexer_client import wazuh_indexer_client


class AnomalyServiceError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


async def analyze_latest_wazuh_alerts(limit: int) -> Dict[str, Any]:
    try:
        response = await wazuh_indexer_client.get_alerts(
            limit=limit,
            offset=0,
            sort="-@timestamp",
        )
    except httpx.TimeoutException as error:
        raise AnomalyServiceError(504, "Wazuh Indexer request timed out") from error
    except httpx.HTTPStatusError as error:
        raise AnomalyServiceError(
            502,
            f"Wazuh Indexer returned HTTP {error.response.status_code}",
        ) from error
    except httpx.RequestError as error:
        raise AnomalyServiceError(502, "Wazuh Indexer is unavailable") from error
    except Exception as error:
        raise AnomalyServiceError(502, "Failed to load Wazuh alerts") from error

    if response.get("error", 0) != 0:
        raise AnomalyServiceError(502, "Wazuh Indexer returned an API error")

    data = response.get("data")
    alerts = data.get("affected_items") if isinstance(data, dict) else None
    if not isinstance(alerts, list):
        raise AnomalyServiceError(502, "Wazuh Indexer returned an invalid alert response")

    return analyze_alerts(alerts)
