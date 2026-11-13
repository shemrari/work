import httpx
import asyncio
import base64
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import logging

from ..core.config import settings

logger = logging.getLogger(__name__)


class WazuhIndexerClient:
    """Client for retrieving alerts from Wazuh Indexer (OpenSearch)"""

    def __init__(self):
        self.base_url = settings.wazuh_indexer_url.rstrip('/')
        self.username = settings.wazuh_indexer_username
        self.password = settings.wazuh_indexer_password
        self.verify_ssl = settings.wazuh_indexer_verify_ssl
        self.timeout = settings.wazuh_indexer_timeout
        self.index_pattern = settings.wazuh_indexer_index_pattern

        # HTTP Basic Auth header
        self._auth_header = self._get_auth_header()

        # HTTP client
        self._client: Optional[httpx.AsyncClient] = None

    def _get_auth_header(self) -> str:
        """Create Basic Auth header for OpenSearch"""
        credentials = f"{self.username}:{self.password}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        return f"Basic {encoded_credentials}"

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client"""
        if self._client is None:
            self._client = httpx.AsyncClient(
                verify=self.verify_ssl,
                timeout=self.timeout
            )
        return self._client

    async def close(self):
        """Close HTTP client"""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Make authenticated request to Wazuh Indexer (OpenSearch)"""
        url = f"{self.base_url}{endpoint}"

        try:
            client = await self._get_client()
            response = await client.request(
                method=method,
                url=url,
                headers={
                    "Authorization": self._auth_header,
                    "Content-Type": "application/json"
                },
                params=params,
                json=json
            )
            response.raise_for_status()

            return response.json()

        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error requesting {endpoint}: {e}")
            raise
        except Exception as e:
            logger.error(f"Error requesting {endpoint}: {e}")
            raise

    async def get_alerts(
        self,
        limit: int = 100,
        offset: int = 0,
        sort: str = "-@timestamp",
        rule_id: Optional[str] = None,
        rule_level: Optional[str] = None,
        agent_id: Optional[str] = None,
        agent_name: Optional[str] = None,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        timestamp_gte: Optional[str] = None,
        timestamp_lte: Optional[str] = None,
        query: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get alerts from Wazuh Indexer (OpenSearch)

        Args:
            limit: Maximum number of alerts to return
            offset: Number of alerts to skip for pagination
            sort: Sort order (e.g., "-@timestamp" for newest first)
            rule_id: Filter by rule ID
            rule_level: Filter by rule level
            agent_id: Filter by agent ID
            agent_name: Filter by agent name
            source_ip: Filter by source IP address
            destination_ip: Filter by destination IP address
            timestamp_gte: Filter alerts greater than or equal to this timestamp (ISO format)
            timestamp_lte: Filter alerts less than or equal to this timestamp (ISO format)
            query: OpenSearch query string for custom filtering

        Returns:
            Dictionary containing alerts and metadata
        """
        # Build OpenSearch query
        # Process sort parameter correctly for OpenSearch
        sort_field = sort.lstrip('-')
        sort_order = "desc" if sort.startswith('-') else "asc"

        query_body = {
            "size": limit,
            "from": offset,
            "sort": [{sort_field: {"order": sort_order}}]
        }

        # Build filter conditions
        must_conditions = []

        if query:
            # Custom query string
            must_conditions.append({
                "query_string": {
                    "query": query,
                    "analyze_wildcard": True
                }
            })
        else:
            # Add individual filters
            if rule_id:
                must_conditions.append({
                    "term": {"rule.id": rule_id}
                })

            if rule_level:
                # Based on the alert structure, rule.level is a number, so term query should work
                try:
                    # Try to convert to integer for term query
                    must_conditions.append({
                        "term": {"rule.level": int(rule_level)}
                    })
                except ValueError:
                    # If not convertible to int, skip this filter or handle differently
                    logger.warning(f"rule_level '{rule_level}' cannot be converted to integer, skipping filter")

            if agent_id:
                must_conditions.append({
                    "term": {"agent.id": agent_id}
                })

            if agent_name:
                must_conditions.append({
                    "match": {"agent.name": agent_name}
                })

            if source_ip:
                must_conditions.append({
                    "term": {"srcip": source_ip}
                })

            if destination_ip:
                must_conditions.append({
                    "term": {"dstip": destination_ip}
                })

            if timestamp_gte or timestamp_lte:
                range_condition = {}
                if timestamp_gte:
                    range_condition["gte"] = timestamp_gte
                if timestamp_lte:
                    range_condition["lte"] = timestamp_lte

                if range_condition:
                    must_conditions.append({
                        "range": {"@timestamp": range_condition}
                    })

        if must_conditions:
            query_body["query"] = {
                "bool": {
                    "must": must_conditions
                }
            }
        else:
            # Match all if no filters
            query_body["query"] = {
                "match_all": {}
            }

        try:
            # Search across the index pattern
            endpoint = f"/{self.index_pattern}/_search"
            response = await self._request("POST", endpoint, json=query_body)

            # Parse OpenSearch response into a format similar to the Manager API
            alerts = []
            for hit in response.get("hits", {}).get("hits", []):
                alert_data = hit.get("_source", {})
                # Add the document ID for reference
                alert_data["_id"] = hit.get("_id")
                alerts.append(alert_data)

            # Format response to be consistent with existing Wazuh client
            formatted_response = {
                "error": 0,
                "message": "No error",
                "data": {
                    "total_affected_items": response.get("hits", {}).get("total", {}).get("value", 0),
                    "affected_items": alerts,
                    "page": {
                        "limit": limit,
                        "offset": offset,
                        "totalItems": response.get("hits", {}).get("total", {}).get("value", 0)
                    }
                }
            }

            return formatted_response

        except Exception as e:
            logger.error(f"Error retrieving alerts from Wazuh Indexer: {e}")
            raise

    async def get_alert_by_id(self, alert_id: str) -> Dict[str, Any]:
        """
        Get a specific alert by its ID

        Args:
            alert_id: The alert document ID

        Returns:
            Dictionary containing the alert data
        """
        try:
            # Search for the document by ID across the index pattern
            # Using the _search endpoint with a IDs query
            query_body = {
                "size": 1,
                "query": {
                    "ids": {
                        "values": [alert_id]
                    }
                }
            }

            endpoint = f"/{self.index_pattern}/_search"
            response = await self._request("POST", endpoint, json=query_body)

            # Format response to be consistent
            hits = response.get("hits", {}).get("hits", [])
            if hits:
                hit = hits[0]
                alert_data = hit.get("_source", {})
                alert_data["_id"] = hit.get("_id")

                formatted_response = {
                    "error": 0,
                    "message": "No error",
                    "data": {
                        "total_affected_items": 1,
                        "affected_items": [alert_data]
                    }
                }
            else:
                # Alert not found
                formatted_response = {
                    "error": 0,
                    "message": "No error",
                    "data": {
                        "total_affected_items": 0,
                        "affected_items": []
                    }
                }

            return formatted_response

        except Exception as e:
            logger.error(f"Error retrieving alert by ID {alert_id}: {e}")
            raise

    async def health_check(self) -> bool:
        """Check if Wazuh Indexer is accessible"""
        try:
            # Simple cluster health check
            response = await self._request("GET", "/_cluster/health")
            return response.get("status") in ["green", "yellow"]
        except Exception:
            return False


# Singleton instance
wazuh_indexer_client = WazuhIndexerClient()