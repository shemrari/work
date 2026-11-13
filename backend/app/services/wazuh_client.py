import httpx
import asyncio
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import logging

from ..core.config import settings

logger = logging.getLogger(__name__)


class WazuhClient:
    """Client for interacting with Wazuh REST API"""

    def __init__(self):
        self.base_url = settings.wazuh_api_url.rstrip('/')
        self.username = settings.wazuh_username
        self.password = settings.wazuh_password
        self.verify_ssl = settings.wazuh_verify_ssl
        self.timeout = settings.wazuh_timeout
        self.token_cache_duration = settings.wazuh_token_cache_duration

        # Token management
        self._access_token: Optional[str] = None
        self._token_expires_at: Optional[datetime] = None
        self._token_lock = asyncio.Lock()

        # HTTP client
        self._client: Optional[httpx.AsyncClient] = None

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

    async def _authenticate(self) -> str:
        """Authenticate with Wazuh API and return JWT token"""
        url = f"{self.base_url}/security/user/authenticate"

        try:
            client = await self._get_client()
            response = await client.post(
                url,
                auth=(self.username, self.password)
            )
            response.raise_for_status()

            data = response.json()
            if data.get("error", 1) != 0:
                raise Exception(f"Authentication failed: {data}")

            token = data["data"]["token"]

            # Set token expiration (Wazuh tokens typically last 900 seconds)
            # We'll refresh a bit before actual expiration
            self._access_token = token
            self._token_expires_at = datetime.utcnow() + timedelta(
                seconds=self.token_cache_duration
            )

            logger.info("Successfully authenticated with Wazuh API")
            return token

        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error during authentication: {e}")
            raise
        except Exception as e:
            logger.error(f"Error during Wazuh authentication: {e}")
            raise

    async def _get_valid_token(self) -> str:
        """Get a valid token, refreshing if necessary"""
        async with self._token_lock:
            # Check if token is still valid
            if (self._access_token and self._token_expires_at and
                datetime.utcnow() < self._token_expires_at):
                return self._access_token

            # Token is expired or doesn't exist, get new one
            return await self._authenticate()

    async def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Make authenticated request to Wazuh API"""
        token = await self._get_valid_token()
        url = f"{self.base_url}{endpoint}"

        try:
            client = await self._get_client()
            response = await client.request(
                method=method,
                url=url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                },
                params=params,
                json=json
            )
            response.raise_for_status()

            data = response.json()
            if data.get("error", 1) != 0:
                logger.warning(f"Wazuh API returned error: {data}")

            return data

        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error requesting {endpoint}: {e}")
            # If we get a 401, token might be expired, clear it and retry once
            if e.response.status_code == 401:
                logger.info("Received 401, clearing token and retrying")
                self._access_token = None
                self._token_expires_at = None
                # Retry once with fresh token
                return await self._request(method, endpoint, params, json)
            raise
        except Exception as e:
            logger.error(f"Error requesting {endpoint}: {e}")
            raise

    # Public API methods

    async def get_agents(
        self,
        limit: int = 100,
        offset: int = 0,
        sort: str = "-name",  # Changed from -date_add to -name (valid sort field)
        search: Optional[str] = None,
        select: Optional[str] = None,
        agent_id: Optional[str] = None,
        status: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get list of agents from Wazuh"""
        params = {
            "limit": limit,
            "offset": offset,
            "sort": sort
        }

        if search:
            params["search"] = search
        if select:
            params["select"] = select
        if agent_id:
            params["agent_id"] = agent_id
        if status:
            params["status"] = status

        return await self._request("GET", "/agents", params=params)

    async def get_events(
        self,
        limit: int = 100,
        offset: int = 0,
        sort: str = "-timestamp",
        search: Optional[str] = None,
        rule_id: Optional[str] = None,
        rule_level: Optional[str] = None,
        agent_id: Optional[str] = None,
        timestamp_gte: Optional[str] = None,
        timestamp_lte: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get security events/alerts from Wazuh"""
        params = {
            "limit": limit,
            "offset": offset,
            "sort": sort
        }

        if search:
            params["search"] = search
        if rule_id:
            params["rule.id"] = rule_id
        if rule_level:
            params["rule.level"] = rule_level
        if agent_id:
            params["agent.id"] = agent_id
        if timestamp_gte:
            params["timestamp.gte"] = timestamp_gte
        if timestamp_lte:
            params["timestamp.lte"] = timestamp_lte

        return await self._request("GET", "/events", params=params)

    async def get_rules(
        self,
        limit: int = 100,
        offset: int = 0,
        sort: str = "id",
        search: Optional[str] = None,
        rule_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get list of rules from Wazuh"""
        params = {
            "limit": limit,
            "offset": offset,
            "sort": sort
        }

        if search:
            params["search"] = search
        if rule_id:
            # If specific rule ID requested, use the specific endpoint
            return await self._request("GET", f"/rules/{rule_id}")

        return await self._request("GET", "/rules", params=params)

    async def get_api_info(self) -> Dict[str, Any]:
        """Get Wazuh API information"""
        return await self._request("GET", "/")

    async def health_check(self) -> bool:
        """Check if Wazuh API is accessible"""
        try:
            await self.get_api_info()
            return True
        except Exception:
            return False


# Singleton instance
wazuh_client = WazuhClient()