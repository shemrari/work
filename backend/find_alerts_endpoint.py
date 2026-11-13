#!/usr/bin/env python3
"""
Script to search for alert-related endpoints in Wazuh OpenAPI spec
"""
import asyncio
import logging
import sys
import os
import json

# Add the current directory to the path so we can import app modules
sys.path.insert(0, os.path.dirname(__file__))

from app.services.wazuh_client import wazuh_client

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def find_alerts_endpoints():
    """Search for endpoints that might return alerts"""
    logger.info("Searching for alert-related endpoints...")

    # Common alert/event endpoint patterns to test
    test_endpoints = [
        "/alerts",
        "/alerts/",
        "/security/alerts",
        "/security/events",
        "/manager/alerts",
        "/manager/events",
        "/agent/alerts",
        "/syscollector/alerts",
        "/rootcheck/alerts",
    ]

    for endpoint in test_endpoints:
        logger.info(f"\nTesting endpoint: {endpoint}")
        try:
            # Try GET first
            result = await wazuh_client._request("GET", endpoint, params={"limit": 1})
            total = result.get('data', {}).get('total_affected_items', 0)
            logger.info(f"  GET {endpoint}: SUCCESS - Found {total} items")
            if total > 0:
                logger.info(f"  First item: {json.dumps(result['data']['affected_items'][0], indent=2)[:200]}...")
        except Exception as e:
            logger.debug(f"  GET {endpoint}: FAILED - {e}")

            # Try POST with empty body for some endpoints
            try:
                result = await wazuh_client._request("POST", endpoint, json={})
                total = result.get('data', {}).get('total_affected_items', 0)
                logger.info(f"  POST {endpoint}: SUCCESS - Found {total} items")
            except Exception as e2:
                logger.debug(f"  POST {endpoint}: FAILED - {e2}")

    # Clean up
    await wazuh_client.close()


if __name__ == "__main__":
    asyncio.run(find_alerts_endpoints())