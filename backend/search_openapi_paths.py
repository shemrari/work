#!/usr/bin/env python3
"""
Search for paths in Wazuh OpenAPI spec that might relate to alerts
"""
import asyncio
import logging
import sys
import os
import re

# Add the current directory to the path so we can import app modules
sys.path.insert(0, os.path.dirname(__file__))

from app.services.wazuh_client import wazuh_client

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def search_openapi_paths():
    """Search OpenAPI spec for alert-related paths"""
    logger.info("Fetching OpenAPI spec...")

    try:
        # Get the OpenAPI spec
        spec_data = await wazuh_client._request("GET", "/openapi.json")

        # Extract all paths
        paths = spec_data.get('paths', {})

        logger.info(f"Found {len(paths)} total paths in OpenAPI spec")

        # Search for paths containing alert (case-insensitive)
        alert_paths = []
        for path in paths.keys():
            if re.search(r'alert', path, re.IGNORECASE):
                alert_paths.append(path)
                logger.info(f"Found alert-related path: {path}")

        # Also search for event-related paths
        event_paths = []
        for path in paths.keys():
            if re.search(r'event', path, re.IGNORECASE):
                event_paths.append(path)
                logger.info(f"Found event-related path: {path}")

        # Show some sample paths to understand the structure
        logger.info("\nSample paths (first 20):")
        for i, path in enumerate(list(paths.keys())[:20]):
            logger.info(f"  {path}")

        if len(paths) > 20:
            logger.info(f"  ... and {len(paths) - 20} more")

        # Let's also look at what methods are available for some key paths
        key_paths = ['/agents', '/events', '/rules', '/']
        for path in key_paths:
            if path in paths:
                methods = list(paths[path].keys())
                logger.info(f"\nPath {path} supports methods: {methods}")

    except Exception as e:
        logger.error(f"Error searching OpenAPI spec: {e}")
        import traceback
        logger.error(traceback.format_exc())
    finally:
        await wazuh_client.close()


if __name__ == "__main__":
    asyncio.run(search_openapi_paths())