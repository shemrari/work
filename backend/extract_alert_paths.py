#!/usr/bin/env python3
"""
Extract alert-related paths from Wazuh OpenAPI spec
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


async def extract_alert_paths():
    """Extract alert-related paths from OpenAPI spec"""
    logger.info("Fetching OpenAPI spec to find alert endpoints...")

    try:
        # Get the OpenAPI spec
        spec_data = await wazuh_client._request("GET", "/openapi.json")

        # Extract all paths
        paths = spec_data.get('paths', {})

        logger.info(f"Found {len(paths)} total paths in OpenAPI spec")

        # Search for paths containing alert (case-insensitive)
        alert_paths = []
        for path in paths.keys():
            if 'alert' in path.lower():
                alert_paths.append(path)
                # Show what methods are available for this path
                methods = list(paths[path].keys())
                logger.info(f"  Path: {path} (methods: {', '.join(methods)})")

        # Search for paths containing event (case-insensitive)
        event_paths = []
        for path in paths.keys():
            if 'event' in path.lower() and 'alert' not in path.lower():
                event_paths.append(path)
                methods = list(paths[path].keys())
                logger.info(f"  Path: {path} (methods: {', '.join(methods)})")

        if not alert_paths and not event_paths:
            logger.warning("No alert or event related paths found in OpenAPI spec")
            # Let's look at some common paths to see what's available
            common_paths = ['/agents', '/rules', '/', '/security/user/authenticate']
            logger.info("\nChecking common paths:")
            for path in common_paths:
                if path in paths:
                    methods = list(paths[path].keys())
                    logger.info(f"  {path}: {', '.join(methods)}")
                else:
                    logger.info(f"  {path}: NOT FOUND")

    except Exception as e:
        logger.error(f"Error extracting paths from OpenAPI spec: {e}")
        import traceback
        logger.error(traceback.format_exc())
    finally:
        await wazuh_client.close()


if __name__ == "__main__":
    asyncio.run(extract_alert_paths())