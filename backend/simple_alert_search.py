#!/usr/bin/env python3
"""
Simple script to search for alert endpoints in OpenAPI spec
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
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def search_for_alerts():
    """Search for alert endpoints in a simple way"""
    logger.info("Getting OpenAPI spec...")

    try:
        # Get OpenAPI spec
        spec_data = await wazuh_client._request("GET", "/openapi.json")

        # Save to temp file for easier parsing
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(spec_data, f)
            temp_file = f.name

        logger.info(f"Saved OpenAPI spec to {temp_file}")

        # Load and search
        with open(temp_file, 'r') as f:
            data = json.load(f)

        paths = data.get('paths', {})
        logger.info(f"Found {len(paths)} total paths")

        # Find paths with alert
        alert_paths = [(path, methods) for path, methods in paths.items()
                      if 'alert' in path.lower()]

        if alert_paths:
            logger.info("Found alert-related paths:")
            for path, methods in alert_paths:
                logger.info(f"  {path}: {list(methods.keys())}")
        else:
            logger.info("No alert-related paths found")

        # Find paths with event (but not alert)
        event_paths = [(path, methods) for path, methods in paths.items()
                      if 'event' in path.lower() and 'alert' not in path.lower()]

        if event_paths:
            logger.info("Found event-related paths:")
            for path, methods in event_paths:
                logger.info(f"  {path}: {list(methods.keys())}")
        else:
            logger.info("No event-related paths found")

        # Show first 10 paths for reference
        logger.info("\nFirst 10 paths:")
        for i, (path, methods) in enumerate(list(paths.items())[:10]):
            logger.info(f"  {path}: {list(methods.keys())}")

    except Exception as e:
        logger.error(f"Error: {e}")
        import traceback
        logger.error(traceback.format_exc())
    finally:
        await wazuh_client.close()


if __name__ == "__main__":
    asyncio.run(search_for_alerts())