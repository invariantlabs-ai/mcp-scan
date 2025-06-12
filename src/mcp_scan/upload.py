import getpass
import logging
import os

import aiohttp

from mcp_scan.models import ScanPathResult
from mcp_scan.paths import get_client_from_path

logger = logging.getLogger(__name__)


async def upload(results: list[ScanPathResult], control_server: str) -> None:
    """
    Upload the scan results to the control server.

    Args:
        results: List of scan path results to upload
        control_server: Base URL of the control server
    """
    if not results:
        logger.info("No scan results to upload")
        return

    # Normalize control server URL
    base_url = control_server.rstrip("/")
    upload_url = f"{base_url}/api/scans/push"

    # get host name
    try:
        hostname = os.uname().nodename
    except Exception:
        hostname = "unknown"

    # Get user information
    try:
        username = getpass.getuser() + "@" + hostname
    except Exception:
        username = "unknown@" + hostname

    # Convert all scan results to server data
    for result in results:
        try:
            # include user and client information in the upload data
            payload = {
                **(result.model_dump()),
                "username": username,
                "client": get_client_from_path(result.path) or "result.path",
            }

            # print(payload)

            async with aiohttp.ClientSession() as session:
                headers = {"Content-Type": "application/json", "User-Agent": "mcp-scan/1.0"}

                async with session.post(
                    upload_url, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        response_data = await response.json()
                        logger.info(
                            f"Successfully uploaded scan results. Server responded with {len(response_data)} results"
                        )
                        print(f"✅ Successfully uploaded scan results to {control_server}")
                    else:
                        error_text = await response.text()
                        logger.error(f"Failed to upload scan results. Status: {response.status}, Error: {error_text}")
                        print(f"❌ Failed to upload scan results: {response.status} - {error_text}")

        except aiohttp.ClientError as e:
            logger.error(f"Network error while uploading scan results: {e}")
            print(f"❌ Network error while uploading scan results: {e}")
        except Exception as e:
            logger.error(f"Unexpected error while uploading scan results: {e}")
            print(f"❌ Unexpected error while uploading scan results: {e}")
