import getpass
import logging
import os

import aiohttp

from mcp_scan.identity import IdentityManager
from mcp_scan.models import ScanPathResult, ScanUserInfo, ScanPathResultsCreate
from mcp_scan.well_known_clients import get_client_from_path

logger = logging.getLogger(__name__)

identity = IdentityManager()


def get_hostname() -> str:
    try:
        return os.uname().nodename
    except Exception:
        return "unknown"


def get_username() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def get_user_info(identifier: str | None = None, opt_out: bool = False) -> ScanUserInfo:
    """
    Get the user info for the scan.

    identifier: A non-anonymous identifier used to identify the user to the control server, e.g. email or serial number
    opt_out: If True, a new identity is created and saved.
    """
    user_identifier = identity.get_identity(regenerate=opt_out)

    # If opt_out is True, clear the identity, so next scan will have a new identity
    # even if --opt-out is set to False on that scan.
    if opt_out:
        identity.clear()

    return ScanUserInfo(
        hostname=get_hostname() if not opt_out else None,
        username=get_username() if not opt_out else None,
        identifier=identifier if not opt_out else None,
        ip_address=None, # don't report local ip address
        anonymous_identifier=user_identifier,
    )


async def upload(
    results: list[ScanPathResult], control_server: str, identifier: str | None = None, opt_out: bool = False, additional_headers: dict = {}
) -> None:
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
    user_info = get_user_info(identifier=identifier, opt_out=opt_out)

    results_with_servers = []
    for result in results:
        # If there are no servers but there is a path-level error, still include the result
        if not result.servers and result.error is None:
            logger.info(f"No servers and no error for path {result.path}. Skipping upload.")
            continue
        result.client = get_client_from_path(result.path) or result.client or result.path
        results_with_servers.append(result)

    payload = ScanPathResultsCreate(
        scan_path_results=results_with_servers,
        scan_user_info=user_info
    )

    try:
        async with aiohttp.ClientSession() as session:
            headers = {"Content-Type": "application/json"}
            headers.update(additional_headers)

            async with session.post(
                control_server, data=payload.model_dump_json(), headers=headers, timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status == 200:
                    response_data = await response.json()
                    logger.info(
                        f"Successfully uploaded scan results. Server responded with {len(response_data)} results"
                    )
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
        raise e
