import getpass
import logging
import os
import socket

import aiohttp
import psutil

from mcp_scan.identity import IdentityManager
from mcp_scan.models import ScanPathResult, ScanUserInfo
from mcp_scan.paths import get_client_from_path

logger = logging.getLogger(__name__)

identity = IdentityManager()


def get_ip_address() -> str:
    try:
        # Get network interfaces, excluding loopback
        for interface, addrs in psutil.net_if_addrs().items():
            if interface.startswith("lo"):  # Skip loopback
                continue
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    return addr.address
        return "unknown"
    except Exception:
        return "unknown"


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


def get_user_info(email: str | None = None, opt_out: bool = False) -> ScanUserInfo:
    """
    Get the user info for the scan.

    email: The email of the user (command line argument).
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
        email=email if not opt_out else None,
        ip_address=get_ip_address() if not opt_out else None,
        anonymous_identifier=user_identifier,
    )


async def upload(
    results: list[ScanPathResult], control_server: str, push_key: str, email: str | None = None, opt_out: bool = False
) -> None:
    """
    Upload the scan results to the control server.

    Args:
        results: List of scan path results to upload
        control_server: Base URL of the control server
        push_key: Push key for authentication
    """
    if not results:
        logger.info("No scan results to upload")
        return

    # Normalize control server URL
    base_url = control_server.rstrip("/")
    upload_url = f"{base_url}/api/scans/push"
    user_info = get_user_info(email=email, opt_out=opt_out)

    # Convert all scan results to server data
    for result in results:
        try:
            # include user and client information in the upload data
            payload = {
                **(result.model_dump()),
                "push_key": push_key,
                "client": get_client_from_path(result.path) or "result.path",
                "scan_user_info": user_info.model_dump(),
            }

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
            raise e
