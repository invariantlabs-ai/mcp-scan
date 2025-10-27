import asyncio
import logging
import rich
import aiohttp

from mcp_scan.models import ScanPathResult, ScanUserInfo, ScanPathResultsCreate
from mcp_scan.well_known_clients import get_client_from_path
from mcp_scan.verify_api import setup_aiohttp_debug_logging, setup_tcp_connector, get_user_info

logger = logging.getLogger(__name__)


async def upload(
    results: list[ScanPathResult], 
    control_server: str, 
    identifier: str | None = None, 
    opt_out: bool = False, 
    verbose: bool = False,
    additional_headers: dict = {},
    max_retries: int = 3
) -> None:
    """
    Upload the scan results to the control server with retry logic.

    Args:
        results: List of scan path results to upload
        control_server: Base URL of the control server
        identifier: Non-anonymous identifier for the user
        opt_out: Whether to opt-out of sending personal information
        additional_headers: Additional HTTP headers to send
        max_retries: Maximum number of retry attempts (default: 3)
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

    last_exception = None
    trace_configs = setup_aiohttp_debug_logging(verbose=verbose)
    tcp_connector = setup_tcp_connector()
    additional_headers = additional_headers or {}

    for attempt in range(max_retries):
        try:
            async with aiohttp.ClientSession(trace_configs=trace_configs, connector=tcp_connector) as session:
                headers = {"Content-Type": "application/json"}
                headers.update(additional_headers)

                async with session.post(
                    control_server, 
                    data=payload.model_dump_json(), 
                    headers=headers, 
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        response_data = await response.json()
                        logger.info(
                            f"Successfully uploaded scan results. Server responded with {len(response_data)} results"
                        )
                        rich.print(f"✅ Successfully uploaded scan results to {control_server}.")
                        return  # Success - exit the function
                    else:
                        error_text = await response.text()
                        logger.warning(
                            f"Failed to upload scan results (attempt {attempt + 1}/{max_retries}). "
                            f"Status: {response.status}, Error: {error_text}"
                        )
                        last_exception = Exception(f"HTTP {response.status}: {error_text}")
                        
                        # Don't retry on client errors (4xx)
                        if 400 <= response.status < 500:
                            rich.print(f"❌ Failed to upload scan results: {response.status} - {error_text}")
                            return

        except aiohttp.ClientError as e:
            logger.warning(f"Network error while uploading scan results (attempt {attempt + 1}/{max_retries}): {e}")
            last_exception = e
            
        except Exception as e:
            logger.error(f"Unexpected error while uploading scan results (attempt {attempt + 1}/{max_retries}): {e}")
            last_exception = e
            # For unexpected errors, don't retry
            rich.print(f"❌ Unexpected error while uploading scan results: {e}")
            raise e
        
        # If not the last attempt, wait before retrying (exponential backoff)
        if attempt < max_retries - 1:
            backoff_time = 2 ** attempt  # 1s, 2s, 4s
            logger.info(f"Retrying in {backoff_time} seconds...")
            await asyncio.sleep(backoff_time)
    
    # All retries exhausted
    error_msg = f"Failed to upload scan results after {max_retries} attempts"
    if last_exception:
        error_msg += f": {last_exception}"
    logger.error(error_msg)
    rich.print(f"❌ {error_msg}")
