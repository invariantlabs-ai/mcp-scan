import asyncio
import getpass
import logging
import os
import ssl

import aiohttp
import certifi
import rich

from mcp_scan.identity import IdentityManager
from mcp_scan.models import (
    ScanError,
    ScanPathResult,
    ScanPathResultsCreate,
    ScanUserInfo,
)
from mcp_scan.well_known_clients import get_client_from_path

logger = logging.getLogger(__name__)
identity_manager = IdentityManager()


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


def setup_aiohttp_debug_logging(verbose: bool) -> list[aiohttp.TraceConfig]:
    """Setup detailed aiohttp logging and tracing for debugging purposes."""
    # Enable aiohttp internal logging
    aiohttp_logger = logging.getLogger("aiohttp")
    aiohttp_logger.setLevel(logging.DEBUG)
    aiohttp_client_logger = logging.getLogger("aiohttp.client")
    aiohttp_client_logger.setLevel(logging.DEBUG)

    # Create trace config for detailed aiohttp logging
    trace_config = aiohttp.TraceConfig()

    if verbose:
        return []

    async def on_request_start(session, trace_config_ctx, params):
        logger.debug("aiohttp: Starting request %s %s", params.method, params.url)

    async def on_request_end(session, trace_config_ctx, params):
        logger.debug("aiohttp: Request completed %s %s -> %s", params.method, params.url, params.response.status)

    async def on_connection_create_start(session, trace_config_ctx, params):
        logger.debug("aiohttp: Creating connection")

    async def on_connection_create_end(session, trace_config_ctx, params):
        logger.debug("aiohttp: Connection created")

    async def on_dns_resolvehost_start(session, trace_config_ctx, params):
        logger.debug("aiohttp: Starting DNS resolution for %s", params.host)

    async def on_dns_resolvehost_end(session, trace_config_ctx, params):
        logger.debug("aiohttp: DNS resolution completed for %s", params.host)

    async def on_connection_queued_start(session, trace_config_ctx, params):
        logger.debug("aiohttp: Connection queued")

    async def on_connection_queued_end(session, trace_config_ctx, params):
        logger.debug("aiohttp: Connection dequeued")

    async def on_request_exception(session, trace_config_ctx, params):
        logger.error("aiohttp: Request exception for %s %s: %s", params.method, params.url, params.exception)
        # Check if it's an SSL-related exception
        if hasattr(params.exception, "__class__"):
            exc_name = params.exception.__class__.__name__
            if "ssl" in exc_name.lower() or "certificate" in str(params.exception).lower():
                logger.error("aiohttp: SSL/Certificate error detected: %s", params.exception)

    async def on_request_redirect(session, trace_config_ctx, params):
        logger.debug(
            "aiohttp: Request redirected from %s %s to %s",
            params.method,
            params.url,
            params.response.headers.get("Location", "unknown"),
        )

    trace_config.on_request_start.append(on_request_start)
    trace_config.on_request_end.append(on_request_end)
    trace_config.on_connection_create_start.append(on_connection_create_start)
    trace_config.on_connection_create_end.append(on_connection_create_end)
    trace_config.on_dns_resolvehost_start.append(on_dns_resolvehost_start)
    trace_config.on_dns_resolvehost_end.append(on_dns_resolvehost_end)
    trace_config.on_connection_queued_start.append(on_connection_queued_start)
    trace_config.on_connection_queued_end.append(on_connection_queued_end)
    trace_config.on_request_exception.append(on_request_exception)
    trace_config.on_request_redirect.append(on_request_redirect)

    return [trace_config]


def setup_tcp_connector() -> aiohttp.TCPConnector:
    """
    Setup a TCP connector with a default SSL context and cleanup enabled.
    """
    ssl_context = ssl.create_default_context(cafile=certifi.where())
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
    connector = aiohttp.TCPConnector(ssl=ssl_context, enable_cleanup_closed=True)
    return connector


def get_user_info(identifier: str | None = None, opt_out: bool = False) -> ScanUserInfo:
    """
    Get the user info for the scan.

    identifier: A non-anonymous identifier used to identify the user to the control server, e.g. email or serial number
    opt_out: If True, a new identity is created and saved.
    """
    user_identifier = identity_manager.get_identity(regenerate=opt_out)

    # If opt_out is True, clear the identity, so next scan will have a new identity
    # even if --opt-out is set to False on that scan.
    if opt_out:
        identity_manager.clear()

    return ScanUserInfo(
        hostname=get_hostname() if not opt_out else None,
        username=get_username() if not opt_out else None,
        identifier=identifier if not opt_out else None,
        ip_address=None,  # don't report local ip address
        anonymous_identifier=user_identifier,
    )


async def analyze_machine(
    scan_paths: list[ScanPathResult],
    analysis_url: str,
    identifier: str | None,
    additional_headers: dict | None = None,
    opt_out_of_identity: bool = False,
    verbose: bool = False,
    skip_pushing: bool = False,
    max_retries: int = 3,
) -> list[ScanPathResult]:
    """
    Analyze the scan paths with the analysis server.

    Args:
        scan_paths: List of scan path results to analyze
        analysis_url: URL of the analysis server
        identifier: Identifier for the user
        additional_headers: Additional headers to send to the analysis server
        opt_out_of_identity: Whether to opt out of sending personal identifier
        verbose: Whether to enable verbose logging
        skip_pushing: Whether to skip pushing the scan to the platform
        max_retries: Maximum number of retry attempts
    """
    logger.debug(f"Analyzing scan path with URL: {analysis_url}")
    user_info = get_user_info(identifier=identifier, opt_out=opt_out_of_identity)

    for result in scan_paths:
        result.client = get_client_from_path(result.path) or result.client or result.path

    payload = ScanPathResultsCreate(scan_path_results=scan_paths, scan_user_info=user_info)
    logger.debug("Payload: %s", payload.model_dump_json())
    trace_configs = setup_aiohttp_debug_logging(verbose=verbose)
    headers = {
        "Content-Type": "application/json",
        "X-Environment": os.getenv("MCP_SCAN_ENVIRONMENT", "production"),
    }
    if additional_headers:
        headers.update(additional_headers)
    if skip_pushing:
        headers["X-Push"] = "skip"

    for attempt in range(max_retries):
        try:
            async with aiohttp.ClientSession(trace_configs=trace_configs, connector=setup_tcp_connector()) as session:
                async with session.post(
                    analysis_url,
                    data=payload.model_dump_json(),
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as response:
                    response.raise_for_status()
                    if response.status == 200:
                        response_data = ScanPathResultsCreate.model_validate_json(await response.text())
                        logger.info("Successfully analyzed scan results.")
                        for sent_scan_path_result, response_scan_path_result in zip(
                            scan_paths, response_data.scan_path_results, strict=True
                        ):
                            sent_scan_path_result.issues = response_scan_path_result.issues
                            sent_scan_path_result.labels = response_scan_path_result.labels
                        return scan_paths  # Success - exit the function

        except aiohttp.ClientResponseError as e:
            error_text = f"Could not reach analysis server: {e.status} - {e.message}"
            if 400 <= e.status < 500:
                logger.warning(error_text)
                for scan_path in scan_paths:
                    if scan_path.servers is not None and scan_path.error is None:
                        scan_path.error = ScanError(message=error_text, exception=e, is_failure=True)
                return scan_paths

        except RuntimeError as e:
            logger.warning(f"Network error while uploading (attempt {attempt + 1}/{max_retries}): {e}")
            raise RuntimeError(error_text) from e

        except Exception as e:
            logger.error(f"Unexpected error while uploading scan results (attempt {attempt + 1}/{max_retries}): {e}")
            # For unexpected errors, don't retry
            rich.print(f"❌ Unexpected error while uploading scan results: {e}")
            raise e

        # If not the last attempt, wait before retrying (exponential backoff)
        if attempt < max_retries - 1:
            backoff_time = 2**attempt  # 1s, 2s, 4s
            logger.info(f"Retrying in {backoff_time} seconds...")
            await asyncio.sleep(backoff_time)

    # failed even after all retries
    for scan_path in scan_paths:
        if scan_path.servers is not None and scan_path.error is None:
            scan_path.error = ScanError(
                message=f"Tried calling verification api {max_retries} times. Could not reach analysis server. Last error: {error_text}",
                exception=None,
                is_failure=True,
            )
    return scan_paths
