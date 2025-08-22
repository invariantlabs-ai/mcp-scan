import logging
import os

import aiohttp
import ssl
import certifi

from .identity import IdentityManager
from .models import (
    AnalysisServerResponse,
    Issue,
    ScanPathResult,
    VerifyServerRequest,
)

logger = logging.getLogger(__name__)
identity_manager = IdentityManager()


def setup_aiohttp_debug_logging():
    """Setup detailed aiohttp logging and tracing for debugging purposes."""
    # Enable aiohttp internal logging
    aiohttp_logger = logging.getLogger('aiohttp')
    aiohttp_logger.setLevel(logging.DEBUG)
    aiohttp_client_logger = logging.getLogger('aiohttp.client')
    aiohttp_client_logger.setLevel(logging.DEBUG)
    
    # Create trace config for detailed aiohttp logging
    trace_config = aiohttp.TraceConfig()
    
    async def on_request_start(session, trace_config_ctx, params):
        logger.debug("aiohttp: Starting request %s %s", params.method, params.url)
        
    async def on_request_end(session, trace_config_ctx, params):
        logger.debug("aiohttp: Request completed %s %s -> %s", 
                    params.method, params.url, params.response.status)
                    
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
        logger.error("aiohttp: Request exception for %s %s: %s", 
                    params.method, params.url, params.exception)
        # Check if it's an SSL-related exception
        if hasattr(params.exception, '__class__'):
            exc_name = params.exception.__class__.__name__
            if 'ssl' in exc_name.lower() or 'certificate' in str(params.exception).lower():
                logger.error("aiohttp: SSL/Certificate error detected: %s", params.exception)
                
    async def on_request_redirect(session, trace_config_ctx, params):
        logger.debug("aiohttp: Request redirected from %s %s to %s", 
                    params.method, params.url, params.response.headers.get('Location', 'unknown'))
    
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
    
    return trace_config


async def analyze_scan_path(
    scan_path: ScanPathResult, base_url: str, additional_headers: dict = {}, opt_out_of_identity: bool = False, verbose: bool = False
) -> ScanPathResult:
    url = base_url[:-1] if base_url.endswith("/") else base_url
    url = url + "/api/v1/public/mcp-analysis"
    headers = {
        "Content-Type": "application/json",
        "X-User": identity_manager.get_identity(opt_out_of_identity),
        "X-Environment": os.getenv("MCP_SCAN_ENVIRONMENT", "production")
    }
    headers.update(additional_headers)

    logger.debug("Analyzing scan path with URL: %s and headers: %s", url, headers)
    payload = VerifyServerRequest(
        root=[
            server.signature.model_dump() if server.signature else None
            for server in scan_path.servers
        ]
    )
    logger.debug("Payload: %s", payload.model_dump_json())

    # Server signatures do not contain any information about the user setup. Only about the server itself.
    try:
        # Setup debugging if verbose mode is enabled
        trace_configs = []
        if verbose:
            trace_config = setup_aiohttp_debug_logging()
            trace_configs.append(trace_config)

        # explicitly creating the ssl context sidesepts SSL issues 
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        
        if verbose:
            logger.debug("aiohttp: SSL context created - verify_mode=%s, check_hostname=%s", 
                        ssl_context.verify_mode, ssl_context.check_hostname)
        
        connector = aiohttp.TCPConnector(
            ssl=ssl_context,
            enable_cleanup_closed=True
        )
        
        if verbose:
            logger.debug("aiohttp: TCPConnector created")
        
        async with aiohttp.ClientSession(connector=connector, trace_configs=trace_configs) as session:
            async with session.post(url, headers=headers, data=payload.model_dump_json()) as response:
                if response.status == 200:
                    results = AnalysisServerResponse.model_validate_json(await response.read())
                else:
                    logger.debug("Error: %s - %s", response.status, await response.text())
                    raise Exception(f"Error: {response.status} - {await response.text()}")

        scan_path.issues += results.issues
        scan_path.labels = results.labels
    except Exception as e:
        logger.exception("Error analyzing scan path")
        try:
            errstr = str(e.args[0])
            errstr = errstr.splitlines()[0]
        except Exception:
            errstr = ""
        for server_idx, server in enumerate(scan_path.servers):
            if server.signature is not None:
                for i, _ in enumerate(server.entities):
                    scan_path.issues.append(
                        Issue(
                            code="X001",
                            message=f"could not reach analysis server {errstr}",
                            reference=(server_idx, i),
                        )
                    )
    return scan_path
