import ast
import json
import rich
import aiohttp

from .models import EntityScanResult, ScanPathResult


async def verify_server(scan_path: ScanPathResult, base_url: str) -> ScanPathResult:
    if len(scan_path.entities) == 0:
        return scan_path.model_copy(deep=True)
    url = base_url[:-1] if base_url.endswith("/") else base_url
    url = url + "/api/v2/public/mcp"
    headers = {"Content-Type": "application/json"}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, data=scan_path.model_dump_json()) as response:
                if response.status == 200:
                    return ScanPathResult.model_validate_json(await response.read())
                else:
                    raise Exception(f"Error: {response.status} - {await response.text()}")
    except Exception as e:
        try:
            errstr = str(e.args[0])
            errstr = errstr.splitlines()[0]
        except Exception:
            errstr = ""
        result = scan_path.model_copy(deep=True)
        for server in result.servers:
            server.result = [EntityScanResult(status="could not reach verification server " + errstr) for _ in server.entities]
        return result
