import aiohttp

from .models import EntityScanResult, ScanPathResult, VerifyServerRequest, VerifyServerResponse


async def verify_server(scan_path: ScanPathResult, base_url: str) -> ScanPathResult:
    output_path = scan_path.model_copy(deep=True)
    url = base_url[:-1] if base_url.endswith("/") else base_url
    url = url + "/api/v1/public/mcp-scan"
    headers = {"Content-Type": "application/json"}
    payload = VerifyServerRequest(root=[])
    for server in scan_path.servers:
        # None server signature are servers which are not reachable.
        if server.signature is not None:
            payload.root.append(server.signature)
    # Server signatures do not contain any information about the user setup. Only about the server itself.
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, data=payload.model_dump_json()) as response:
                if response.status == 200:
                    results = VerifyServerResponse.model_validate_json(await response.read())
                else:
                    raise Exception(f"Error: {response.status} - {await response.text()}")
        for server in output_path.servers:
            if server.signature is None:
                pass
            server.result = results.root.pop(0)
        assert len(results.root) == 0  # all results should be consumed
        return output_path
    except Exception as e:
        try:
            errstr = str(e.args[0])
            errstr = errstr.splitlines()[0]
        except Exception:
            errstr = ""
        for server in output_path.servers:
            if server.signature is not None:
                server.result = [
                    EntityScanResult(status="could not reach verification server " + errstr) for _ in server.entities
                ]

        return output_path
