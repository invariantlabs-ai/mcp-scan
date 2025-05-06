import ast
import json

import aiohttp

from .models import EntityScanResult, ServerScanResult, entity_type_to_str


async def verify_server(server_scan_result: ServerScanResult, base_url: str) -> ServerScanResult:
    result = server_scan_result.model_copy(deep=True)
    if len(server_scan_result.entities) == 0:
        return result
    messages = [
        {
            "role": "system",
            "content": (
                f"{entity_type_to_str(entity).capitalize()} Name:{entity.name}\n"
                f"{entity_type_to_str(entity).capitalize()} Description:{entity.description}"
            ),
        }
        for entity in server_scan_result.entities
    ]
    url = base_url[:-1] if base_url.endswith("/") else base_url
    url = url + "/api/v1/public/mcp"
    headers = {"Content-Type": "application/json"}
    data = {
        "messages": messages,
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, data=json.dumps(data)) as response:
                if response.status == 200:
                    response_content: dict = await response.json()
                    result.result = [EntityScanResult(verified=True) for _ in messages]
                    for error in response_content.get("errors", []):
                        key = ast.literal_eval(error["key"])
                        idx = key[1][0]
                        result.result[idx].verified = False
                        result.result[idx].status = "failed - " + " ".join(error["args"])
                    return result
                else:
                    raise Exception(f"Error: {response.status} - {await response.text()}")
    except Exception as e:
        try:
            errstr = str(e.args[0])
            errstr = errstr.splitlines()[0]
        except Exception:
            errstr = ""
        result.result = [EntityScanResult(status="could not reach verification server " + errstr) for _ in messages]
        return result
