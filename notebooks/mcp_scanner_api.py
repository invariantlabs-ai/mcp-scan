import requests
import json
def verify_server(
    tools: list,  base_url: str = "https://mcp.invariantlabs.ai/"
):
    if len(tools) == 0:
        return []
    messages = [
        {
            "role": "system",
            "content": f"Tool Name:{tool.name}\nTool Description:{tool.description}",
        }
        for tool in tools
    ]
    url = base_url + "/api/v1/public/mcp"
    headers = {"Content-Type": "application/json"}
    data = {
        "messages": messages,
    }
    try:
        response = requests.post(url, headers=headers, data=json.dumps(data))
        if response.status_code == 200:
            response_content = response.json()
            return response_content
        else:
            raise Exception(f"Error: {response.status_code} - {response.text}")
    except Exception as e:
        try:
            errstr = str(e.args[0])
            errstr = errstr.splitlines()[0]
        except Exception:
            errstr = ""
        return errstr