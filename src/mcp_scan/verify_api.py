import requests
import json
import ast
from .models import Result
from mcp.types import Tool, Prompt, Resource

def verify_server(
    tools: list[Tool],
    prompts: list[Prompt],
    resources: list[Resource],
    base_url: str
) -> tuple[list[Result], list[Result], list[Result]]:
    if len(tools) + len(prompts) + len(resources) == 0:
        return [], [], []
    messages = [
        {
            "role": "system",
            "content": f"Tool Name:{tool.name}\nTool Description:{tool.description}",
        }
        for tool in tools
    ]
    messages += [
        {
            "role": "system",
            "content": f"Prompt Name:{prompt.name}\nPrompt Description:{prompt.description}",
        }
        for prompt in prompts
    ]
    messages += [
        {
            "role": "system",
            "content": f"Resource Name:{resource.name}\nResource Description:{resource.description}",
        }
        for resource in resources
    ]
    url = base_url + "/api/v1/public/mcp"
    headers = {"Content-Type": "application/json"}
    data = {
        "messages": messages,
    }
    try:
        response = requests.post(url, headers=headers, data=json.dumps(data))
        if response.status_code == 200:
            response_content: dict = response.json()
            results = [Result(True, "verified") for _ in messages]
            for error in response_content.get("errors", []):
                key = ast.literal_eval(error["key"])
                idx = key[1][0]
                results[idx] = Result(False, "failed - " + " ".join(error["args"]))
            results_tools, results = results[:len(tools)], results[len(tools):]
            results_prompts, results = results[:len(prompts)], results[len(prompts):]
            results_resources = results
            return results_tools, results_prompts, results_resources
        else:
            raise Exception(f"Error: {response.status_code} - {response.text}")
    except Exception as e:
        try:
            errstr = str(e.args[0])
            errstr = errstr.splitlines()[0]
        except Exception:
            errstr = ""
        return [
            Result(None, "could not reach verification server " + errstr) for _ in tools
        ], [
            Result(None, "could not reach verification server " + errstr) for _ in prompts
        ], [
            Result(None, "could not reach verification server " + errstr) for _ in resources
        ]

