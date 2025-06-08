#!/usr/bin/env python3
import json
import sys
import asyncio
from typing import Any, Dict

async def handle_initialize(request: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request.get("id"),
        "result": {
            "protocolVersion": "2024-11-05",
            "serverInfo": {
                "name": "Simple MCP Server",
                "version": "mcp_version"
            },
            "capabilities": {
                "experimental": {},
                "logging": None,
                "prompts": {
                    "listChanged": False
                },
                "resources": {
                    "subscribe": False,
                    "listChanged": False
                },
                "tools": {
                    "listChanged": False
                }
            }
        }
    }

async def handle_list_prompts(request: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request.get("id"),
        "result": {
            "prompts": [
                {
                    "name": "echo",
                    "description": "Echoes back the input"
                },
                {
                    "name": "list_files",
                    "description": "Lists files in a directory"
                }
            ]
        }
    }

async def handle_list_resources(request: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request.get("id"),
        "result": {
            "resources": []
        }
    }

async def handle_list_tools(request: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request.get("id"),
        "result": {
            "tools": [
                {
                    "name": "echo",
                    "description": "Echoes back the input",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "message": {
                                "type": "string",
                                "description": "Message to echo"
                            }
                        },
                        "required": ["message"]
                    }
                },
                {
                    "name": "list_files",
                    "description": "Lists files in a directory",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Directory path to list"
                            }
                        },
                        "required": ["path"]
                    }
                }
            ]
        }
    }

async def handle_request(request_str: str) -> str:
    try:
        request = json.loads(request_str)
        method = request.get("method")
        
        # 메서드 이름 매핑
        method_map = {
            "initialize": handle_initialize,
            "prompts/list": handle_list_prompts,
            "resources/list": handle_list_resources,
            "tools/list": handle_list_tools
        }
        
        handler = method_map.get(method)
        if handler:
            response = await handler(request)
        else:
            response = {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}"
                }
            }
        
        return json.dumps(response) + "\n"
    except Exception as e:
        return json.dumps({
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "error": {
                "code": -32603,
                "message": str(e)
            }
        }) + "\n"

async def main():
    while True:
        try:
            request_str = await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)
            if not request_str:
                break
            response = await handle_request(request_str)
            sys.stdout.write(response)
            sys.stdout.flush()
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.stderr.flush()

if __name__ == "__main__":
    asyncio.run(main()) 