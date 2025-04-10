import os
from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.client.sse import sse_client
import json
import os
import textwrap
import asyncio
import requests
import ast
import rich
from rich.tree import Tree
from .surpressIO import SuppressStd
from collections import namedtuple
from datetime import datetime
from hashlib import md5

Result = namedtuple("Result", field_names=["value", "message"], defaults=[None, None])


def format_path_line(path, status):
    text = f"● Scanning [bold]{path}[/bold] [gray62]{status}[/gray62]"
    return rich.text.Text.from_markup(text)


def format_servers_line(server, status=None):
    text = f"[bold]{server}[/bold]"
    if status:
        text += f" [gray62]{status}[/gray62]"
    return rich.text.Text.from_markup(text)


def format_tool_line(tool, verified: Result, changed: Result = Result(), type="tool"):
    is_verified = verified.value
    if is_verified is not None and changed.value is not None:
        is_verified = is_verified and not changed.value

    message = [verified.message, changed.message]
    message = [m for m in message if m is not None]
    message = ", ".join(message)

    color = {True: "[green]", False: "[red]", None: "[gray62]"}[is_verified]
    icon = {True: ":white_heavy_check_mark:", False: ":cross_mark:", None: ""}[
        is_verified
    ]
    name = tool.name
    if len(name) > 25:
        name = name[:22] + "..."
    name = name + " " * (25 - len(name))
    text = f"{type} {color}[bold]{name}[/bold] {icon} {message}"

    text = rich.text.Text.from_markup(text)
    return text


def format_inspect_tool_line(
    tool,
):
    name = tool.name
    if len(name) > 25:
        name = name[:22] + "..."
    name = name + " " * (25 - len(name))

    if hasattr(tool, "description"):
        # dedent the description
        description = tool.description
        # wrap the description to 80 characters
        description = textwrap.dedent(description)
    else:
        description = "<no description available>"

    color = "[gray62]"
    icon = ""
    type = "tool"
    message = ""
    text = f"{type} {color}[bold]{name}[/bold] {icon} {message}"
    text += f"\n{description}"

    text = rich.text.Text.from_markup(text)
    return text


def verify_server(tools, prompts, resources, base_url):
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
            response = response.json()
            results = [Result(True, "verified") for _ in tools]
            for error in response["errors"]:
                key = ast.literal_eval(error["key"])
                idx = key[1][0]
                results[idx] = Result(False, "failed - " + " ".join(error["args"]))
            return results
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
        ]


async def check_server(server_config, timeout):
    def get_client(server_config):
        if "url" in server_config:
            raise NotImplementedError("SSE servers not supported yet")
            # return sse_client(url=server_config['url'], timeout=timeout)
        else:
            server_params = StdioServerParameters(**server_config)
            return stdio_client(server_params)

    with SuppressStd():
        async with get_client(server_config) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                try:
                    prompts = await session.list_prompts()
                    prompts = list(prompts.prompts)
                except:
                    prompts = []
                try:
                    resources = await session.list_resources()
                    resources = list(resources.resources)
                except:
                    resources = []
                try:
                    tools = await session.list_tools()
                    tools = list(tools.tools)
                except:
                    tools = []
    return prompts, resources, tools


async def check_server_with_timeout(server_config, timeout):
    return await asyncio.wait_for(check_server(server_config, timeout), timeout)


def scan_config_file(path):
    path = os.path.expanduser(path)
    with open(path, "r") as f:
        config = json.load(f)
        servers = config.get("mcpServers")
        return servers


class StorageFile:
    def __init__(self, path):
        self.path = path
        self.data = {}
        if os.path.exists(path):
            with open(path, "r") as f:
                self.data = json.load(f)

    def compute_hash(self, server_name, tool):
        return md5(tool.description.encode()).hexdigest()

    def check_and_update(self, server_name, tool, verified):
        key = f"{server_name}.{tool.name}"
        hash = self.compute_hash(server_name, tool)
        new_data = {
            "hash": hash,
            "timestamp": datetime.now().strftime("%d/%m/%Y, %H:%M:%S"),
            "description": tool.description,
        }
        changed = False
        message = None
        if key in self.data:
            changed = self.data[key]["hash"] != new_data["hash"]
            if changed:
                message = (
                    "tool description changed since previous scan at "
                    + self.data[key]["timestamp"]
                )
        self.data[key] = new_data
        return Result(changed, message)

    def save(self):
        with open(self.path, "w") as f:
            json.dump(self.data, f)


class MCPScanner:
    def __init__(
        self, files, base_url, checks_per_server, storage_file, server_timeout
    ):
        self.paths = files
        self.base_url = base_url
        self.checks_per_server = checks_per_server
        self.storage_file_path = os.path.expanduser(storage_file)
        self.storage_file = StorageFile(self.storage_file_path)
        self.server_timeout = server_timeout

    def inspect_path(self, path, verbose=True):
        """
        Just inspects the server and prints the tools, prompts and resources without checking them.
        """
        try:
            servers = scan_config_file(path)
            status = f"found {len(servers)} server{'' if len(servers) == 1 else 's'}"
        except FileNotFoundError:
            status = f"file does not exist"
            return
        except json.JSONDecodeError:
            status = f"invalid json"
            return
        finally:
            if verbose:
                rich.print(format_path_line(path, status))

        path_print_tree = Tree("│")
        for server_name, server_config in servers.items():
            try:
                prompts, resources, tools = asyncio.run(
                    check_server_with_timeout(server_config, self.server_timeout)
                )
                status = None
            except TimeoutError as e:
                status = "Could not reach server within timeout"
                continue
            except Exception as e:
                status = str(e).splitlines()[0] + "..."
                continue
            finally:
                server_print = path_print_tree.add(
                    format_servers_line(server_name, status)
                )

            for tool in tools:
                server_print.add(format_inspect_tool_line(tool))

            for prompt in prompts:
                server_print.add(format_inspect_tool_line(prompt))

            for resource in resources:
                server_print.add(format_inspect_tool_line(resource))

        if len(servers) > 0 and verbose:
            rich.print(path_print_tree)

    def scan(self, path, verbose=True):
        try:
            servers = scan_config_file(path)
            status = f"found {len(servers)} server{'' if len(servers) == 1 else 's'}"
        except FileNotFoundError:
            status = f"file does not exist"
            return
        except json.JSONDecodeError:
            status = f"invalid json"
            return
        finally:
            if verbose:
                rich.print(format_path_line(path, status))

        path_print_tree = Tree("│")
        servers_with_tools = {}
        for server_name, server_config in servers.items():
            try:
                prompts, resources, tools = asyncio.run(
                    check_server_with_timeout(server_config, self.server_timeout)
                )
                status = None
            except TimeoutError as e:
                status = "Could not reach server within timeout"
                continue
            except Exception as e:
                status = str(e).splitlines()[0] + "..."
                continue
            finally:
                server_print = path_print_tree.add(
                    format_servers_line(server_name, status)
                )
            servers_with_tools[server_name] = tools

            verification_result = verify_server(
                tools, prompts, resources, base_url=self.base_url
            )
            for tool, verified in zip(tools, verification_result):
                changed = self.storage_file.check_and_update(
                    server_name, tool, verified.value
                )
                server_print.add(format_tool_line(tool, verified, changed))
            for prompt in prompts:
                server_print.add(
                    format_tool_line(prompt, Result(message="skipped"), type="prompt")
                )
            for resource in resources:
                server_print.add(
                    format_tool_line(
                        resource, Result(message="skipped"), type="resource"
                    )
                )

        if len(servers) > 0 and verbose:
            rich.print(path_print_tree)

        # cross-references check
        # for each tool check if it referenced by tools of other servers
        cross_ref_found = False
        cross_reference_sources = set()
        for server_name, tools in servers_with_tools.items():
            other_server_names = set(servers.keys())
            other_server_names.remove(server_name)
            other_tool_names = [
                tool.name
                for s in other_server_names
                for tool in servers_with_tools.get(s, [])
            ]
            flagged_names = list(other_server_names) + other_tool_names
            flagged_names = set(map(str.lower, flagged_names))
            for tool in tools:
                tokens = tool.description.lower().split()
                for token in tokens:
                    if token in flagged_names:
                        cross_ref_found = True
                        cross_reference_sources.add(token)
        if cross_ref_found and verbose:
            rich.print(
                rich.text.Text.from_markup(
                    f"\n[bold yellow]:construction: Cross-Origin Violation: Tool descriptions of server {cross_reference_sources} explicitly mention tools of other servers, or other servers.[/bold yellow]"
                ),
            )

        print()

    def start(self):
        for i, path in enumerate(self.paths):
            for k in range(self.checks_per_server):
                self.scan(path, verbose=(k == self.checks_per_server - 1))
            if i < len(self.paths) - 1:
                rich.print("")
        self.storage_file.save()

    def inspect(self):
        for i, path in enumerate(self.paths):
            self.inspect_path(path, verbose=True)
            if i < len(self.paths) - 1:
                rich.print("")
        self.storage_file.save()
