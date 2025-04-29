import json

import aiohttp
from lark import Lark


def rebalance_command_args(command, args):
    # create a parser that splits on whitespace,
    # unless it is inside "." or '.'
    # unless that is escaped
    # permit arbitrary whitespace between parts
    parser = Lark(
        r"""
        command: WORD+
        WORD: (PART|SQUOTEDPART|DQUOTEDPART)
        PART: /[^\s'".]+/
        SQUOTEDPART: /'[^']'/
        DQUOTEDPART: /"[^"]"/
        %import common.WS
        %ignore WS
        """,
        parser="lalr",
        start="command",
        regex=True,
    )
    tree = parser.parse(command)
    command = [node.value for node in tree.children]
    args = command[1:] + (args or [])
    command = command[0]
    return command, args


async def upload_whitelist_entry(name: str, hash: str, base_url: str):
    url = base_url + "/api/v1/public/mcp-whitelist"
    headers = {"Content-Type": "application/json"}
    data = {
        "name": name,
        "hash": hash,
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=headers, data=json.dumps(data)) as response:
            if response.status != 200:
                raise Exception(f"Failed to upload whitelist entry: {response.status} - {response.text}")
