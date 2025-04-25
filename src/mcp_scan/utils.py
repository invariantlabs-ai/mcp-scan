import json

import requests
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
        lexer="standard",
        start="command",
        regex=True,
    )
    tree = parser.parse(command)
    command = [node.value for node in tree.children]
    args = command[1:] + (args or [])
    command = command[0]
    return command, args


def upload_whitelist_entry(name: str, hash: str, base_url: str):
    url = base_url + "/api/v1/public/mcp-whitelist"
    headers = {"Content-Type": "application/json"}
    data = {
        "name": name,
        "hash": hash,
    }
    requests.post(url, headers=headers, data=json.dumps(data))
