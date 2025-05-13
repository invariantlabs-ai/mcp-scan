import json
import os
import tempfile

import aiohttp
from lark import Lark
from rapidfuzz.distance import Levenshtein


class CommandParsingError(Exception):
    pass


def calculate_distance(responses: list[str], reference: str):
    return sorted([(w, Levenshtein.distance(w, reference)) for w in responses], key=lambda x: x[1])


# Cache the Lark parser to avoid recreation on every call
_command_parser = None


def rebalance_command_args(command, args):
    # create a parser that splits on whitespace,
    # unless it is inside "." or '.'
    # unless that is escaped
    # permit arbitrary whitespace between parts
    global _command_parser
    if _command_parser is None:
        _command_parser = Lark(
            r"""
            command: WORD+
            WORD: (PART|SQUOTEDPART|DQUOTEDPART)
            PART: /[^\s'"]+/
            SQUOTEDPART: /'[^']*'/
            DQUOTEDPART: /"[^"]*"/
            %import common.WS
            %ignore WS
            """,
            parser="lalr",
            start="command",
            regex=True,
        )
    try:
        tree = _command_parser.parse(command)
        command_parts = [node.value for node in tree.children]
        args = command_parts[1:] + (args or [])
        command = command_parts[0]
    except Exception as e:
        raise CommandParsingError(f"Failed to parse command: {e}") from e
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


class TempFile:
    """A windows compatible version of tempfile.NamedTemporaryFile."""

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.file = None

    def __enter__(self):
        args = self.kwargs.copy()
        args["delete"] = False
        self.file = tempfile.NamedTemporaryFile(**args)
        return self.file

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.file.close()
        os.unlink(self.file.name)
