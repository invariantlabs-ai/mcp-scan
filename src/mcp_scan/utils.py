import contextlib
import glob
import logging
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from lark import Lark
from rapidfuzz.distance import Levenshtein

from mcp_scan.models import ControlServer, StdioServer

logger = logging.getLogger(__name__)


class CommandParsingError(Exception):
    pass


def get_relative_path(path: str) -> str:
    try:
        expanded_path = os.path.expanduser(path)
        home_dir = os.path.expanduser("~")
        if expanded_path.startswith(home_dir):
            result = "~" + expanded_path[len(home_dir) :]
            # Normalize to forward slashes for consistent display across platforms
            return result.replace("\\", "/")
        return path
    except Exception:
        return path


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


def parse_headers(headers: list[str] | None) -> dict:
    if headers is None:
        return {}
    headers = [header.strip() for header in headers]
    for header in headers:
        if ":" not in header:
            raise ValueError(f"Invalid header: {header}")
    return {header.split(":")[0]: header.split(":")[1] for header in headers}


def check_executable_exists(command: str) -> bool:
    path = Path(command)
    return path.exists() or shutil.which(command) is not None


def resolve_command_and_args(server_config: StdioServer) -> tuple[str, list[str] | None]:
    """
    Resolve the command and arguments for a StdioServer.
    """
    # check if command points to an executable and whether it exists absolute or on the path
    if check_executable_exists(server_config.command):
        return server_config.command, server_config.args

    # attempt to rebalance the command/arg structure
    logger.debug(f"Command does not exist: {server_config.command}, attempting to rebalance")
    command, args = rebalance_command_args(server_config.command, server_config.args)
    if check_executable_exists(command):
        return command, args

    if os.path.sep in command:
        logger.warning(f"Path does not exist: {command}")
        raise ValueError(f"Path does not exist: {command}")

    # attempt to find the command in well-known directories
    # npx via nvm - look for node versions directory
    nvm_pattern = os.path.expanduser("~/.nvm/versions/node/*/bin")
    nvm_dirs = sorted(glob.glob(nvm_pattern), reverse=True)
    fallback_dirs = [
        # node / npx
        *nvm_dirs,
        os.path.expanduser("~/.npm-global/bin"),
        os.path.expanduser("~/.yarn/bin"),
        os.path.expanduser("~/.local/share/pnpm"),
        os.path.expanduser("~/.config/yarn/global/node_modules/.bin"),
        # python / uvx
        os.path.expanduser("~/.cargo/bin"),
        os.path.expanduser("~/.pyenv/shims"),
        # user local paths
        os.path.expanduser("~/.local/bin"),
        os.path.expanduser("~/.bin"),
        os.path.expanduser("~/bin"),
        # package manager paths
        "/opt/homebrew/bin",
        "/opt/local/bin",
        "/snap/bin",
        # system paths
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
        # docker path
        "/Applications/Docker.app/Contents/Resources/bin",
    ]

    for d in fallback_dirs:
        potential_path = os.path.join(d, command)
        if check_executable_exists(potential_path):
            logger.debug(f"Found {command} at fallback location: {potential_path}")
            return potential_path, args

    logger.warning(f"Command {command} not found in any fallback location")
    raise ValueError(f"Command {command} not found")


@contextlib.contextmanager
def suppress_stdout():
    with open(os.devnull, "w") as devnull:
        with contextlib.redirect_stdout(devnull):
            yield


def get_push_key(control_servers: list[ControlServer] | list[dict[str, Any]]) -> str | None:
    parsed_control_servers: list[ControlServer] = []
    for control_server in control_servers:
        if isinstance(control_server, dict):
            parsed_control_servers.append(
                ControlServer(
                    url=control_server["url"],
                    headers=parse_headers(control_server["headers"]),
                    identifier=control_server["identifier"],
                    opt_out=control_server["opt_out"],
                )
            )
        else:
            parsed_control_servers.append(control_server)
    for control_server in parsed_control_servers:
        for header in control_server.headers:
            if "x-client-id" in header:
                return control_server.headers[header]
    return None
