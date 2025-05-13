import importlib
import re
from functools import lru_cache

from invariant.analyzer.extras import Extra

BLACKLIST_WHITELIST = r"{{ BLACKLIST_WHITELIST }}"
REQUIRES_PATTERN = re.compile(r"\{\{\s*REQUIRES:\s*\[(.*?)\]\s*\}\}")


def blacklist_tool_from_guardrail(guardrail_content: str, tool_names: list[str]) -> str:
    """Format a guardrail to only raise an error if the tool is not in the list.

    Args:
        guardrail_content (str): The content of the guardrail.
        tool_names (list[str]): The names of the tools to blacklist.

    Returns:
        str: The formatted guardrail.
    """
    assert BLACKLIST_WHITELIST in guardrail_content, f"Default guardrail must contain {BLACKLIST_WHITELIST}"

    if len(tool_names) == 0:
        return guardrail_content.replace(BLACKLIST_WHITELIST, "")
    return guardrail_content.replace(BLACKLIST_WHITELIST, f"not (tool_call(tooloutput).function.name in {tool_names})")


def whitelist_tool_from_guardrail(guardrail_content: str, tool_names: list[str]) -> str:
    """Format a guardrail to only raise an error if the tool is in the list.

    Args:
        guardrail_content (str): The content of the guardrail.
        tool_names (list[str]): The names of the tools to whitelist.

    Returns:
        str: The formatted guardrail.
    """
    assert BLACKLIST_WHITELIST in guardrail_content, f"Default guardrail must contain {BLACKLIST_WHITELIST}"
    return guardrail_content.replace(BLACKLIST_WHITELIST, f"tool_call(tooloutput).function.name in {tool_names}")


@lru_cache
def extract_requires(guardrail_content: str) -> list[Extra]:
    """Extract the requires from a guardrail.

    Args:
        guardrail_content (str): The content of the guardrail.

    Returns:
        list[str]: The requires.
    """
    match = re.search(REQUIRES_PATTERN, guardrail_content)
    if not match:
        raise ValueError(f"Default guardrail must contain {REQUIRES_PATTERN}")

    extras_str = match.group(1).strip()
    if not extras_str:
        return []

    extras_names = [extra.strip() for extra in extras_str.split(",") if extra.strip()]
    extras_available = []
    path = "invariant.analyzer.extras"

    for extra in extras_names:
        try:
            module = importlib.import_module(path)
            extra_class = getattr(module, extra)
            extras_available.append(extra_class)
        except (ImportError, AttributeError) as e:
            raise ValueError(f"Extra '{extra}' not found in '{path}'.") from e

    return extras_available
