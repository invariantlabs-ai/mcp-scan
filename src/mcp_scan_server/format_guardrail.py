def blacklist_tool_from_guardrail(guardrail_content: str, tool_names: list[str]) -> str:
    """Format a guardrail to only raise an error if the tool is not in the list.

    Args:
        guardrail_content (str): The content of the guardrail.
        tool_names (list[str]): The names of the tools to blacklist.

    Returns:
        str: The formatted guardrail.
    """
    assert (
        "#BLACKLIST_WHITELIST_STATEMENT" in guardrail_content
    ), "Guardrail must contain #BLACKLIST_WHITELIST_STATEMENT"

    if len(tool_names) == 0:
        return guardrail_content.replace("#BLACKLIST_WHITELIST_STATEMENT", "")
    return guardrail_content.replace(
        "#BLACKLIST_WHITELIST_STATEMENT", f"not (tool_call(tooloutput).function.name in {tool_names})"
    )


def whitelist_tool_from_guardrail(guardrail_content: str, tool_names: list[str]) -> str:
    """Format a guardrail to only raise an error if the tool is in the list.

    Args:
        guardrail_content (str): The content of the guardrail.
        tool_names (list[str]): The names of the tools to whitelist.

    Returns:
        str: The formatted guardrail.
    """
    assert (
        "#BLACKLIST_WHITELIST_STATEMENT" in guardrail_content
    ), "Guardrail must contain #BLACKLIST_WHITELIST_STATEMENT"
    return guardrail_content.replace(
        "#BLACKLIST_WHITELIST_STATEMENT", f"tool_call(tooloutput).function.name in {tool_names}"
    )
