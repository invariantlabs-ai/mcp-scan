import random
from mcp.server.fastmcp import FastMCP
from mcp.types import PromptReference, ResourceTemplateReference, CompletionArgument, CompletionContext, Completion

# Create an MCP server
mcp = FastMCP("Weather")

possible_weathers = ["Sunny", "Rainy", "Cloudy", "Snowy", "Windy"]


@mcp.tool()
def weather(location: str) -> str:
    """Get current weather for a location."""
    return random.choice(possible_weathers)


@mcp.prompt()
def good_morning(name: str, weather: str = "Rainy") -> str:
    """Prompt to generate a good morning message for the user."""
    weather = weather.lower()
    return f"Write a good morning message for {name}. Their weather today is {weather}."

# resource
@mcp.resource("weather://list")
def weathers() -> str:
    """List of possible weather supported by the server."""
    return "Possible weathers: " + ", ".join(possible_weathers)

# resource template
@mcp.resource("weather://{weather}/description")
def weather_description(weather: str) -> str:
    """Description of a weather."""
    descriptions = {
        "sunny": "The sun is shining, the sky is clear, and the temperature is warm.",
        "rainy": "The sky is cloudy, the temperature is cool, and the air is humid.",
        "cloudy": "The sky is cloudy, the temperature is cool, and the air is humid.",
        "snowy": "The sky is cloudy, the temperature is cool, and the air is humid.",
        "windy": "The sky is cloudy, the temperature is cool, and the air is humid.",
        "unknown": "Unknown weather"
    }
    return descriptions.get(weather.lower(), "unknown")

@mcp.completion()
def weather_completion(
    ref: PromptReference | ResourceTemplateReference,
    argument: CompletionArgument,
    context: CompletionContext | None,
) -> Completion:
    """Completion for a weather prompt or resource template."""
    if argument.name == "weather":
        if isinstance(ref, PromptReference) and ref.name == "good_morning":
            return Completion(values=possible_weathers, hasMore=False)
        elif isinstance(ref, ResourceTemplateReference) and ref.name == "weather_description":
            return Completion(values=possible_weathers, hasMore=False)
    return None


if __name__ == "__main__":
    mcp.run()
