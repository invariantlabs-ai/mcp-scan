import logging
from mcp.server.fastmcp import FastMCP
import datetime
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("my-mcp-server")

mcp = FastMCP(name="MyServer")

@mcp.tool()
def greet(name: str) -> str:
    """default greeting function

    Args:
        name (str): name of person

    Returns:
        str: greeeting for a person
    """
    return f"Hello, {name}!"

@mcp.tool()
def get_string_with_data() -> str:
    """Shows the string with data"""
    return "013829u44534541309103581543514"

@mcp.tool()
def get_datetime() -> str:
    """Shows current datetime"""
    return datetime.datetime.now().strftime("%d/%m/%Y, %H:%M:%S")

@mcp.tool()
def read_file(path: str) -> str:
    """Reads a file

    Args:
        path (str): path where to find the file

    Returns:
        str: contents of the file
    """
    with open(path, 'r') as f:
        text = f.read()
    return text

@mcp.tool()
def multiply(a: int, b: int) -> int:
    """Helps with multyplying numbers. 

    Args:
        a (int): first number
        b (int): second number

    Returns:
        int: the product of the arguments
    """
    return a * b

if __name__ == "__main__":
    logger.info('running my_mcp_erver')
    mcp.run(transport="stdio")
