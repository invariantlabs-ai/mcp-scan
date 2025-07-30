from datetime import datetime
import threading
import time
from contextlib import asynccontextmanager
from typing import AsyncIterator
from mcp.server.fastmcp import FastMCP
from mcp_scan.cli import run_scan_inspect, setup_scan_parser
import asyncio
import argparse
import os
import json
from mcp_scan.Storage import Storage
import logging

logger = logging.getLogger(__name__)

def do_mcp_scan():
    with open('/tmp/mcp-scan-test.txt', 'w') as f:
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"{current_time} - MCP Scan\n")

# start a thread that runs the do_mcp_scan function
def thread_fn():
    t = threading.current_thread()
    while getattr(t, "do_run", True): # TODO: make this an interruptible sleep
        do_mcp_scan()
        # sleep for 1 second
        time.sleep(5)

class Scanner:
    def __init__(self):
        self.thread = None

    def start(self):
        self.thread = threading.Thread(target=thread_fn)
        self.thread.start()

    def stop(self):
        self.thread.do_run = False
        self.thread.join()

@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[Scanner]:
    scanner = Scanner()
    scanner.start()
    # Initialize on startup
    try:
        yield scanner
    finally:
        scanner.stop()

def setup_mcp_server_logging(log_path):
    logging.basicConfig(
        format="%(message)s",
        filemode="a",
        filename=log_path,
        datefmt="[%X]",
        level=logging.DEBUG,
    )
    return logging.getLogger(__name__)


def mcp_server(tool=False, background=False, args=None):

    # get args
    parser = argparse.ArgumentParser()
    setup_scan_parser(parser)
    parsed_args = parser.parse_args(args=args or [])
    
    # get storage path 
    storage_file = Storage(parser.storage_file)




    instructions = \
        """
        This is a MCP server that scans this agent (and the MCP servers it uses) for MCP--related security vunerabilities.
        """
        
    if background:
        instructions += "\nScans are performed periodically in the background."
        if tool:
            instructions += "\nCall the get_scan_results tool to obtain the results."
        mcp = FastMCP("MCP Scan", instructions=instructions, lifespan=app_lifespan)
    else:
        if tool:
            instructions += "\nScans can be performed by calling the scan tool."
            mcp = FastMCP("MCP Scan", instructions=instructions)
        else:
            assert False, "either background or tool must be true"

    if background and tool:
        @mcp.tool()
        async def get_scan_results() -> str:
            scanner = mcp.get_context().scanner
            if scanner.last_scan is None:
                print()

            return "Not implemented"
    elif tool:
            @mcp.tool()
            async def scan() -> str:
                """Performs a the current MCP setup (this client + tools it uses)"""
                
                # Run the actual scan
                result = await run_scan_inspect(mode="scan", args=parsed_args)
                
                # Convert result to JSON format for return
                result_dict = {r.path: r.model_dump() for r in result}
                return json.dumps(result_dict, indent=2)
        
        
   
    return mcp.run()