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



def mcp_server(args):

    mcp = FastMCP("MCP Scan")#, lifespan=app_lifespan)

    # Add an addition tool
    @mcp.tool()
    async def scan() -> str:
        """Performs a the current MCP setup (this client + tools it uses)"""
        parser = argparse.ArgumentParser()
        setup_scan_parser(parser)
        
        # Use default arguments (scan all well-known MCP paths)
        parsed_args = parser.parse_args(args=args)
        
        # Run the actual scan
        result = await run_scan_inspect(mode="scan", args=parsed_args)
        
        # Convert result to JSON format for return
        result_dict = {r.path: r.model_dump() for r in result}
        return json.dumps(result_dict, indent=2)
   
    return mcp.run()