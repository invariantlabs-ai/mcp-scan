"""
Traffic capture utilities for MCP protocol debugging.

This module provides classes to capture MCP protocol traffic (sent and received
messages, plus stderr output) for debugging failed server connections.
"""

import asyncio
import contextlib
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TrafficCapture:
    """Captures MCP protocol traffic (messages sent and received) plus stderr."""

    sent: list[Any] = field(default_factory=list)
    received: list[Any] = field(default_factory=list)
    stderr: list[str] = field(default_factory=list)

    def get_traffic_log(self, max_chars: int = 10000) -> str | None:
        """Format captured traffic as a string for error reporting."""
        lines = []
        for msg in self.sent:
            lines.append(f">>> SENT: {msg}")
        for msg in self.received:
            lines.append(f"<<< RECV: {msg}")
        for line in self.stderr:
            lines.append(f"STDERR: {line}")

        if not lines:
            return None

        output = "\n".join(lines)
        if len(output) > max_chars:
            return output[:max_chars] + "\n... (truncated)"
        return output


class PipeStderrCapture:
    """
    A file-like object backed by a real OS pipe for capturing stderr.

    This can be passed to subprocess.Popen as stderr because it has a real
    file descriptor via fileno().
    """

    def __init__(self, capture: TrafficCapture):
        self._capture = capture
        # Create a real OS pipe
        self._read_fd, self._write_fd = os.pipe()
        # Wrap write end as a file object for the subprocess
        self._write_file = os.fdopen(self._write_fd, "w")
        self._reader_task: asyncio.Task | None = None
        self._closed = False

    def fileno(self) -> int:
        """Return the write end file descriptor for subprocess."""
        return self._write_fd

    def write(self, data: str) -> int:
        """Write to the pipe (used if errlog is written to directly)."""
        return self._write_file.write(data)

    def flush(self) -> None:
        """Flush the write buffer."""
        self._write_file.flush()

    async def start_reading(self) -> None:
        """Start a background task to read from the pipe and capture stderr."""
        self._reader_task = asyncio.create_task(self._read_stderr())

    async def _read_stderr(self) -> None:
        """Read stderr from the pipe in a background task."""
        loop = asyncio.get_event_loop()
        read_file = os.fdopen(self._read_fd, "r")
        try:
            while True:
                # Read in executor to avoid blocking the event loop
                line = await loop.run_in_executor(None, read_file.readline)
                if not line:
                    break
                line = line.rstrip("\n\r")
                if line:
                    self._capture.stderr.append(line)
        except Exception:
            pass  # Pipe closed or error
        finally:
            with contextlib.suppress(Exception):
                read_file.close()

    async def close(self) -> None:
        """Close the pipe and stop reading."""
        if self._closed:
            return
        self._closed = True

        with contextlib.suppress(Exception):
            self._write_file.close()

        # Give reader a moment to finish
        if self._reader_task:
            with contextlib.suppress(Exception):
                # Cancel the reader task since the write end is closed
                self._reader_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, asyncio.TimeoutError):
                    await asyncio.wait_for(self._reader_task, timeout=0.1)


class CapturingReadStream:
    """Wraps a read stream to capture all received messages."""

    def __init__(self, read_stream, capture: TrafficCapture):
        self._read_stream = read_stream
        self._capture = capture

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            msg = await self._read_stream.__anext__()
            self._capture.received.append(msg)
            return msg
        except StopAsyncIteration:
            raise

    # Delegate async context manager protocol
    async def __aenter__(self):
        if hasattr(self._read_stream, "__aenter__"):
            await self._read_stream.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if hasattr(self._read_stream, "__aexit__"):
            return await self._read_stream.__aexit__(exc_type, exc_val, exc_tb)
        return None

    # Delegate any other attributes to the underlying stream
    def __getattr__(self, name):
        return getattr(self._read_stream, name)


class CapturingWriteStream:
    """Wraps a write stream to capture all sent messages."""

    def __init__(self, write_stream, capture: TrafficCapture):
        self._write_stream = write_stream
        self._capture = capture

    async def send(self, msg):
        """Send a message and capture it."""
        self._capture.sent.append(msg)
        return await self._write_stream.send(msg)

    async def __call__(self, msg):
        """Also support callable interface for compatibility."""
        self._capture.sent.append(msg)
        if hasattr(self._write_stream, "send"):
            return await self._write_stream.send(msg)
        return await self._write_stream(msg)

    # Delegate async context manager protocol
    async def __aenter__(self):
        if hasattr(self._write_stream, "__aenter__"):
            await self._write_stream.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if hasattr(self._write_stream, "__aexit__"):
            return await self._write_stream.__aexit__(exc_type, exc_val, exc_tb)
        return None

    # Delegate any other attributes to the underlying stream
    def __getattr__(self, name):
        return getattr(self._write_stream, name)


@asynccontextmanager
async def capturing_client(client_cm, capture: TrafficCapture) -> AsyncIterator[tuple]:
    """Wrap a client context manager to capture all traffic."""
    async with client_cm as (read, write):
        yield CapturingReadStream(read, capture), CapturingWriteStream(write, capture)
