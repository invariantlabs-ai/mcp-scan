from fastapi import APIRouter, Request, Depends
from typing import Annotated

from mcp_scan_server.activity_logger import ActivityLogger, get_activity_logger 

router = APIRouter()


@router.post("/{trace_id}/messages")
async def append_messages(trace_id: str, request: Request, activity_logger: Annotated[ActivityLogger, Depends(get_activity_logger)]):
    """Append messages to a trace. For now this is a dummy response."""

    body = await request.json()
    messages = body.get("messages", [])

    await activity_logger.handle_append(trace_id, messages)

    return {"success": True}
