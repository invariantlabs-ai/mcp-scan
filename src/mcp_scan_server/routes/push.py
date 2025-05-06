import uuid
import rich
import json

from fastapi import APIRouter, Request, Depends
from typing import Annotated
from invariant_sdk.types.push_traces import PushTracesResponse

from mcp_scan_server.activity_logger import ActivityLogger, get_activity_logger

router = APIRouter()

@router.post("/trace")
async def push_trace(request: Request, activity_logger: Annotated[ActivityLogger, Depends(get_activity_logger)]) -> PushTracesResponse:
    """Push a trace. For now, this is a dummy response."""
    body = await request.json()
    metadata = body.get("metadata", [{}])
    messages = body.get("messages", [[]])

    # trace_id = await activity_logger.handle_push(messages, metadata)
    trace_id = str(uuid.uuid4())

    # return the trace ID
    return PushTracesResponse(id=[trace_id], success=True)
