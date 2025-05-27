import json

from fastapi import APIRouter, Request

from ..record_file import append_messages_to_record_file
from ..session_store import SessionStore

router = APIRouter()


session_store = SessionStore()


@router.post("/{trace_id}/messages")
async def append_messages(trace_id: str, request: Request):
    """Append messages to a trace. For now this is a dummy response."""

    request_data = await request.body()
    request_data = json.loads(request_data)

    # If we are calling append, we should already have set the trace_id
    if request.app.state.record_file:
        await append_messages_to_record_file(
            trace_id,
            request.app.state.record_file,
            annotations=request_data.get("annotations"),
        )

    return {"success": True}
