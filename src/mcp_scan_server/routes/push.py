import json
import uuid

from fastapi import APIRouter, Request
from invariant_sdk.types.push_traces import PushTracesResponse

from ..record_file import push_session_to_record_file
from ..session_store import SessionStore

router = APIRouter()

session_store = SessionStore()


@router.post("/trace")
async def push_trace(request: Request) -> PushTracesResponse:
    """Push a trace. For now, this is a dummy response."""

    request_data = await request.body()
    request_data = json.loads(request_data)
    mcp_client = request_data.get("metadata")[0].get("client")
    session = session_store[mcp_client]

    record_file = request.app.state.record_file

    # Push the session to the record file if it exists
    if trace_id := await push_session_to_record_file(session, record_file, mcp_client):
        return PushTracesResponse(id=[trace_id], success=True)
    else:
        return PushTracesResponse(id=[str(uuid.uuid4())], success=False)
