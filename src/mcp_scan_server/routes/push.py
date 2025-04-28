import uuid

from fastapi import APIRouter
from invariant_sdk.types.push_traces import PushTracesResponse

router = APIRouter()


@router.post("/trace")
async def push_trace():
    """
    Push a trace. For now, this is a dummy response.
    """
    return PushTracesResponse(id=[str(uuid.uuid4())], success=True)
    
