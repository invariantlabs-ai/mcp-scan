from fastapi import APIRouter, Request

router = APIRouter()


@router.post("/{trace_id}/messages")
async def append_messages(request: Request):
    """
    Append messages to a trace. For now this is a NoOp.
    """
    return {"success": True}
