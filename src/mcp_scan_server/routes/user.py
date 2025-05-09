from fastapi import APIRouter

router = APIRouter()


@router.get("/identity")
async def identity():
    """Get the identity of the user. For now, this is a dummy response."""
    return {"username": "user"}
