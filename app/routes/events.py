from fastapi import APIRouter, HTTPException

from app.schemas.event import EventCreateRequest
from app.services.event_service import create_event, get_all_events
from app.services.agent_service import agent_exists


router = APIRouter(
    prefix="/api/events",
    tags=["Events"]
)


@router.post("")
def receive_event(event: EventCreateRequest) -> dict:
    if not agent_exists(event.agent_id):
        raise HTTPException(
            status_code=404,
            detail=f"Agent '{event.agent_id}' is not registered"
        )

    created_event = create_event(event)

    return {
        "message": "Event received successfully",
        "event": created_event,
        "next_action": "none"
    }


@router.get("")
def list_events() -> dict:
    events = get_all_events()
    return {
        "count": len(events),
        "events": events
    }
