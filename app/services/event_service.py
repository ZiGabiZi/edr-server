from typing import List
from app.schemas.event import EventCreateRequest

events_store: List[dict] = []


def create_event(event: EventCreateRequest) -> dict:
    event_id = len(events_store) + 1

    new_event = {
        "event_id": event_id,
        "agent_id": event.agent_id,
        "event_type": event.event_type,
        "file_path": event.file_path,
        "sha256": event.sha256,
        "description": event.description,
        "status": "received",
    }

    events_store.append(new_event)

    return new_event


def get_all_events() -> List[dict]:
    return events_store
