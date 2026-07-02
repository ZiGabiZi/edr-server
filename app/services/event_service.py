from itertools import count
from threading import Lock
from typing import List
from app.schemas.event import EventCreateRequest

events_store: List[dict] = []
events_lock = Lock()
_event_id_counter = count(1)


def create_event(event: EventCreateRequest) -> dict:
    new_event = {
        "agent_id": event.agent_id,
        "event_type": event.event_type,
        "file_path": event.file_path,
        "sha256": event.sha256,
        "description": event.description,
        "status": "received",
    }

    with events_lock:
        new_event["event_id"] = next(_event_id_counter)
        events_store.append(new_event)

    return new_event


def get_all_events() -> List[dict]:
    with events_lock:
        return list(events_store).copy()
