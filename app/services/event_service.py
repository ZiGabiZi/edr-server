from itertools import count
from threading import Lock
from typing import List, Dict, Optional
from app.schemas.event import EventCreateRequest

events_store: List[dict] = []
events_lock = Lock()
_event_id_counter = count(1)
_events_by_client_id: Dict[str, dict] = {}


def find_event_by_client_id(client_event_id: str) -> Optional[dict]:
    with events_lock:
        return _events_by_client_id.get(client_event_id)

def create_event(event: EventCreateRequest) -> dict:
    new_event = {
        "agent_id": event.agent_id,
        "event_type": event.event_type,
        "client_event_id": event.client_event_id,
        "file_path": event.file_path,
        "sha256": event.sha256,
        "description": event.description,
        "status": "received",
    }

    with events_lock:
        if event.client_event_id:
            existing_event = _events_by_client_id.get(event.client_event_id)
            if existing_event:
                return existing_event
            
        new_event["event_id"] = next(_event_id_counter)
        events_store.append(new_event)

        if event.client_event_id:
            _events_by_client_id[event.client_event_id] = new_event

    return new_event


def get_all_events() -> List[dict]:
    with events_lock:
        return list(events_store).copy()
