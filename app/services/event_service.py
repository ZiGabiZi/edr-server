from datetime import datetime, timezone
from itertools import count
from threading import Lock
from typing import List, Dict, Optional
from app.schemas.event import EventCreateRequest
from app.services import measurement_run

events_store: List[dict] = []
events_lock = Lock()
_event_id_counter = count(1)
_events_by_client_id: Dict[str, dict] = {}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def find_event_by_client_id(client_event_id: str) -> Optional[dict]:
    with events_lock:
        return _events_by_client_id.get(client_event_id)

def create_event(event: EventCreateRequest) -> dict:
    """
    Înregistrează un eveniment primit de la un agent.

    Eticheta rulării se citește AICI, la ingestie, nu la interogarea metricii.
    Un eveniment aparține experimentului în care a sosit; dacă eticheta s-ar
    aplica la citire, toate evenimentele din depozit ar migra spre rularea
    curentă la fiecare schimbare de etichetă, iar experimentele vechi s-ar goli
    pe măsură ce se fac altele noi.

    Un duplicat după `client_event_id` PĂSTREAZĂ rularea primei sosiri și nu
    primește eticheta curentă. Retransmisia e a aceluiași eveniment (§1.3, coada
    e at-least-once), deci o rulare deschisă între cele două plecări n-a
    observat nimic nou — a doua sosire nu are ce adăuga în ea.
    """
    new_event = {
        "agent_id": event.agent_id,
        "agent_instance_id": event.agent_instance_id,
        "event_type": event.event_type,
        "client_event_id": event.client_event_id,
        "file_path": event.file_path,
        "sha256": event.sha256,
        "hash_status": event.hash_status,
        "file_size": event.file_size,
        "measurements": event.measurements.model_dump() if event.measurements else None,
        "disclosure": event.disclosure.model_dump() if event.disclosure else None,
        "description": event.description,
        "occurred_at": event.occurred_at,
        "received_at": utc_now(),
        "run_id": measurement_run.current_run_id(),
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
