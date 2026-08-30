from fastapi import APIRouter, Depends, HTTPException

from app.schemas.event import EventCreateRequest
from app.security import authenticated_agent_id, require_identity_match
from app.services.event_service import create_event, get_all_events
from app.services.agent_service import agent_exists


router = APIRouter(
    prefix="/api/events",
    tags=["Events"]
)


@router.post("")
def receive_event(
    event: EventCreateRequest,
    caller_agent_id: str = Depends(authenticated_agent_id),
) -> dict:
    """
    Primește un eveniment de la un agent.

    Ordinea verificărilor e o decizie de securitate, nu una de stil:

        1. identitatea (dependency-ul de mai sus) — 401 dacă nu e recunoscută;
        2. potrivirea identității cu agent_id-ul din corp — 403;
        3. abia apoi existența agentului în registru — 404.

    Dacă 3 ar veni înaintea lui 2, un agent autentificat ar putea afla, din
    diferența dintre 404 și 200, care agent_id-uri există în parc — o rută de
    enumerare oferită tocmai celui care nu are voie să știe.
    """
    require_identity_match(caller_agent_id, event.agent_id)

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
    """
    Fluxul de evenimente al întregului parc, din rularea de măsurătoare CURENTĂ.

    Restrângerea la rulare nu îngustează ce se vedea înainte, o păstrează: până
    la persistență, depozitul conținea prin construcție doar evenimentele
    pornirii curente. Un implicit care ar întoarce tot istoricul ar schimba
    tăcut înțelesul rutei — vezi event_service.get_all_events.

    GAURĂ CUNOSCUTĂ, TRATATĂ SEPARAT: ruta nu cere nicio credențială — vezi
    nota de la GET /api/agents și AUTH.md. Aici miza e mai mare decât la
    inventar: evenimentele conțin căi de fișiere și hash-uri de conținut de pe
    endpoint-uri. Cheia unui agent NU deschide ruta asta, dar nici nu o închide
    pentru altcineva; separarea drepturilor de citire de cele de scriere e
    pasul următor declarat, nu unul făcut aici.
    """
    events = get_all_events()
    return {
        "count": len(events),
        "events": events
    }
