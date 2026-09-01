from fastapi import APIRouter, Depends, HTTPException

from app.schemas.event import EventCreateRequest, EventCreateResponse
from app.routes.scope import RunScope, RunScopeDependency
from app.security import authenticated_agent_id, require_identity_match
from app.services.event_service import (
    create_event,
    get_all_events,
    get_events_of_all_runs,
)
from app.services.agent_service import agent_exists


router = APIRouter(
    prefix="/api/events",
    tags=["Events"]
)


@router.post("")
def receive_event(
    event: EventCreateRequest,
    caller_agent_id: str = Depends(authenticated_agent_id),
) -> EventCreateResponse:
    """
    Primește un eveniment de la un agent.

    Tipul de retur nu e adnotare de politețe: e modelul declarat de contract
    (`event_create_response`, contract_version 6), iar FastAPI îl folosește ca
    `response_model`. Până la el, ruta întorcea un dicționar construit aici, deci
    direcția descendentă a rutei nu era descrisă de niciun contract și nu era
    verificată de niciun test — singura direcție rămasă așa, exact înaintea
    pasului care pune pe ea dispoziția de treaptă (P2.3).

    Adoptarea modelului nu schimbă niciun octet de pe fir: câmpurile lui repetă
    cheile și ordinea dicționarului de dinainte. Un model de răspuns FILTREAZĂ
    însă ce nu declară, deci un câmp stocat și nedeclarat ar dispărea tăcut —
    păzit de test_event_response_declares_every_stored_field.

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

    # `next_action` rămâne "none": e o DIRECTIVĂ, iar directivele aparțin benzii
    # de incertitudine și canalului de heartbeat. Dispoziția de treaptă care vine
    # la P2.3 spune ce se ȘTIE, nu ce trebuie făcut, și nu are voie să ajungă
    # aici — două mecanisme de decizie în același răspuns se contrazic pe tăcute.
    return EventCreateResponse(
        message="Event received successfully",
        event=created_event,
        next_action="none",
    )


@router.get("")
def list_events(scope: RunScope = RunScopeDependency) -> dict:
    """
    Fluxul de evenimente al întregului parc, dintr-o rulare de măsurătoare.

    Implicit, rularea CURENTĂ. Restrângerea nu îngustează ce se vedea înainte, o
    păstrează: până la persistență, depozitul conținea prin construcție doar
    evenimentele pornirii curente. Un implicit care ar întoarce tot istoricul ar
    schimba tăcut înțelesul rutei.

    `run_id` cere altă rulare, `all_runs=true` cere agregatul peste toate.
    Răspunsul poartă întotdeauna rularea pe care o descrie, ca nimeni să nu
    citească un flux crezând că e al altui experiment.

    GAURĂ CUNOSCUTĂ, TRATATĂ SEPARAT: ruta nu cere nicio credențială — vezi
    nota de la GET /api/agents și AUTH.md. Aici miza e mai mare decât la
    inventar: evenimentele conțin căi de fișiere și hash-uri de conținut de pe
    endpoint-uri. Cheia unui agent NU deschide ruta asta, dar nici nu o închide
    pentru altcineva; separarea drepturilor de citire de cele de scriere e
    pasul următor declarat, nu unul făcut aici.
    """
    events = (
        get_events_of_all_runs()
        if scope.covers_all_runs
        else get_all_events(scope.run_id)
    )

    return {
        "run": scope.declaration(),
        "count": len(events),
        "events": events,
    }
