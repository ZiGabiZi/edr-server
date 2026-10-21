from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException

from app.routes.scope import RunScope, RunScopeDependency
from app.schemas.agent import AgentRegisterRequest
from app.security import authorize_registration, require_operator_secret
from app.services import auth_service
from app.services.agent_service import (
    AgentIdConflictError,
    get_agents,
    get_agents_monitoring,
    register_agent,
)
from app.services.event_service import (
    MONITORING_CHANGED_EVENT_TYPE,
    get_all_events,
    get_events_of_all_runs,
)

router = APIRouter(
    prefix="/api/agents",
    tags=["Agents"],
)


@router.post("/register")
def register_new_agent(
    agent: AgentRegisterRequest,
    x_enrollment_secret: Optional[str] = Header(default=None),
    x_agent_key: Optional[str] = Header(default=None),
) -> dict:
    """
    Înrolează sau re-înregistrează un agent.

    Autorizarea se face ÎNAINTE de orice atingere a store-ului: altfel un apelant
    neautentificat ar putea încă muta identități de mașină între agent_id-uri
    prin logica de deduplicare din register_agent(), fără să apuce să treacă de
    verificarea de credențiale.

    Cheia se emite abia DUPĂ ce înregistrarea a reușit. Emisă înainte, un
    conflict de machine_id (409) ar fi lăsat în urmă o credențială validă pentru
    un agent care nu există în registru.
    """
    authorization = authorize_registration(
        agent.agent_id, x_enrollment_secret, x_agent_key
    )

    try:
        stored_agent = register_agent(agent)
    except AgentIdConflictError:
        raise HTTPException(
            status_code=409,
            detail="agent_id already registered to a different machine",
        )

    response = {
        "message": "Agent registered successfully",
        "agent": stored_agent,
    }

    if authorization.issues_key:
        # Singurul moment din viața cheii în care valoarea în clar există.
        # Serverul păstrează doar amprenta, deci răspunsul ăsta nu poate fi
        # reconstituit mai târziu, din nicio rută.
        response["agent_key"] = auth_service.issue_agent_key(agent.agent_id)
        response["agent_key_header"] = auth_service.AGENT_KEY_HEADER

    return response


@router.get("")
def list_agents() -> dict:
    """
    Inventarul parcului.

    GAURĂ CUNOSCUTĂ, TRATATĂ SEPARAT: ruta nu cere nicio credențială. E o rută
    de citire, destinată analistului, iar analistul nu are încă un secret
    propriu — decizie luată explicit la închiderea proiectării Etapei 0. Până
    atunci, oricine poate ajunge la port poate enumera parcul: hostname-uri,
    versiuni de agent, amprente de mașină, contoare de repornire.

    Ce NU divulgă, prin construcție: nicio cheie de agent. Cheile se țin în
    app/services/auth_service.py, într-un depozit separat de agents_store, exact
    ca gaura asta să rămână o problemă de confidențialitate a inventarului, nu
    una de divulgare a credențialelor. Vezi AUTH.md.
    """
    agents = get_agents()

    return {
        "count": len(agents),
        "agents": agents,
    }


@router.get("/monitoring")
def list_agents_monitoring(
    scope: RunScope = RunScopeDependency,
    _: None = Depends(require_operator_secret),
) -> dict:
    """
    Care endpoint-uri sunt supravegheate acum și ce tranziții a avut rularea.

    De ce cere secretul de operator, când GET /api/agents nu cere nimic:
        Inventarul public spune ce mașini există. Ruta asta spune care dintre
        ele sunt oarbe — o hartă de țintire, nu un inventar. Gaura de citire
        publică e declarată (edr-server#9), dar n-are voie să crească cu
        informația cea mai utilă unui atacator. Secretul de înrolare e aceeași
        reutilizare declarată ca la POST /api/runs/{label}; secretul de analist
        o înlocuiește odată cu închiderea celorlalte rute de citire.

    De ce și tranzițiile, nu doar starea curentă:
        Registrul de agenți e volatil (METRICS.md §9.5). Pentru o rulare deja
        încheiată, starea curentă nu mai spune nimic; evenimentele persistate,
        cu eticheta rulării, spun ce endpoint a fost orb și când.

    Ce NU garantează: un "active" e afirmația agentului. Prinde defecte, nu
    sabotaj — vezi contracts/METRICS.md §8.
    """
    events = (
        get_events_of_all_runs()
        if scope.covers_all_runs
        else get_all_events(scope.run_id)
    )
    transitions = [
        {
            "agent_id": event["agent_id"],
            "agent_instance_id": event["agent_instance_id"],
            "occurred_at": event["occurred_at"],
            "description": event["description"],
            "run_id": event["run_id"],
        }
        for event in events
        if event["event_type"] == MONITORING_CHANGED_EVENT_TYPE
    ]

    return {
        "run": scope.declaration(),
        "agents": get_agents_monitoring(),
        "transitions": transitions,
    }
