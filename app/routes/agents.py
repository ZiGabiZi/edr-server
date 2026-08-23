from typing import Optional

from fastapi import APIRouter, Header, HTTPException

from app.schemas.agent import AgentRegisterRequest
from app.security import authorize_registration
from app.services import auth_service
from app.services.agent_service import AgentIdConflictError, get_agents, register_agent

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
