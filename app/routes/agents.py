from fastapi import APIRouter, HTTPException

from app.schemas.agent import AgentRegisterRequest
from app.services.agent_service import AgentIdConflictError, get_agents, register_agent
router = APIRouter(
    prefix="/api/agents",
    tags=["Agents"],
)


@router.post("/register")
def register_new_agent(agent: AgentRegisterRequest) -> dict:
    try:
        stored_agent = register_agent(agent)
    except AgentIdConflictError:
        raise HTTPException(
            status_code=409,
            detail="agent_id already registered to a different machine",
        )

    return {
        "message": "Agent registered successfully",
        "agent": stored_agent,
    }


@router.get("")
def list_agents() -> dict:
    agents = get_agents()

    return {
        "count": len(agents),
        "agents": agents,
    }
