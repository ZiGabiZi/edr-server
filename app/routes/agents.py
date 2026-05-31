from fastapi import APIRouter

from app.schemas.agent import AgentRegisterRequest
from app.services.agent_service import get_all_agents, register_agent

router = APIRouter(
    prefix="/api/agents",
    tags=["Agents"],
)


@router.post("/register")
def register_new_agent(agent: AgentRegisterRequest) -> dict:
    registered_agent = register_agent(agent)

    return {
        "message": "Agent registered successfully",
        "agent": registered_agent,
    }


@router.get("")
def list_agents() -> dict:
    agents = get_all_agents()

    return {
        "count": len(agents),
        "agents": agents,
    }
