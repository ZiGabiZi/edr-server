from typing import Dict, List

from app.schemas.agent import AgentRegisterRequest

agents_store: Dict[str, dict] = {}


def register_agent(agent: AgentRegisterRequest) -> dict:
    agents_store[agent.agent_id] = {
        "agent_id": agent.agent_id,
        "hostname": agent.hostname,
        "operating_system": agent.operating_system,
        "ip_address": agent.ip_address,
        "status": "registered",
    }

    return agents_store[agent.agent_id]


def get_all_agents() -> List[dict]:
    return list(agents_store.values())


def agent_exists(agent_id: str) -> bool:
    return agent_id in agents_store
