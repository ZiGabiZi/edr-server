from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.schemas.agent import AgentRegisterRequest


agents_store: Dict[str, Dict[str, Any]] = {}
STALE_AFTER_S = 30
OFFLINE_AFTER_S = 90


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _model_to_dict(model: AgentRegisterRequest) -> Dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()

    return model.dict()


def find_agent_by_machine_id_hash(machine_id_hash: Optional[str]) -> Optional[Dict[str, Any]]:
    if not machine_id_hash:
        return None

    for agent in agents_store.values():
        if agent.get("machine_id_hash") == machine_id_hash:
            return agent

    return None

def record_heartbeat(agent_id: str) -> Optional[Dict[str, Any]]:
    """
    Actualizează last_seen pentru agentul dat.
    Returnează None dacă agentul nu există (agent neînregistrat).
    """
    agent = agents_store.get(agent_id)
    if agent is None:
        return None

    agent["last_seen"] = _utc_now()
    return agent


def register_agent(agent_request: AgentRegisterRequest) -> Dict[str, Any]:
    agent_data = _model_to_dict(agent_request)
    now = _utc_now()

    agent_data["status"] = "registered"
    agent_id = agent_data["agent_id"]

    existing_agent_by_id = agents_store.get(agent_id)

    if existing_agent_by_id:
        created_at = existing_agent_by_id.get("created_at", now)

        existing_agent_by_id.update(agent_data)
        existing_agent_by_id["created_at"] = created_at
        existing_agent_by_id["last_seen"] = now
        existing_agent_by_id["registration_status"] = "updated_by_agent_id"

        return existing_agent_by_id

    existing_agent_by_machine_id = find_agent_by_machine_id_hash(
        agent_data.get("machine_id_hash")
    )

    if existing_agent_by_machine_id:
        old_agent_id = existing_agent_by_machine_id["agent_id"]
        created_at = existing_agent_by_machine_id.get("created_at", now)

        updated_agent = existing_agent_by_machine_id.copy()
        updated_agent.update(agent_data)
        updated_agent["created_at"] = created_at
        updated_agent["last_seen"] = now
        updated_agent["registration_status"] = "updated_by_machine_id"

        if old_agent_id != agent_id:
            agents_store.pop(old_agent_id, None)

        agents_store[agent_id] = updated_agent

        return updated_agent

    agent_data["created_at"] = now
    agent_data["last_seen"] = now
    agent_data["registration_status"] = "created"

    agents_store[agent_id] = agent_data

    return agent_data

def _derive_status(agent: Dict[str, Any]) -> str:
    last_seen_raw = agent.get("last_seen")
    if not last_seen_raw:
        return "unknown"

    last_seen = datetime.fromisoformat(last_seen_raw)
    age_seconds = (datetime.now(timezone.utc) - last_seen).total_seconds()

    if age_seconds < STALE_AFTER_S:
        return "online"
    if age_seconds < OFFLINE_AFTER_S:
        return "degraded"
    return "offline"


def get_agents() -> List[Dict[str, Any]]:
    result = []
    for agent in agents_store.values():
        agent_view = agent.copy()
        agent_view["status"] = _derive_status(agent_view)
        result.append(agent_view)
    return result


def agent_exists(agent_id: str) -> bool:
    return agent_id in agents_store
