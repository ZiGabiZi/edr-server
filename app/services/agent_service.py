from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from threading import Lock  # <-- IMPORT NOU

from app.schemas.agent import AgentRegisterRequest

agents_store: Dict[str, Dict[str, Any]] = {}
agents_lock = Lock()

STALE_AFTER_S = 30
OFFLINE_AFTER_S = 90

# Cadența de heartbeat pe care serverul o dictează agenților. Centralizată aici
# (nu în agent) astfel încât operatorul poate schimba ritmul întregului parc de
# agenți dintr-un singur loc, fără a redistribui configurație pe fiecare endpoint.
HEARTBEAT_INTERVAL_SECONDS = 10


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _model_to_dict(model: AgentRegisterRequest) -> Dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


@dataclass
class HeartbeatResult:
    """
    Rezultatul procesării unui heartbeat.

    Pe lângă snapshot-ul agentului (sau None dacă agentul nu e înregistrat),
    poartă verdictul de continuitate derivat din contorul de secvență:
        - restart_detected: contorul agentului a scăzut/resetat => proces repornit.
        - missed_heartbeats: câte heartbeat-uri au lipsit în golul de secvență curent.
    """
    agent: Optional[Dict[str, Any]]
    restart_detected: bool = False
    missed_heartbeats: int = 0
    sequence: Optional[int] = None


def record_heartbeat(
    agent_id: str,
    sequence: Optional[int] = None,
) -> HeartbeatResult:
    """
    Actualizează last_seen pentru agentul dat în mod atomic și, dacă heartbeat-ul
    poartă un contor de secvență, evaluează continuitatea față de ultima secvență
    cunoscută pentru acel agent.

    Semantica secvenței (contor monoton per proces al agentului, resetat la fiecare
    pornire a procesului):
        - sequence None            -> agent legacy, fără detecție (doar last_seen).
        - prima secvență observată -> stabilim baseline, fără verdict (n-avem cu ce compara).
        - sequence <= last_sequence -> contorul a regresat/resetat => RESTART de agent.
        - sequence  > last+1        -> gol în secvență => (sequence - last - 1) heartbeat-uri pierdute.
        - sequence == last+1        -> continuitate normală.

    Contoarele cumulative restart_count / missed_heartbeats_total sunt persistate pe
    înregistrarea agentului pentru observabilitate.
    """
    with agents_lock:
        agent = agents_store.get(agent_id)
        if agent is None:
            return HeartbeatResult(agent=None)

        agent["last_seen"] = _utc_now()

        restart_detected = False
        missed = 0

        if sequence is not None:
            last_sequence = agent.get("last_sequence")

            if last_sequence is None:
                # Prima secvență observată pentru acest agent: doar baseline.
                pass
            elif sequence <= last_sequence:
                # Contorul agentului a scăzut/resetat -> procesul a repornit.
                restart_detected = True
                agent["restart_count"] = agent.get("restart_count", 0) + 1
            elif sequence > last_sequence + 1:
                # Gol în secvență -> heartbeat-uri pierdute între două primiri.
                missed = sequence - last_sequence - 1
                agent["missed_heartbeats_total"] = (
                    agent.get("missed_heartbeats_total", 0) + missed
                )

            agent["last_sequence"] = sequence

        return HeartbeatResult(
            agent=agent.copy(),
            restart_detected=restart_detected,
            missed_heartbeats=missed,
            sequence=sequence,
        )


def register_agent(agent_request: AgentRegisterRequest) -> Dict[str, Any]:
    agent_data = _model_to_dict(agent_request)
    now = _utc_now()

    agent_data["status"] = "registered"
    agent_id = agent_data["agent_id"]

    with agents_lock:
        existing_agent_by_id = agents_store.get(agent_id)

        if existing_agent_by_id:
            created_at = existing_agent_by_id.get("created_at", now)

            existing_agent_by_id.update(agent_data)
            existing_agent_by_id["created_at"] = created_at
            existing_agent_by_id["last_seen"] = now
            existing_agent_by_id["registration_status"] = "updated_by_agent_id"

            return existing_agent_by_id.copy()

        existing_agent_by_machine_id = None
        for agent in agents_store.values():
            if agent.get("machine_id_hash") == agent_data.get("machine_id_hash"):
                existing_agent_by_machine_id = agent
                break

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
            return updated_agent.copy()

        agent_data["created_at"] = now
        agent_data["last_seen"] = now
        agent_data["registration_status"] = "created"

        agents_store[agent_id] = agent_data
        return agent_data.copy()


def _derive_status(agent: Dict[str, Any]) -> str:
    last_seen_raw = agent.get("last_seen")
    if not last_seen_raw:
        return "unknown"

    try:
        last_seen = datetime.fromisoformat(last_seen_raw)
        
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
            
        age_seconds = (datetime.now(timezone.utc) - last_seen).total_seconds()
        
    except (ValueError, TypeError):
        return "unknown"

    if age_seconds < STALE_AFTER_S:
        return "online"
    if age_seconds < OFFLINE_AFTER_S:
        return "degraded"
    return "offline"


def get_agents() -> List[Dict[str, Any]]:
    result = []
    with agents_lock:
        agents_snapshot = list(agents_store.values())
        

        for agent in agents_snapshot:
            agent_view = agent.copy()
            agent_view["status"] = _derive_status(agent_view)
            result.append(agent_view)
            
        return result


def agent_exists(agent_id: str) -> bool:
    with agents_lock:
        return agent_id in agents_store