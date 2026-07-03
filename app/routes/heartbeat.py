from fastapi import APIRouter, HTTPException
from app.schemas.heartbeat import HeartbeatRequest, HeartbeatDirective, HeartbeatResponse
from app.services.agent_service import record_heartbeat, HEARTBEAT_INTERVAL_SECONDS

router = APIRouter(prefix="/api/agents", tags=["Heartbeat"])

@router.post("/{agent_id}/heartbeat")
def receive_heartbeat(agent_id: str, body: HeartbeatRequest) -> HeartbeatResponse:
    if agent_id != body.agent_id:
        raise HTTPException(status_code=400, detail="agent_id mismatch")

    agent = record_heartbeat(agent_id)

    if agent is None:
        # Agentul a pierdut înregistrarea (ex: server restartat, store șters).
        # Îi spunem să se re-înregistreze — fără să-l blocăm brutal.
        return HeartbeatResponse(
            status="unregistered",
            agent_id=agent_id,
            directive=HeartbeatDirective(action="reregister"),
            next_heartbeat_seconds=HEARTBEAT_INTERVAL_SECONDS,
        )

    return HeartbeatResponse(
        status="ok",
        agent_id=agent_id,
        directive=HeartbeatDirective(action="none"),
        next_heartbeat_seconds=HEARTBEAT_INTERVAL_SECONDS,
    )
