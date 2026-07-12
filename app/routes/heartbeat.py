from fastapi import APIRouter, HTTPException
from app.schemas.heartbeat import HeartbeatRequest, HeartbeatDirective, HeartbeatResponse
from app.schemas.event import EventCreateRequest
from app.services.agent_service import record_heartbeat, HEARTBEAT_INTERVAL_SECONDS
from app.services.event_service import create_event

router = APIRouter(prefix="/api/agents", tags=["Heartbeat"])

@router.post("/{agent_id}/heartbeat")
def receive_heartbeat(agent_id: str, body: HeartbeatRequest) -> HeartbeatResponse:
    if agent_id != body.agent_id:
        raise HTTPException(status_code=400, detail="agent_id mismatch")

    result = record_heartbeat(agent_id, body.sequence, body.agent_instance_id)

    if result.agent is None:
        # Agentul a pierdut înregistrarea (ex: server restartat, store șters).
        # Îi spunem să se re-înregistreze — fără să-l blocăm brutal.
        return HeartbeatResponse(
            status="unregistered",
            agent_id=agent_id,
            directive=HeartbeatDirective(action="reregister"),
            next_heartbeat_seconds=HEARTBEAT_INTERVAL_SECONDS,
        )

    if result.restart_detected:
        # Restart detectat pur server-side, din regresia contorului de secvență —
        # independent de ce raportează agentul. Acesta e evenimentul agent_restart
        # legitim: prinde reporniri (crash, kill, tampering) chiar și când agentul
        # nu apucă să trimită un shutdown controlat.
        create_event(
            EventCreateRequest(
                agent_id=agent_id,
                event_type="agent_restart",
                description=(
                    f"Agent restart detected server-side: new instance "
                    f"{result.instance_id} began at sequence {result.sequence}."
                ),
            )
        )

    return HeartbeatResponse(
        status="ok",
        agent_id=agent_id,
        directive=HeartbeatDirective(action="none"),
        next_heartbeat_seconds=HEARTBEAT_INTERVAL_SECONDS,
        restart_detected=result.restart_detected,
        missed_heartbeats=result.missed_heartbeats,
    )
