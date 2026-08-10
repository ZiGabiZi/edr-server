from fastapi import APIRouter, HTTPException
from app.schemas.heartbeat import HeartbeatRequest, HeartbeatDirective, HeartbeatResponse
from app.schemas.event import EventCreateRequest
from app.services.agent_service import record_heartbeat, HEARTBEAT_INTERVAL_SECONDS
from app.services.event_service import create_event, utc_now

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
        # Repornire detectată prin schimbarea incarnării raportate de agent
        # (agent_instance_id), nu prin regresia secvenței. Prinde inclusiv
        # terminările necurate — crash, kill, tampering — când agentul nu apucă
        # să trimită agent_shutdown.
        create_event(
            EventCreateRequest(
                agent_id=agent_id,
                event_type="agent_restart",
                agent_instance_id=result.instance_id,
                occurred_at=utc_now(),
                description=(
                    f"Agent restart detected server-side: new instance "
                    f"{result.instance_id} began at sequence {result.sequence}."
                ),
            )
        )

    if result.continuity_lost:
        # Lacună de acoperire, nu constatare de securitate: serverul spune explicit
        # că nu poate garanta continuitatea pentru acest agent. Deliberat NU e
        # agent_restart — nu avem dovada unei reporniri, iar un verdict inventat ar
        # fi un fals pozitiv într-un sistem al cărui rost e să nu producă așa ceva.
        create_event(
            EventCreateRequest(
                agent_id=agent_id,
                event_type="agent_continuity_lost",
                agent_instance_id=None,
                occurred_at=utc_now(),
                description=(
                    f"Heartbeat sequence regressed to {result.sequence} from an agent "
                    f"that does not report its process incarnation. A restart cannot "
                    f"be distinguished from a reordered packet; the sequence baseline "
                    f"was reset so continuity tracking can resume. Upgrade the agent "
                    f"to a build that sends agent_instance_id."
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
        failed_attempts=result.failed_attempts,
        silence_seconds=result.silence_seconds,
        continuity_lost=result.continuity_lost,
    )
