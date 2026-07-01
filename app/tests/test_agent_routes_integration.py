from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

import app.services.agent_service as svc
from app.main import app

client = TestClient(app)


def setup_function():
    svc.agents_store.clear()


def _register(agent_id: str = "agent-1"):
    return client.post(
        "/api/agents/register",
        json={
            "agent_id": agent_id,
            "hostname": "HOST1",
            "operating_system": "windows",
            "architecture": "x64",
            "os_architecture": "x64",
            "machine_id_type": "hash",
            "machine_id_hash": f"hash-{agent_id}",
        },
    )


def _backdate_last_seen(agent_id: str, seconds_ago: float):
    svc.agents_store[agent_id]["last_seen"] = (
        datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)
    ).isoformat()


def test_fresh_agent_is_online():
    _register()

    response = client.get("/api/agents")

    assert response.json()["agents"][0]["status"] == "online"


def test_stale_agent_becomes_offline_without_new_heartbeat():
    _register()
    _backdate_last_seen("agent-1", seconds_ago=200)

    response = client.get("/api/agents")

    # regresie directa pentru bug-ul original: inainte de fix, aici ar fi aparut "active"
    assert response.json()["agents"][0]["status"] == "offline"


def test_stale_agent_is_degraded_between_thresholds():
    _register()
    _backdate_last_seen("agent-1", seconds_ago=45)

    response = client.get("/api/agents")

    assert response.json()["agents"][0]["status"] == "degraded"


def test_heartbeat_revives_offline_agent():
    _register()
    _backdate_last_seen("agent-1", seconds_ago=200)

    client.post("/api/agents/agent-1/heartbeat", json={"agent_id": "agent-1"})
    response = client.get("/api/agents")

    assert response.json()["agents"][0]["status"] == "online"


def test_heartbeat_for_unknown_agent_requests_reregister():
    response = client.post("/api/agents/ghost/heartbeat", json={"agent_id": "ghost"})
    body = response.json()

    assert body["status"] == "unregistered"
    assert body["directive"]["action"] == "reregister"


def test_heartbeat_agent_id_mismatch_is_rejected():
    _register()

    response = client.post(
        "/api/agents/agent-1/heartbeat", json={"agent_id": "other-id"}
    )

    assert response.status_code == 400


def test_internal_store_status_is_not_overwritten_by_derived_view():
    _register()

    client.get("/api/agents")

    # get_agents() trebuie sa lucreze pe .copy(), nu pe referinta din store
    assert svc.agents_store["agent-1"]["status"] == "registered"