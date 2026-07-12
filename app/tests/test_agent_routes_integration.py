from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

import app.services.agent_service as svc
from app.main import app

client = TestClient(app)


def setup_function():
    svc.agents_store.clear()


def _register(
    agent_id: str = "agent-1",
    machine_id_type: str = "hash",
    machine_id_hash=...,
):
    if machine_id_hash is ...:
        machine_id_hash = f"hash-{agent_id}"
    return client.post(
        "/api/agents/register",
        json={
            "agent_id": agent_id,
            "hostname": "HOST1",
            "operating_system": "windows",
            "architecture": "x64",
            "os_architecture": "x64",
            "machine_id_type": machine_id_type,
            "machine_id_hash": machine_id_hash,
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


def test_heartbeat_response_includes_server_dictated_cadence():
    _register()

    response = client.post(
        "/api/agents/agent-1/heartbeat", json={"agent_id": "agent-1"}
    )
    body = response.json()

    assert body["next_heartbeat_seconds"] == svc.HEARTBEAT_INTERVAL_SECONDS
    assert body["next_heartbeat_seconds"] > 0


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


def test_reregister_with_same_machine_id_merges_onto_existing_record():
    _register("agent-1", "windows_machine_guid", "guid-hash")

    body = _register("agent-2", "windows_machine_guid", "guid-hash").json()

    assert body["agent"]["registration_status"] == "updated_by_machine_id"
    assert "agent-1" not in svc.agents_store
    assert list(svc.agents_store) == ["agent-2"]


def test_fallback_machine_id_type_still_participates_in_dedup():
    # regresie: allowlist-ul de tipuri "strong" excludea mac_address_fallback,
    # creand un agent duplicat la fiecare reinstalare pe astfel de masini
    _register("agent-1", "mac_address_fallback", "mac-hash")

    body = _register("agent-2", "mac_address_fallback", "mac-hash").json()

    assert body["agent"]["registration_status"] == "updated_by_machine_id"
    assert list(svc.agents_store) == ["agent-2"]


def test_same_hash_different_machine_id_type_is_not_merged():
    _register("agent-1", "windows_machine_guid", "shared-hash")

    body = _register("agent-2", "mac_address_fallback", "shared-hash").json()

    assert body["agent"]["registration_status"] == "created"
    assert set(svc.agents_store) == {"agent-1", "agent-2"}


def test_agents_without_machine_id_hash_do_not_collide():
    _register("agent-1", "unknown", None)

    body = _register("agent-2", "unknown", None).json()

    assert body["agent"]["registration_status"] == "created"
    assert set(svc.agents_store) == {"agent-1", "agent-2"}