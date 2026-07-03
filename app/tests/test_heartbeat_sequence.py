"""
Teste pentru detecția server-side de heartbeat-uri pierdute și reporniri de agent,
derivată din contorul de secvență trimis de agent în fiecare heartbeat.
"""
from fastapi.testclient import TestClient

import app.services.agent_service as agent_svc
import app.services.event_service as event_svc
from app.main import app

client = TestClient(app)


def setup_function():
    agent_svc.agents_store.clear()
    event_svc.events_store.clear()


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


def _heartbeat(agent_id: str, sequence=None):
    payload = {"agent_id": agent_id}
    if sequence is not None:
        payload["sequence"] = sequence
    return client.post(f"/api/agents/{agent_id}/heartbeat", json=payload)


def _restart_events():
    return [
        e for e in event_svc.get_all_events() if e["event_type"] == "agent_restart"
    ]


def test_first_sequence_sets_baseline_without_restart():
    _register()

    body = _heartbeat("agent-1", sequence=1).json()

    assert body["restart_detected"] is False
    assert body["missed_heartbeats"] == 0
    assert _restart_events() == []


def test_monotonic_sequence_is_normal():
    _register()
    _heartbeat("agent-1", sequence=1)

    body = _heartbeat("agent-1", sequence=2).json()

    assert body["restart_detected"] is False
    assert body["missed_heartbeats"] == 0
    assert _restart_events() == []


def test_sequence_gap_counts_missed_heartbeats():
    _register()
    _heartbeat("agent-1", sequence=1)

    # sarim peste 2, 3, 4 -> 3 heartbeat-uri pierdute
    body = _heartbeat("agent-1", sequence=5).json()

    assert body["missed_heartbeats"] == 3
    assert body["restart_detected"] is False
    assert agent_svc.agents_store["agent-1"]["missed_heartbeats_total"] == 3
    # gap-ul nu e un restart -> niciun eveniment agent_restart
    assert _restart_events() == []


def test_sequence_reset_is_detected_as_restart_and_emits_event():
    _register()
    _heartbeat("agent-1", sequence=1)
    _heartbeat("agent-1", sequence=2)
    _heartbeat("agent-1", sequence=3)

    # procesul agentului repornește -> contorul revine la 1
    body = _heartbeat("agent-1", sequence=1).json()

    assert body["restart_detected"] is True

    restart_events = _restart_events()
    assert len(restart_events) == 1
    assert restart_events[0]["agent_id"] == "agent-1"
    assert agent_svc.agents_store["agent-1"]["restart_count"] == 1


def test_equal_sequence_is_treated_as_restart():
    # nu strict crescător (replay/reset la aceeași valoare) -> tratat ca restart
    _register()
    _heartbeat("agent-1", sequence=7)

    body = _heartbeat("agent-1", sequence=7).json()

    assert body["restart_detected"] is True
    assert len(_restart_events()) == 1


def test_baseline_resets_after_restart_so_next_beat_is_normal():
    _register()
    _heartbeat("agent-1", sequence=5)
    _heartbeat("agent-1", sequence=1)  # restart -> baseline devine 1

    body = _heartbeat("agent-1", sequence=2).json()

    assert body["restart_detected"] is False
    # un singur eveniment de restart, nu se re-emite pentru heartbeat-ul normal următor
    assert len(_restart_events()) == 1


def test_legacy_heartbeat_without_sequence_is_backward_compatible():
    _register()

    body = _heartbeat("agent-1").json()  # fără sequence

    assert body["status"] == "ok"
    assert body["restart_detected"] is False
    assert body["missed_heartbeats"] == 0
    assert "last_sequence" not in agent_svc.agents_store["agent-1"]
    assert _restart_events() == []
