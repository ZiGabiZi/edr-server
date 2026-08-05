"""
Teste pentru detecția server-side de heartbeat-uri pierdute și reporniri de agent:
pierderile sunt derivate din contorul de secvență, iar repornirile din agent_instance_id
(incarnarea procesului), ambele trimise de agent în fiecare heartbeat.
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


def _heartbeat(agent_id: str, sequence=None, instance_id="inst-A"):
    payload = {"agent_id": agent_id}
    if sequence is not None:
        payload["sequence"] = sequence
    if instance_id is not None:
        payload["agent_instance_id"] = instance_id
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


def test_equal_sequence_same_instance_is_duplicate_not_restart():
    _register()
    _heartbeat("agent-1", sequence=7)
    body = _heartbeat("agent-1", sequence=7).json()   # retransmisie exactă
    assert body["restart_detected"] is False
    assert _restart_events() == []
    assert agent_svc.agents_store["agent-1"].get("restart_count", 0) == 0


def test_legacy_heartbeat_without_sequence_is_backward_compatible():
    _register()
    body = _heartbeat("agent-1", instance_id=None).json()   # nici sequence, nici instance
    assert body["status"] == "ok"
    assert body["restart_detected"] is False
    assert body["missed_heartbeats"] == 0
    assert "last_sequence" not in agent_svc.agents_store["agent-1"]
    assert _restart_events() == []



def test_lower_sequence_same_instance_is_stale_duplicate():
    _register()
    _heartbeat("agent-1", sequence=5)
    body = _heartbeat("agent-1", sequence=4).json()   # pachet întârziat
    assert body["restart_detected"] is False
    assert _restart_events() == []
    assert agent_svc.agents_store["agent-1"]["last_sequence"] == 5


# --- REPORNIRE (prin schimbarea incarnării) ----------------------------------
def test_new_instance_is_detected_as_restart_and_emits_event():
    _register()
    _heartbeat("agent-1", sequence=1, instance_id="inst-A")
    _heartbeat("agent-1", sequence=2, instance_id="inst-A")
    _heartbeat("agent-1", sequence=3, instance_id="inst-A")

    body = _heartbeat("agent-1", sequence=1, instance_id="inst-B").json()  # proces nou

    assert body["restart_detected"] is True
    events = _restart_events()
    assert len(events) == 1
    assert events[0]["agent_id"] == "agent-1"
    assert agent_svc.agents_store["agent-1"]["restart_count"] == 1


def test_restart_detected_even_when_sequence_is_higher():
    _register()
    _heartbeat("agent-1", sequence=5, instance_id="inst-A")
    body = _heartbeat("agent-1", sequence=100, instance_id="inst-B").json()
    assert body["restart_detected"] is True
    assert body["missed_heartbeats"] == 0
    assert len(_restart_events()) == 1


def test_baseline_resets_after_restart_so_next_beat_is_normal():
    _register()
    _heartbeat("agent-1", sequence=5, instance_id="inst-A")
    _heartbeat("agent-1", sequence=1, instance_id="inst-B")   # restart -> baseline 1
    body = _heartbeat("agent-1", sequence=2, instance_id="inst-B").json()
    assert body["restart_detected"] is False
    assert len(_restart_events()) == 1


# --- CONTINUITATE ÎN ABSENȚA INCARNĂRII --------------------------------------
#
# Zona pe care suita nu o acoperea. Testul legacy existent trimite nici sequence,
# nici instance_id — combinație inofensivă, pentru că ramura periculoasă nici nu
# se atinge. Combinația care doare e sequence prezent + incarnare absentă: exact
# ce trimitea build-ul de agent dinaintea introducerii lui agent_instance_id.

def _continuity_lost_events():
    return [
        e for e in event_svc.get_all_events()
        if e["event_type"] == "agent_continuity_lost"
    ]


def test_sequence_reset_without_instance_does_not_freeze_the_baseline():
    """
    Regresia centrală închisă de acest bloc.

    Cu baseline-ul blocat pe valoarea rulării precedente, fiecare heartbeat până la
    depășirea ei ar fi aruncat ca „pachet reordonat”, iar fereastra oarbă ar dura
    exact cât a durat rularea precedentă — ore sau săptămâni, fără plafon.
    """
    _register()
    _heartbeat("agent-1", sequence=500, instance_id=None)

    body = _heartbeat("agent-1", sequence=1, instance_id=None).json()

    assert body["status"] == "ok"
    assert agent_svc.agents_store["agent-1"]["last_sequence"] == 1


def test_tracking_resumes_immediately_after_a_sequence_reset():
    _register()
    _heartbeat("agent-1", sequence=500, instance_id=None)
    _heartbeat("agent-1", sequence=1, instance_id=None)

    body = _heartbeat("agent-1", sequence=2, instance_id=None).json()

    assert body["missed_heartbeats"] == 0
    assert agent_svc.agents_store["agent-1"]["last_sequence"] == 2


def test_sequence_reset_without_instance_is_never_reported_as_restart():
    """
    Serverul nu are dovada unei reporniri. A o declara ar fabrica un fals pozitiv.
    """
    _register()
    _heartbeat("agent-1", sequence=500, instance_id=None)

    body = _heartbeat("agent-1", sequence=1, instance_id=None).json()

    assert body["restart_detected"] is False
    assert _restart_events() == []
    assert agent_svc.agents_store["agent-1"].get("restart_count", 0) == 0


def test_sequence_reset_without_instance_is_surfaced_as_a_coverage_gap():
    """Baseline-ul refăcut tăcut ar ascunde faptul că agentul nu e urmăribil."""
    _register()
    _heartbeat("agent-1", sequence=500, instance_id=None)

    body = _heartbeat("agent-1", sequence=1, instance_id=None).json()

    assert body["continuity_lost"] is True
    events = _continuity_lost_events()
    assert len(events) == 1
    assert events[0]["agent_id"] == "agent-1"
    assert agent_svc.agents_store["agent-1"]["continuity_losses_total"] == 1


def test_reordered_packet_within_a_known_incarnation_is_still_ignored():
    """
    Relaxarea se aplică strict în absența incarnării. Cu incarnare cunoscută,
    regresia rămâne pachet întârziat, iar baseline-ul nu se atinge — altfel
    patch-ul ar fi reintrodus regula eliminată de comitul afe160d.
    """
    _register()
    _heartbeat("agent-1", sequence=5, instance_id="inst-A")

    body = _heartbeat("agent-1", sequence=4, instance_id="inst-A").json()

    assert body["continuity_lost"] is False
    assert agent_svc.agents_store["agent-1"]["last_sequence"] == 5
    assert _continuity_lost_events() == []


def test_first_incarnation_discards_a_baseline_left_by_a_legacy_run():
    """
    Upgrade de agent: rulările legacy lasă un last_sequence care nu aparține
    incarnării nou raportate. Comparat cu ea, ar bloca baseline-ul din nou —
    de data asta chiar pentru un agent corect, actualizat.
    """
    _register()
    _heartbeat("agent-1", sequence=500, instance_id=None)      # build vechi

    body = _heartbeat("agent-1", sequence=1, instance_id="inst-A").json()  # build nou

    assert body["status"] == "ok"
    assert body["restart_detected"] is False
    assert body["continuity_lost"] is False
    assert agent_svc.agents_store["agent-1"]["last_sequence"] == 1