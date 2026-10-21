"""
Teste pentru câmpul monitoring din heartbeat (contract v10).

Problema închisă: un agent al cărui spool sau FileMonitor nu pornește, ori al
cărui pipeline moare în timpul rulării, rămâne "online" fără să supravegheze
nimic, iar serverul nu află. Pentru un EDR e cea mai proastă formă de eșec:
endpoint-ul orb arată sănătos și, într-o măsurătoare, arată liniștit.
"""
import logging

import app.services.agent_service as agent_svc
import app.services.auth_service as auth_svc
import app.services.event_service as event_svc
import app.services.measurement_run as measurement_run
from app.tests.support import make_test_client

client = make_test_client()


def setup_function():
    agent_svc.agents_store.clear()
    event_svc.reset_for_tests()
    measurement_run.reset_for_tests()
    auth_svc.reset_for_tests()
    client.forget_keys()


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


def _heartbeat(agent_id="agent-1", sequence=1, instance_id="inst-A", monitoring=None):
    payload = {
        "agent_id": agent_id,
        "sequence": sequence,
        "agent_instance_id": instance_id,
    }
    if monitoring is not None:
        payload["monitoring"] = monitoring
    return client.post(f"/api/agents/{agent_id}/heartbeat", json=payload)


def _listed(agent_id="agent-1"):
    """Vederea operatorului: clientul de test poartă singur secretul de înrolare."""
    agents = client.get("/api/agents/monitoring").json()["agents"]
    return next(a for a in agents if a["agent_id"] == agent_id)


def _monitoring_events():
    return [
        e
        for e in event_svc.get_all_events()
        if e["event_type"] == "agent_monitoring_changed"
    ]


def test_heartbeat_without_the_field_leaves_monitoring_unknown():
    _register()

    assert _heartbeat().status_code == 200

    assert _listed()["monitoring"] is None
    assert _monitoring_events() == []


def test_the_operator_route_exposes_the_reported_state():
    _register()

    _heartbeat(monitoring="spool_unavailable")

    assert _listed()["monitoring"] == "spool_unavailable"


def test_a_blind_agent_stays_online():
    """monitoring nu are voie să atingă status: degraded = heartbeat întârziat."""
    _register()

    _heartbeat(monitoring="monitor_unavailable")

    listed = _listed()
    assert listed["status"] == "online"
    assert listed["monitoring"] == "monitor_unavailable"
    assert listed["monitored"] is False


def test_an_unknown_value_is_accepted_but_never_counts_as_active(caplog):
    """
    422 ar opri bucla de heartbeat a agentului până la repornire: un agent mai
    nou, cu o stare necunoscută aici, ar apărea mort în loc de orb.
    """
    _register()

    with caplog.at_level(logging.WARNING):
        response = _heartbeat(monitoring="partially_blind")

    assert response.status_code == 200
    assert _listed()["monitoring"] == "unrecognized"
    assert "partially_blind" in caplog.text


def test_the_normal_start_emits_no_event():
    _register()

    _heartbeat(sequence=1, monitoring="active")
    _heartbeat(sequence=2, monitoring="active")

    assert _monitoring_events() == []


def test_the_first_blind_heartbeat_emits_an_event():
    """
    Fără stare anterioară: registrul e volatil, deci după o repornire a
    serverului primul heartbeat orb e singura ocazie de a lăsa o urmă.
    """
    _register()

    _heartbeat(monitoring="spool_unavailable")

    events = _monitoring_events()
    assert len(events) == 1
    assert "not_reported -> spool_unavailable" in events[0]["description"]
    assert events[0]["agent_instance_id"] == "inst-A"


def test_monitoring_lost_at_runtime_and_recovered_emits_both_transitions():
    _register()

    _heartbeat(sequence=1, monitoring="active")
    _heartbeat(sequence=2, monitoring="stopped")
    _heartbeat(sequence=3, monitoring="stopped")
    _heartbeat(sequence=4, instance_id="inst-B", monitoring="active")

    descriptions = [e["description"] for e in _monitoring_events()]
    assert len(descriptions) == 2
    assert "active -> stopped" in descriptions[0]
    assert "stopped -> active" in descriptions[1]
    assert _listed()["monitoring"] == "active"


def test_the_event_carries_the_current_measurement_run():
    """Rularea e ce permite măsurătorii să-și excludă endpoint-urile oarbe."""
    _register()

    _heartbeat(monitoring="stopped")

    (event,) = _monitoring_events()
    assert event["run_id"] == measurement_run.current_run_id()


def test_a_reordered_heartbeat_does_not_overwrite_a_newer_state():
    _register()

    _heartbeat(sequence=5, monitoring="stopped")
    _heartbeat(sequence=4, monitoring="active")

    assert _listed()["monitoring"] == "stopped"
    assert len(_monitoring_events()) == 1


def test_an_old_build_does_not_inherit_active_from_the_previous_incarnation():
    _register()

    _heartbeat(sequence=1, instance_id="inst-A", monitoring="active")
    _heartbeat(sequence=1, instance_id="inst-B")

    assert _listed()["monitoring"] is None


# --- Expunere ---------------------------------------------------------------
#
# Lista endpoint-urilor oarbe e o hartă de țintire. Rutele publice de citire
# (gaura declarată, edr-server#9) n-au voie s-o arate.

_WRONG_SECRET = {auth_svc.ENROLLMENT_SECRET_HEADER: "not-the-secret"}


def test_the_public_inventory_does_not_say_which_agents_are_blind():
    _register()
    _heartbeat(monitoring="spool_unavailable")

    (listed,) = client.get("/api/agents").json()["agents"]

    assert "monitoring" not in listed
    assert "spool_unavailable" not in str(listed)


def test_the_public_event_feed_does_not_carry_monitoring_transitions():
    _register()
    _heartbeat(monitoring="stopped")

    for query in ("", "?all_runs=true"):
        events = client.get(f"/api/events{query}").json()["events"]
        assert all(e["event_type"] != "agent_monitoring_changed" for e in events)

    # Depozitul îl păstrează: măsurătoarea are nevoie de el.
    assert len(_monitoring_events()) == 1


def test_the_operator_route_refuses_a_caller_without_the_secret():
    _register()
    _heartbeat(monitoring="stopped")

    response = client.get("/api/agents/monitoring", headers=_WRONG_SECRET)

    assert response.status_code == 401
    assert "stopped" not in response.text


def test_the_operator_route_refuses_an_agent_key():
    """Partea măsurată nu citește cine din parc e orb."""
    _register()
    _heartbeat(monitoring="stopped")
    agent_key = client.issued_keys["agent-1"]

    response = client.get(
        "/api/agents/monitoring",
        headers={**_WRONG_SECRET, auth_svc.AGENT_KEY_HEADER: agent_key},
    )

    assert response.status_code == 401


def test_the_operator_route_returns_the_transitions_of_the_run():
    """Starea curentă se pierde cu registrul; tranzițiile persistate, nu."""
    _register()
    _heartbeat(sequence=1, monitoring="active")
    _heartbeat(sequence=2, monitoring="stopped")
    agent_svc.agents_store.clear()

    body = client.get("/api/agents/monitoring").json()

    assert body["agents"] == []
    (transition,) = body["transitions"]
    assert transition["agent_id"] == "agent-1"
    assert "active -> stopped" in transition["description"]
    assert transition["run_id"] == measurement_run.current_run_id()
