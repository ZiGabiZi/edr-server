"""
Teste de contract pentru câmpurile evenimentelor și pentru proprietatea exclusivă
a incarnării de către canalul de heartbeat.

Testele de payload din edr-agent verifică ce *trimite* agentul. Acestea verifică
ce *supraviețuiește* validării și ajunge efectiv în store — cele două împreună
închid golul; niciunul singur nu îl închide.
"""

import app.services.agent_service as agent_service
import app.services.event_service as event_service
from app.schemas.event import EventResponse


OCCURRED_AT = "2026-08-05T10:00:00+00:00"


def _register(client, agent_id: str):
    """Aceeași identitate de mașină ca fixture-ul registered_agent_id (fără conflict)."""
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


def _post_startup_event(client, agent_id: str, **overrides):
    payload = {
        "agent_id": agent_id,
        "event_type": "agent_startup",
        "client_event_id": "evt-startup",
        "agent_instance_id": "inst-A",
        "occurred_at": OCCURRED_AT,
        "description": "Agent started successfully",
    }
    payload.update(overrides)
    return client.post("/api/events", json=payload)


def _heartbeat(client, agent_id: str, sequence: int, instance_id: str):
    return client.post(
        f"/api/agents/{agent_id}/heartbeat",
        json={
            "agent_id": agent_id,
            "sequence": sequence,
            "agent_instance_id": instance_id,
        },
    )


def test_event_keeps_occurred_at_and_instance_id(client, registered_agent_id):
    response = _post_startup_event(client, registered_agent_id)

    assert response.status_code == 200, response.text
    stored = response.json()["event"]
    assert stored["occurred_at"] == OCCURRED_AT
    assert stored["agent_instance_id"] == "inst-A"
    assert stored["received_at"], "received_at trebuie pus de server la primire"


def test_startup_event_can_be_correlated_with_the_run_that_heartbeats(
    client, registered_agent_id
):
    """
    Scopul întregii schimbări: evenimentul de pornire și heartbeat-urile aceleiași
    rulări trebuie să poarte aceeași incarnare, ca un restart observat pe heartbeat
    să poată fi atribuit unui agent_startup anume.
    """
    _post_startup_event(client, registered_agent_id, agent_instance_id="inst-B")
    _heartbeat(client, registered_agent_id, sequence=1, instance_id="inst-B")

    events = client.get("/api/events").json()["events"]
    startup = next(e for e in events if e["client_event_id"] == "evt-startup")

    assert (
        startup["agent_instance_id"]
        == agent_service.agents_store[registered_agent_id]["agent_instance_id"]
    )


def test_agents_without_the_new_fields_are_still_accepted(client, registered_agent_id):
    """Compatibilitate: un agent vechi nu trimite occurred_at / agent_instance_id."""
    response = client.post(
        "/api/events",
        json={
            "agent_id": registered_agent_id,
            "event_type": "file_created",
            "client_event_id": "evt-legacy",
            "file_path": "C:/tmp/proba.txt",
        },
    )

    assert response.status_code == 200, response.text
    stored = response.json()["event"]
    assert stored["occurred_at"] is None
    assert stored["agent_instance_id"] is None
    assert stored["received_at"]


def test_registration_does_not_adopt_the_incarnation(client, registered_agent_id):
    """
    Gardă de regresie pentru detecția de repornire.

    Dacă cineva adaugă agent_instance_id în AgentRegisterRequest, reînregistrarea de
    la repornire (care rulează înaintea primului heartbeat al noii incarnări) ar
    scrie noua incarnare direct în store prin existing_agent_by_id.update(...).
    Primul heartbeat ar găsi baseline-ul deja egal cu ce raportează, iar
    restart_detected ar rămâne False pentru totdeauna.
    """
    _heartbeat(client, registered_agent_id, sequence=1, instance_id="inst-A")

    # Repornirea agentului: se reînregistrează și trimite (în plus) noua incarnare.
    response = client.post(
        "/api/agents/register",
        json={
            "agent_id": registered_agent_id,
            "hostname": "HOST1",
            "operating_system": "windows",
            "architecture": "x64",
            "os_architecture": "x64",
            "machine_id_type": "hash",
            "machine_id_hash": f"hash-{registered_agent_id}",
            "agent_instance_id": "inst-B",
        },
    )
    assert response.status_code == 200, response.text

    assert (
        agent_service.agents_store[registered_agent_id].get("agent_instance_id")
        == "inst-A"
    ), "Înregistrarea a suprascris baseline-ul incarnării; repornirile devin invizibile."

    body = _heartbeat(client, registered_agent_id, sequence=1, instance_id="inst-B").json()

    assert body["restart_detected"] is True
    assert agent_service.agents_store[registered_agent_id]["restart_count"] == 1

def test_restart_event_carries_the_incarnation_it_detected(client, registered_agent_id):
    """
    Fără aceste câmpuri, agent_restart nu poate fi legat de agent_startup-ul
    incarnării noi decât prin adiacența lui event_id — exact slăbiciunea pe care
    occurred_at / agent_instance_id au fost adăugate să o elimine.
    """
    _heartbeat(client, registered_agent_id, sequence=1, instance_id="inst-A")
    _heartbeat(client, registered_agent_id, sequence=1, instance_id="inst-B")

    events = client.get("/api/events").json()["events"]
    restart = [e for e in events if e["event_type"] == "agent_restart"]

    assert len(restart) == 1
    assert restart[0]["agent_instance_id"] == "inst-B"
    assert restart[0]["occurred_at"]


def test_event_response_declares_every_stored_field(client, registered_agent_id):
    """
    Modelul de răspuns FILTREAZĂ ce nu declară; nu completează ce lipsește.

    Un câmp adăugat evenimentului stocat și uitat în `EventResponse` dispare de pe
    fir fără nicio eroare — exact clasa de bug pentru care există contractul, doar
    pe direcția pe care `WireModel` n-o acoperă, fiindcă acolo emitentul e chiar
    serverul. `run_id` era deja în situația asta: trimis de rută de la 1.4.2
    încoace, absent din model cât timp modelul era cod mort, deci adoptarea lui la
    contract_version 6 l-ar fi șters de pe fir în commit-ul care promitea că nu
    schimbă nimic.

    Se verifică în două locuri, nu într-unul: ce ține depozitul și ce iese efectiv
    pe fir. Prima verificare singură ar trece și dacă ruta ar filtra câmpuri la
    ieșire; a doua singură ar trece și dacă modelul ar declara un câmp pe care
    nimeni nu-l stochează.
    """
    response = _post_startup_event(client, registered_agent_id)
    assert response.status_code == 200, response.text

    declarate = set(EventResponse.model_fields)
    stocate = set(event_service.get_all_events()[-1])
    pe_fir = set(response.json()["event"])

    assert stocate == declarate, (
        f"Evenimentul stocat și modelul de răspuns nu mai descriu același lucru. "
        f"Stocate și nedeclarate (dispar tăcut de pe fir): "
        f"{sorted(stocate - declarate)}. Declarate și nestocate (răspunsul le-ar "
        f"cere și n-ar avea de unde): {sorted(declarate - stocate)}."
    )

    assert pe_fir == declarate, (
        f"Răspunsul de pe fir nu poartă exact câmpurile declarate: lipsă "
        f"{sorted(declarate - pe_fir)}, în plus {sorted(pe_fir - declarate)}."
    )