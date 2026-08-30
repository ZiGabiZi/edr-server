"""
Autentificarea API — ce apără, și ce anume ar tăcea dacă ar lipsi.
==================================================================

Testele de aici NU folosesc clientul care se autentifică singur (support.py):
tot rostul lor e să trimită exact ce vor, inclusiv nimic.

Ce se verifică, în ordinea în care lucrurile pot să tacă:

  1. rutele de scriere refuză un apelant fără credențiale — altfel restul e
     decorativ;
  2. legarea cheie ↔ agent_id. E pasul cel mai ușor de uitat: fără el toți
     agenții sunt autentificați și oricare poate scrie în numele oricui, adică
     exact starea de dinainte, cu un antet în plus;
  3. re-înregistrarea cu cheia existentă. Fără ea, un restart al serverului ar
     bloca definitiv un parc care și-a consumat deja secretul de înrolare;
  4. cheile nu ies niciodată pe rutele de citire, care în pasul ăsta sunt încă
     deschise.
"""

import pytest
from fastapi.testclient import TestClient

import app.services.agent_service as agent_service
import app.services.auth_service as auth_service
import app.services.event_service as event_service
from app.main import app


ENROLLMENT_SECRET = "test-enrollment-secret"


@pytest.fixture
def raw_client():
    """Client fără niciun antet automat — trimite exact ce cere testul."""
    agent_service.agents_store.clear()
    event_service.reset_for_tests()
    auth_service.reset_for_tests(ENROLLMENT_SECRET)
    return TestClient(app)


def _registration_body(agent_id: str) -> dict:
    return {
        "agent_id": agent_id,
        "hostname": "HOST1",
        "operating_system": "windows",
        "architecture": "x64",
        "os_architecture": "x64",
        "machine_id_type": "hash",
        "machine_id_hash": f"hash-{agent_id}",
    }


def _enroll(raw_client: TestClient, agent_id: str) -> str:
    """Înrolează un agent cu secretul de înrolare și întoarce cheia emisă."""
    response = raw_client.post(
        "/api/agents/register",
        json=_registration_body(agent_id),
        headers={auth_service.ENROLLMENT_SECRET_HEADER: ENROLLMENT_SECRET},
    )
    assert response.status_code == 200, response.text

    agent_key = response.json().get("agent_key")
    assert agent_key, "înrolarea trebuie să emită o cheie"
    return agent_key


def _event_body(agent_id: str) -> dict:
    return {"agent_id": agent_id, "event_type": "agent_startup"}


# ---------------------------------------------------------------------------
# 1. Rutele de scriere refuză apelanții fără credențiale
# ---------------------------------------------------------------------------

def test_registration_without_any_credential_is_refused(raw_client):
    response = raw_client.post(
        "/api/agents/register", json=_registration_body("agent-1")
    )

    assert response.status_code == 401
    assert "agent-1" not in agent_service.agents_store, (
        "store-ul nu are voie să fie atins de o cerere neautorizată"
    )


def test_registration_with_a_wrong_enrollment_secret_is_refused(raw_client):
    response = raw_client.post(
        "/api/agents/register",
        json=_registration_body("agent-1"),
        headers={auth_service.ENROLLMENT_SECRET_HEADER: "not-the-secret"},
    )

    assert response.status_code == 401
    assert "agent-1" not in agent_service.agents_store


def test_a_non_ascii_enrollment_secret_is_refused_not_a_server_error(raw_client):
    """
    Intrare ostilă, nu eroare de programare.

    Antetele HTTP se decodează latin-1, deci un client poate trimite oricând
    octeți care devin caractere non-ASCII. hmac.compare_digest refuză să compare
    șiruri cu non-ASCII și ridică TypeError; netratată, excepția ieșea din rută
    ca 500 — adică un curl scris de mână producea eroare de server pe frontiera
    de încredere, în loc de un refuz.

    Cazul are și o formă complet nevinovată: un fișier de secret salvat cu BOM
    arată exact așa privit dinspre server.
    """
    response = raw_client.post(
        "/api/agents/register",
        json=_registration_body("agent-1"),
        headers={
            auth_service.ENROLLMENT_SECRET_HEADER: "﻿secret".encode("utf-8")
        },
    )

    assert response.status_code == 401, response.text
    assert "agent-1" not in agent_service.agents_store


def test_an_enrollment_secret_file_with_a_bom_still_matches(tmp_path):
    """
    Fișierul de secret al serverului poate fi scris de un operator pe Windows,
    unde uneltele obișnuite adaugă BOM. Citit ca utf-8 curat, secretul citit de
    server n-ar mai corespunde niciodată celui de pe endpoint, fără ca nimic să
    spună de ce: ambele părți ar afișa aceeași valoare la o inspecție vizuală.
    """
    secret_file = tmp_path / "enrollment_secret.txt"
    secret_file.write_bytes("﻿secret-de-pe-disc\n".encode("utf-8"))

    auth_service.reset_for_tests(ENROLLMENT_SECRET)
    auth_service._enrollment_secret = None
    auth_service._enrollment_secret_path = secret_file

    try:
        assert auth_service.get_enrollment_secret() == "secret-de-pe-disc"
        assert auth_service.verify_enrollment_secret("secret-de-pe-disc") is True
    finally:
        auth_service.reset_for_tests(ENROLLMENT_SECRET)


def test_events_without_a_key_are_refused(raw_client):
    _enroll(raw_client, "agent-1")

    response = raw_client.post("/api/events", json=_event_body("agent-1"))

    assert response.status_code == 401
    assert event_service.get_all_events() == []


def test_heartbeat_without_a_key_is_refused(raw_client):
    _enroll(raw_client, "agent-1")

    response = raw_client.post(
        "/api/agents/agent-1/heartbeat", json={"agent_id": "agent-1"}
    )

    assert response.status_code == 401


def test_a_revoked_key_stops_working(raw_client):
    agent_key = _enroll(raw_client, "agent-1")

    assert auth_service.revoke_agent_key("agent-1") is True

    response = raw_client.post(
        "/api/events",
        json=_event_body("agent-1"),
        headers={auth_service.AGENT_KEY_HEADER: agent_key},
    )

    assert response.status_code == 401


# ---------------------------------------------------------------------------
# 2. Legarea cheie ↔ agent_id
# ---------------------------------------------------------------------------

def test_a_valid_key_writes_events_for_its_own_agent(raw_client):
    agent_key = _enroll(raw_client, "agent-1")

    response = raw_client.post(
        "/api/events",
        json=_event_body("agent-1"),
        headers={auth_service.AGENT_KEY_HEADER: agent_key},
    )

    assert response.status_code == 200, response.text
    assert len(event_service.get_all_events()) == 1


def test_an_agent_cannot_write_events_in_the_name_of_another(raw_client):
    """
    Verificarea fără de care autentificarea n-ar valora mare lucru.

    Ambii agenți sunt autentici. Dacă legarea ar lipsi, un endpoint compromis ar
    putea fabrica activitate pe orice altă mașină din parc, iar registrul ar
    prelua fabricația ca adevăr.
    """
    agent_one_key = _enroll(raw_client, "agent-1")
    _enroll(raw_client, "agent-2")

    response = raw_client.post(
        "/api/events",
        json=_event_body("agent-2"),
        headers={auth_service.AGENT_KEY_HEADER: agent_one_key},
    )

    assert response.status_code == 403
    assert event_service.get_all_events() == []


def test_an_agent_cannot_heartbeat_in_the_name_of_another(raw_client):
    agent_one_key = _enroll(raw_client, "agent-1")
    _enroll(raw_client, "agent-2")

    response = raw_client.post(
        "/api/agents/agent-2/heartbeat",
        json={"agent_id": "agent-2", "sequence": 1, "agent_instance_id": "inst-A"},
        headers={auth_service.AGENT_KEY_HEADER: agent_one_key},
    )

    assert response.status_code == 403
    assert agent_service.agents_store["agent-2"].get("last_sequence") is None, (
        "un heartbeat refuzat nu are voie să miște starea agentului vizat"
    )


def test_identity_is_checked_before_the_agent_is_looked_up(raw_client):
    """
    403, nu 404, pentru un agent_id inexistent.

    Ordinea contează: dacă existența s-ar verifica prima, diferența dintre 404
    și 200 ar spune unui agent autentificat care agent_id-uri există în parc —
    o rută de enumerare oferită tocmai celui care n-are voie să știe.
    """
    agent_key = _enroll(raw_client, "agent-1")

    response = raw_client.post(
        "/api/events",
        json=_event_body("never-registered"),
        headers={auth_service.AGENT_KEY_HEADER: agent_key},
    )

    assert response.status_code == 403


def test_a_key_cannot_register_another_agent_id(raw_client):
    """Cazul tipic: fișierul de cheie al unei mașini, copiat pe alta."""
    agent_one_key = _enroll(raw_client, "agent-1")

    response = raw_client.post(
        "/api/agents/register",
        json=_registration_body("agent-2"),
        headers={auth_service.AGENT_KEY_HEADER: agent_one_key},
    )

    assert response.status_code == 403
    assert "agent-2" not in agent_service.agents_store


# ---------------------------------------------------------------------------
# 3. Re-înregistrarea cu cheia existentă
# ---------------------------------------------------------------------------

def test_reregistration_with_the_existing_key_keeps_that_key(raw_client):
    """
    Calea de după un restart al serverului: agentul nu mai are secret de
    înrolare (l-a șters după prima folosire), dar are cheia. Ea trebuie să fie
    suficientă — și trebuie să rămână valabilă după.
    """
    agent_key = _enroll(raw_client, "agent-1")
    agent_service.agents_store.clear()

    response = raw_client.post(
        "/api/agents/register",
        json=_registration_body("agent-1"),
        headers={auth_service.AGENT_KEY_HEADER: agent_key},
    )

    assert response.status_code == 200, response.text
    assert "agent_key" not in response.json(), (
        "re-înregistrarea nu rotește credențiale; rotația e o operație explicită"
    )

    still_works = raw_client.post(
        "/api/events",
        json=_event_body("agent-1"),
        headers={auth_service.AGENT_KEY_HEADER: agent_key},
    )
    assert still_works.status_code == 200, still_works.text


def test_the_enrollment_secret_can_reissue_a_key_after_it_is_lost(raw_client):
    """
    Recuperarea după pierderea fișierului de cheie de pe endpoint. Cheia veche
    trebuie să moară în același moment — altfel o mașină dezafectată ar rămâne
    cu o credențială validă la nesfârșit.
    """
    old_key = _enroll(raw_client, "agent-1")
    new_key = _enroll(raw_client, "agent-1")

    assert new_key != old_key

    refused = raw_client.post(
        "/api/events",
        json=_event_body("agent-1"),
        headers={auth_service.AGENT_KEY_HEADER: old_key},
    )
    assert refused.status_code == 401

    accepted = raw_client.post(
        "/api/events",
        json=_event_body("agent-1"),
        headers={auth_service.AGENT_KEY_HEADER: new_key},
    )
    assert accepted.status_code == 200, accepted.text


# ---------------------------------------------------------------------------
# 4. Cheile nu ies pe rutele de citire (care sunt încă deschise)
# ---------------------------------------------------------------------------

def test_the_public_agent_list_never_carries_key_material(raw_client):
    """
    GET /api/agents e deliberat deschis în pasul ăsta (gaură cunoscută, vezi
    AUTH.md). Testul fixează singurul lucru care face gaura suportabilă: prin
    ea nu se scurg credențiale. Ar fi fost altfel dacă cheia stătea pe
    înregistrarea agentului, în agents_store.
    """
    agent_key = _enroll(raw_client, "agent-1")

    body = raw_client.get("/api/agents").json()
    serialized = repr(body)

    assert agent_key not in serialized
    for agent in body["agents"]:
        assert "agent_key" not in agent
        assert "key_hash" not in agent


def test_the_store_keeps_a_fingerprint_not_the_key(raw_client):
    agent_key = _enroll(raw_client, "agent-1")

    records = auth_service.list_key_records()

    assert set(records) == {"agent-1"}
    assert records["agent-1"]["key_hash"] != agent_key
    assert len(records["agent-1"]["key_hash"]) == 64  # SHA-256 hex
