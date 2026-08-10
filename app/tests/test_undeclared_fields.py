"""
O cheie pe care contractul nu o declară trebuie să se audă, nu să oprească agentul.

De ce există acest fișier:
    Pydantic aruncă implicit cheile necunoscute, fără nicio urmă. Cazul concret
    care a motivat schimbarea: un builder din agent scria agent_instnce_id în loc
    de agent_instance_id. Serverul răspundea 200 OK, nu scria nimic în log, iar
    detecția de repornire nu se mai declanșa niciodată — pentru că se compara cu
    un None. Nimic nu eșua; doar încetase să funcționeze.

    app/schemas/wire.py::WireModel închide golul logând cheia, apoi aruncând-o.
    Testele de aici păzesc ambele jumătăți ale acelei alegeri: că zgomotul chiar
    apare, și că prețul lui rămâne zero pentru agent.
"""

import logging

import pytest

import app.services.agent_service as agent_service
from app.schemas.wire import WireModel
from app.tests.test_wire_contract import CONTRACT, CONTRACT_MODELS


WIRE_LOGGER = "app.schemas.wire"

INBOUND_DIRECTION = "agent -> server"


def _heartbeat_with(client, agent_id: str, **extra):
    payload = {"agent_id": agent_id, "sequence": 1, "agent_instance_id": "inst-A"}
    payload.update(extra)
    return client.post(f"/api/agents/{agent_id}/heartbeat", json=payload)


def test_an_undeclared_key_is_reported_with_its_name(
    client, registered_agent_id, caplog
):
    """
    Numele contează mai mult decât avertismentul. „Cheie necunoscută" trimite pe
    cineva să caute prin toate payload-urile; „agent_instnce_id" arată direct
    litera lipsă.
    """
    with caplog.at_level(logging.WARNING, logger=WIRE_LOGGER):
        response = _heartbeat_with(client, registered_agent_id, agent_instnce_id="x")

    assert response.status_code == 200, response.text

    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert "agent_instnce_id" in logged, (
        "Cheia scrisă greșit a trecut fără urmă în log. Exact eșecul tăcut pe "
        "care WireModel trebuie să îl elimine."
    )
    assert "HeartbeatRequest" in logged, "Logul nu spune pe ce model a apărut cheia."


def test_a_payload_that_respects_the_contract_stays_silent(
    client, registered_agent_id, caplog
):
    """
    Un avertisment care apare la fiecare heartbeat corect n-ar mai fi citit de
    nimeni după prima zi. Zgomotul e util doar cât timp e rar.
    """
    with caplog.at_level(logging.WARNING, logger=WIRE_LOGGER):
        response = _heartbeat_with(client, registered_agent_id)

    assert response.status_code == 200, response.text
    assert not [r for r in caplog.records if r.name == WIRE_LOGGER]


def test_an_undeclared_key_does_not_reject_the_request(client, registered_agent_id):
    """
    Gardă împotriva „îmbunătățirii" evidente: extra="forbid".

    Un 422 aici nu e o eroare vizibilă, ci oprirea monitorizării. Agentul
    clasifică orice 4xx în afară de 404/408/429 drept FatalTransportError, iar
    la heartbeat asta înseamnă heartbeat_loop() -> return: agentul tace până la
    repornirea procesului, iar endpoint-ul apare mort în consolă. O cheie scrisă
    greșit ar costa vizibilitatea completă asupra mașinii, nu un câmp gol.

    Dacă testul ăsta cade pentru că cineva a pus extra="forbid", citește întâi
    docstring-ul din app/schemas/wire.py.
    """
    response = _heartbeat_with(client, registered_agent_id, complet_necunoscut=1)

    assert response.status_code == 200, response.text


def test_an_undeclared_key_never_reaches_the_store(client, registered_agent_id):
    """
    Cheile logate trebuie și aruncate, nu doar semnalate.

    Cu extra="allow" simplu, ele ar rămâne pe model și ar intra în model_dump(),
    iar register_agent() face update(agent_data) peste înregistrarea existentă —
    adică orice cheie străină ar ajunge în store. Cazul periculos e
    agent_instance_id: scris acolo, suprascrie baseline-ul incarnării și omoară
    detecția de repornire (vezi test_event_contract.py::
    test_registration_does_not_adopt_the_incarnation).
    """
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
            "agent_versionn": "1.0.0",
        },
    )

    assert response.status_code == 200, response.text
    assert "agent_versionn" not in agent_service.agents_store[registered_agent_id], (
        "Cheia nedeclarată a ajuns în store. WireModel o loghează, dar nu o mai "
        "curăță — orice payload poate scrie acum câmpuri arbitrare pe agent."
    )


@pytest.mark.parametrize(
    "model_name",
    sorted(
        name
        for name, spec in CONTRACT["models"].items()
        if spec["direction"] == INBOUND_DIRECTION
    ),
)
def test_every_inbound_contract_model_reports_undeclared_keys(model_name: str):
    """
    Gardă structurală, ca acoperirea să nu depindă de memoria cuiva.

    Testele de mai sus verifică trei modele pentru că azi doar trei intră de pe
    fir. O schemă de cerere adăugată mâine și derivată din BaseModel ar readuce
    tăcerea exact pe canalul nou — cel mai puțin testat dintre toate. Lista vine
    din contract, deci se extinde singură.
    """
    schema = CONTRACT_MODELS[model_name]

    assert issubclass(schema, WireModel), (
        f"{schema.__name__} intră de pe fir, dar derivă direct din BaseModel: "
        f"cheile pe care nu le declară sunt aruncate fără nicio urmă în log. "
        f"Derivă-l din app.schemas.wire.WireModel."
    )
