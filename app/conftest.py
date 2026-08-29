import pytest

import app.services.agent_service as agent_service
import app.services.auth_service as auth_service
import app.services.event_service as event_service
import app.services.wire_accounting as wire_accounting
from app.tests.support import make_test_client


@pytest.fixture
def client():
    agent_service.agents_store.clear()
    event_service.events_store.clear()
    event_service._events_by_client_id.clear()

    # Golește depozitul de chei ȘI dezactivează persistența lui: fără asta,
    # suita ar scrie agent_keys.json în rădăcina repo-ului și ar duce credențiale
    # dintr-o rulare în următoarea.
    auth_service.reset_for_tests()

    # Contabilizarea e stare de proces, ca store-urile de mai sus: fara golire,
    # octetii unui test s-ar aduna peste ai urmatorului, iar testele ar trece
    # sau ar cadea dupa ordinea in care ruleaza.
    wire_accounting.reset_for_tests()

    return make_test_client()


@pytest.fixture
def registered_agent_id(client):
    agent_id = "agent-1"
    response = client.post(
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
    assert response.status_code == 200, response.text

    # Înrolarea trebuie să fi emis o cheie; fără ea, orice test care scrie
    # după fixture-ul ăsta ar primi 401, iar cauza ar fi greu de citit.
    assert "agent_key" in response.json(), response.text

    return agent_id
