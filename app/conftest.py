import pytest
from fastapi.testclient import TestClient

import app.services.agent_service as agent_service
import app.services.event_service as event_service
from app.main import app


@pytest.fixture
def client():
    agent_service.agents_store.clear()
    event_service.events_store.clear()
    event_service._events_by_client_id.clear()
    return TestClient(app)


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
    return agent_id
