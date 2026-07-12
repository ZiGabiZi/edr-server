def test_duplicate_client_event_id_is_idempotent(client, registered_agent_id):
    payload = {
        "agent_id": registered_agent_id,
        "event_type": "file_created",
        "file_path": "C:\\monitored\\test.exe",
        "client_event_id": "11111111-1111-4111-8111-111111111111",
    }

    first = client.post("/api/events", json=payload)
    second = client.post("/api/events", json=payload)  # retransmisie simulată

    assert first.status_code == 200
    assert second.status_code == 200
    # Același eveniment, nu unul nou:
    assert second.json()["event"]["event_id"] == first.json()["event"]["event_id"]

    events = client.get("/api/events").json()
    assert events["count"] == 1


def test_event_without_client_id_still_accepted(client, registered_agent_id):
    """Compatibilitate: evenimente vechi din spool, fără client_event_id."""
    payload = {"agent_id": registered_agent_id, "event_type": "agent_startup"}
    response = client.post("/api/events", json=payload)
    assert response.status_code == 200