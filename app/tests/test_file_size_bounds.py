"""
file_size: ce respinge granița și ce declară metrica (contract v12).
=====================================================================

Până la v12 câmpul era `Optional[int]` fără nicio limită. `-5000000`, `10**15`,
`true` și `4096.0` primeau toate 200, iar `file_size` e NUMITORUL metricii de
divulgare: un singur eveniment cu `10**15` lângă zece fișiere de 1 MB a dus
raportul de la 0,000336 la 0,0.

Apărarea e împărțită în două, și testele urmează împărțirea:

  1. GRANIȚA respinge ce niciun agent corect nu poate emite: negativ sau
     ne-întreg. Agentul ia valoarea din stat().st_size.
  2. METRICA declară ce granița nu poate ști: o dimensiune prea mare, dar
     întreagă și pozitivă. Plafonul real e în configul agentului, pe care
     serverul nu-l vede, deci cifra spune cât din numitor vine de la un singur
     eveniment și de la fiecare agent (METRICS.md §2.2).
  3. ISTORIA — evenimentele stocate înainte de v12 cu dimensiuni pe care schema
     de azi le respinge nu au voie să strice numitorul.
"""

import hashlib

import pytest
from pydantic import ValidationError

from app.schemas.event import EventCreateRequest
from app.services.disclosure_metrics import compute_disclosure_metrics


def _request(**overrides):
    payload = {
        "agent_id": "a1",
        "event_type": "file_created",
        "file_path": "C:/tmp/x.bin",
        "hash_status": "ok",
        "sha256": "a" * 64,
        "file_size": 1024,
    }
    payload.update(overrides)
    return payload


def _stored(event_id: int, size, agent_id: str = "agent-1", hash_status: str = "ok"):
    """Un eveniment așa cum îl întoarce depozitul, cu `event_id`."""
    return {
        "event_id": event_id,
        "agent_id": agent_id,
        "event_type": "file_created",
        "file_path": f"C:\\EDR_Test\\{event_id}.bin",
        "sha256": hashlib.sha256(str(event_id).encode()).hexdigest(),
        "hash_status": hash_status,
        "file_size": size,
        "disclosure": {"tier": "T0", "content_bytes": 0},
    }


# ---------------------------------------------------------------------------
# 1. Granița
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("hash_status", ["ok", "too_large"])
def test_a_negative_file_size_is_rejected_at_any_hash_status(hash_status):
    """'too_large' poartă și el file_size din stat(), deci regula e aceeași."""
    payload = _request(file_size=-5_000_000, hash_status=hash_status)

    if hash_status != "ok":
        payload["sha256"] = None

    with pytest.raises(ValidationError, match="file_size nu poate fi negativ"):
        EventCreateRequest.model_validate(payload)


@pytest.mark.parametrize("value", [True, 4096.0, "4096"])
def test_a_file_size_that_is_not_an_integer_is_rejected(value):
    """
    În modul implicit, Pydantic făcea `true` → 1 și `4096.0` → 4096, tăcut.
    `True` e cel mai insidios: în Python e subclasă de `int`.
    """
    with pytest.raises(ValidationError):
        EventCreateRequest.model_validate(_request(file_size=value))


@pytest.mark.parametrize("value", [0, 1, 10**15])
def test_zero_and_large_sizes_still_pass_the_boundary(value):
    """
    Zero e un fișier gol, real. 10**15 trece DELIBERAT: limita de sus nu e a
    serverului de impus, iar apărarea pentru ea e în metrică, nu aici.
    """
    event = EventCreateRequest.model_validate(_request(file_size=value))

    assert event.file_size == value


def test_the_route_answers_422_and_stores_nothing(client, registered_agent_id):
    response = client.post(
        "/api/events",
        json=_request(agent_id=registered_agent_id, file_size=-5_000_000),
    )

    assert response.status_code == 422
    assert client.get("/api/events").json()["events"] == []


# ---------------------------------------------------------------------------
# 2. Metrica declară dominanța
# ---------------------------------------------------------------------------

def test_one_absurd_size_is_visible_as_nearly_the_whole_denominator():
    """
    Cazul care a produs 0,0. Raportul rămâne ce e — nu se ascunde și nu se
    corectează — dar declarația de lângă el spune că descrie un singur fișier.
    """
    events = [_stored(i, 1_000_000) for i in range(1, 11)] + [_stored(11, 10**15)]

    concentration = compute_disclosure_metrics(events)["always_upload"]["concentration"]

    assert concentration["largest_event"]["event_id"] == 11
    assert concentration["largest_event"]["share"] > 0.999


def test_an_honest_run_has_no_dominant_event():
    events = [_stored(i, 1_000_000) for i in range(1, 11)]

    concentration = compute_disclosure_metrics(events)["always_upload"]["concentration"]

    assert concentration["largest_event"]["share"] == pytest.approx(0.1, abs=0.001)


def test_the_contribution_is_size_plus_envelope_on_the_denominator_ruler():
    """
    Contribuțiile se adună exact la numitor: aceeași riglă, nu o cotă calculată
    doar pe conținut lângă un numitor care include plicul.
    """
    events = [_stored(1, 900, "agent-1"), _stored(2, 5_000, "agent-2")]

    metrics = compute_disclosure_metrics(events)
    by_agent = metrics["always_upload"]["concentration"]["by_agent"]

    assert sum(a["bytes"] for a in by_agent.values()) == metrics["always_upload"]["bytes"]
    assert sum(a["share"] for a in by_agent.values()) == pytest.approx(1.0, abs=1e-5)


def test_one_agent_dominating_the_park_is_visible():
    """
    Un agent care minte în limite plauzibile — 200 MiB la fiecare fișier — nu
    l-ar fi prins niciun prag. Cota lui din numitor îl arată.
    """
    events = [_stored(i, 4096, "cinstit") for i in range(1, 21)] + [
        _stored(100 + i, 200 * 1024 * 1024, "umflat") for i in range(5)
    ]

    by_agent = compute_disclosure_metrics(events)["always_upload"]["concentration"]["by_agent"]

    assert by_agent["umflat"]["events"] == 5
    assert by_agent["umflat"]["share"] > 0.99
    assert by_agent["cinstit"]["events"] == 20


def test_the_ruler_follows_the_measured_numerator():
    """Sub numărătorul măsurat, contribuția folosește plicul de pe fir (#14)."""
    events = [_stored(1, 900), _stored(2, 900)]

    metrics = compute_disclosure_metrics(
        events,
        measured_channel_bytes=980,
        measured_channel_messages=2,
        measured_envelope_bytes={1: 490, 2: 490},
    )

    largest = metrics["always_upload"]["concentration"]["largest_event"]

    assert largest["bytes"] == 900 + 490
    assert largest["share"] == pytest.approx(0.5)


def test_an_empty_denominator_keeps_the_shape_without_inventing_an_event():
    metrics = compute_disclosure_metrics([_stored(1, None, hash_status="unstable")])
    concentration = metrics["always_upload"]["concentration"]

    assert concentration["largest_event"] is None
    assert concentration["by_agent"] == {}
    assert "note" in concentration


# ---------------------------------------------------------------------------
# 3. Istoria de dinainte de v12
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad", [-5_000_000, True, 4096.0, "4096"])
def test_a_stored_invalid_size_leaves_the_denominator_and_is_counted(bad):
    honest = [_stored(i, 1_000_000) for i in range(1, 4)]

    baseline = compute_disclosure_metrics(honest)["always_upload"]
    metrics = compute_disclosure_metrics(honest + [_stored(99, bad)])

    assert metrics["always_upload"]["content_bytes"] == baseline["content_bytes"]
    assert metrics["always_upload"]["file_events_with_size"] == 3
    assert metrics["unmeasured"]["file_size_invalid"] == 1


def test_no_invalid_sizes_means_zero_not_absent():
    metrics = compute_disclosure_metrics([_stored(1, 1024)])

    assert metrics["unmeasured"]["file_size_invalid"] == 0
