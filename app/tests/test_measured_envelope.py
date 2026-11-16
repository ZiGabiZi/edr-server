"""
Plicul din numitor se măsoară cu rigla numărătorului.
=====================================================

Defectul pe care îl prind testele de aici:
    `0465c4b` a pus plicul în numitorul always-upload, „cu același plic ca la
    numărător" (METRICS.md §2). Era adevărat cât timp ambele părți
    reserializau evenimentul stocat. `c3f6c6d` a trecut numărătorul pe octeții
    măsurați pe fir și n-a atins numitorul, care a rămas cu reserializarea.

    Evenimentul stocat poartă câmpuri pe care agentul nu le-a trimis niciodată
    (`event_id`, `received_at`, `run_id`, `status`, `reputation`,
    `prevalence`, nulurile explicite), deci reserializarea e mai lungă decât
    corpul de pe fir. Numitorul primea plic care n-a existat, raportul ieșea mai
    mic, iar protocolul părea mai ieftin decât e — exact direcția pe care §2
    spune că numitorul n-o poate lua. Pe un fișier de 900 B, cu 811 B
    reserializați și 490 B pe fir: 0,286 în loc de 0,353.

Regula apărată (N1): numărător măsurat ⟹ plic măsurat în numitor; numărător
estimat ⟹ plic reserializat. Nicio cifră nu amestecă rigle.

Plicul măsurat e corpul cererii care a CREAT evenimentul, consemnat de server la
primire (N2), într-un tabel propriu, nu în payload (N3), o singură dată (N4).
Un eveniment fără plic măsurat iese din numitorul măsurat cu totul, iar numărul
lor se raportează ca gol (N5).
"""

import json

import pytest

import app.services.event_store as event_store
import app.services.measurement_run as measurement_run
from app.services import auth_service
from app.services.disclosure_metrics import _payload_bytes, compute_disclosure_metrics
from app.wire_middleware import WIRE_INSTANCE_HEADER


INSTANCE_ID = "incarnare-de-test"


def _file_event(
    event_id: int,
    file_size: int | None = 900,
    envelope: int | None = None,
    **overrides,
):
    """
    Un eveniment de fișier hash-uit, așa cum îl întoarce depozitul.

    `envelope` umple descrierea până când reserializarea are exact atâția
    octeți, ca testul să poată numi cele două rigle cu cifre fixe.
    """
    event = {
        "event_id": event_id,
        "agent_id": "agent-1",
        "event_type": "file_created",
        "file_path": f"C:/tmp/f{event_id}.bin",
        "sha256": "a" * 64,
        "hash_status": "ok",
        "file_size": file_size,
        "disclosure": {"tier": "T0", "content_bytes": 0},
        "description": "",
    }
    event.update(overrides)

    if envelope is not None:
        event["description"] = "x" * (envelope - _payload_bytes(event))
        assert _payload_bytes(event) == envelope

    return event


# ---------------------------------------------------------------------------
# N1 — aceeași riglă în ambele părți
# ---------------------------------------------------------------------------


class TestTheDenominatorUsesTheRulerOfTheNumerator:
    def test_the_measured_numerator_uses_the_measured_envelope_in_the_denominator(self):
        # Cazul care a descoperit defectul: 900 B de fișier, 811 B
        # reserializați, 490 B pe fir. Raportul corect e 490 / (900 + 490).
        event = _file_event(1, file_size=900, envelope=811)

        metrics = compute_disclosure_metrics(
            [event],
            measured_channel_bytes=490,
            measured_envelope_bytes={1: 490},
        )

        assert metrics["always_upload"]["envelope_source"] == "measured"
        assert metrics["always_upload"]["envelope_bytes"] == 490
        assert metrics["always_upload"]["bytes"] == 900 + 490
        assert metrics["ratio"]["sent_over_always_upload"] == pytest.approx(0.352518)

    def test_the_estimated_numerator_keeps_the_reserialized_envelope(self):
        # Plicurile măsurate există, dar numărătorul e estimat: rigla
        # numitorului urmează numărătorul, nu ce date se întâmplă să fie la
        # îndemână. Altfel defectul s-ar inversa.
        event = _file_event(1, file_size=900, envelope=811)

        metrics = compute_disclosure_metrics([event], measured_envelope_bytes={1: 490})

        assert metrics["progressive"]["numerator_source"] == "estimated"
        assert metrics["always_upload"]["envelope_source"] == "estimated"
        assert metrics["always_upload"]["envelope_bytes"] == 811
        assert metrics["always_upload"]["bytes"] == 900 + 811

    def test_a_zero_measurement_keeps_the_reserialized_envelope(self):
        # Zero măsurat nu e măsurătoare (§7.5): numărătorul revine la estimare,
        # deci și plicul din numitor.
        event = _file_event(1, file_size=900, envelope=811)

        metrics = compute_disclosure_metrics(
            [event], measured_channel_bytes=0, measured_envelope_bytes={1: 490}
        )

        assert metrics["always_upload"]["envelope_source"] == "estimated"
        assert metrics["always_upload"]["envelope_bytes"] == 811

    def test_only_hashed_file_events_bring_their_envelope(self):
        # Ce a rămas valid din 0465c4b: plicul care intră în numitor e al
        # evenimentelor care intră în el. Evenimentele de ciclu de viață și
        # fișierele fără hash au plic măsurat, dar nu-l aduc în numitor.
        events = [
            _file_event(1, file_size=900),
            _file_event(2, hash_status="unstable", file_size=None, sha256=None),
            {"event_id": 3, "agent_id": "agent-1", "event_type": "agent_startup"},
        ]

        metrics = compute_disclosure_metrics(
            events,
            measured_channel_bytes=1_500,
            measured_envelope_bytes={1: 490, 2: 470, 3: 300},
        )

        assert metrics["always_upload"]["envelope_bytes"] == 490
        assert metrics["always_upload"]["bytes"] == 900 + 490


# ---------------------------------------------------------------------------
# N5 — fără plic măsurat, evenimentul iese din numitorul măsurat
# ---------------------------------------------------------------------------


class TestAnEventWithoutAMeasuredEnvelope:
    def test_it_leaves_the_measured_denominator_with_content_and_envelope(self):
        # Rezerva cu plicul reserializat ar reintroduce defectul exact pentru
        # evenimentul acesta. Scos cu totul, numitorul scade, raportul crește:
        # subestimare a economiei, ca restul golului de la §2.1.
        events = [_file_event(1, file_size=900), _file_event(2, file_size=5_000)]

        metrics = compute_disclosure_metrics(
            events,
            measured_channel_bytes=1_000,
            measured_envelope_bytes={1: 490},
        )

        assert metrics["always_upload"]["file_events_with_size"] == 1
        assert metrics["always_upload"]["content_bytes"] == 900
        assert metrics["always_upload"]["bytes"] == 900 + 490
        assert metrics["unmeasured"]["envelope_unmeasured"] == 1

    def test_without_any_measured_envelope_the_measured_ratio_has_no_denominator(self):
        # None, nu o cifră calculată pe rigla greșită: un raport fără numitor e
        # o afirmație fără suport.
        metrics = compute_disclosure_metrics(
            [_file_event(1, file_size=900)], measured_channel_bytes=490
        )

        assert metrics["always_upload"]["bytes"] == 0
        assert metrics["ratio"]["sent_over_always_upload"] is None
        assert metrics["unmeasured"]["envelope_unmeasured"] == 1

    def test_the_estimated_denominator_has_no_envelope_gap(self):
        # Golul e al riglei măsurate. Pe rigla estimată orice eveniment are un
        # plic reserializabil, deci nimic nu lipsește.
        metrics = compute_disclosure_metrics([_file_event(1, file_size=900)])

        assert metrics["unmeasured"]["envelope_unmeasured"] == 0


# ---------------------------------------------------------------------------
# N2–N4 — ce consemnează depozitul
# ---------------------------------------------------------------------------


@pytest.fixture
def fresh_store():
    event_store.reset_for_tests()

    yield

    event_store.reset_for_tests()
    measurement_run.reset_for_tests()


def _stored_event(client_event_id, **extra):
    event = {
        "agent_id": "agent-1",
        "agent_instance_id": "inst-A",
        "event_type": "file_created",
        "client_event_id": client_event_id,
        "file_path": "C:/tmp/proba.txt",
        "sha256": "a" * 64,
        "hash_status": "ok",
        "file_size": 1024,
        "measurements": None,
        "disclosure": {"tier": "T0", "content_bytes": 0},
        "description": "proba",
        "occurred_at": "2026-08-30T10:00:00+00:00",
        "received_at": "2026-08-30T10:00:01+00:00",
        "run_id": "rulare-1",
        "status": "received",
    }
    event.update(extra)

    return event


class TestTheStoreRecordsTheEnvelope:
    def test_the_body_bytes_are_recorded_per_event(self, fresh_store):
        stored = event_store.insert_event(_stored_event("evt-1"), body_bytes=490)

        assert event_store.envelope_bytes_by_event() == {stored["event_id"]: 490}

    def test_a_retransmission_keeps_the_body_bytes_of_the_first_arrival(self, fresh_store):
        # Ca la M9 și F9: ce se persistă e prima sosire. Retransmisia rămâne
        # doar în numărătorul măsurat, deci asimetria rămasă face protocolul
        # cel mult mai scump, niciodată mai ieftin.
        first = event_store.insert_event(_stored_event("evt-1"), body_bytes=490)
        event_store.insert_event(_stored_event("evt-1"), body_bytes=700)

        assert event_store.envelope_bytes_by_event() == {first["event_id"]: 490}

    def test_an_event_without_body_bytes_has_no_envelope(self, fresh_store):
        event_store.insert_event(_stored_event("evt-1"))

        assert event_store.envelope_bytes_by_event() == {}

    def test_the_body_bytes_do_not_enter_the_stored_payload(self, fresh_store):
        # În payload, valoarea ar intra în reserializare — umflând exact plicul
        # estimat, cum a făcut `run_id` — și în răspunsul descendent, care e
        # contract.
        event_store.insert_event(_stored_event("evt-1"), body_bytes=490)
        event_store.insert_event(_stored_event("evt-2"))

        with_bytes, without_bytes = event_store.all_events()

        assert set(with_bytes) == set(without_bytes)
        assert 490 not in with_bytes.values()

    def test_the_envelopes_are_restricted_to_the_requested_run(self, fresh_store):
        in_run = event_store.insert_event(_stored_event("evt-1"), body_bytes=490)
        event_store.insert_event(
            _stored_event("evt-2", run_id="rulare-2"), body_bytes=510
        )

        assert event_store.envelope_bytes_by_event("rulare-1") == {
            in_run["event_id"]: 490
        }

    def test_the_envelope_survives_a_restart(self, tmp_path, monkeypatch):
        # Contabilizarea de proces se pierde la repornire; plicul per
        # eveniment nu are voie.
        monkeypatch.setenv(event_store.DB_PATH_ENV, str(tmp_path / "masuratoare.db"))
        event_store.close()

        try:
            stored = event_store.insert_event(_stored_event("evt-1"), body_bytes=490)
            event_store.close()

            assert event_store.envelope_bytes_by_event() == {stored["event_id"]: 490}
        finally:
            event_store.reset_for_tests()
            measurement_run.reset_for_tests()


# ---------------------------------------------------------------------------
# Prin rută — de la Content-Length la numitor
# ---------------------------------------------------------------------------


class TestThroughTheRoute:
    def _send_event(self, client, agent_id, client_event_id="ev-1", file_size=4096):
        body = json.dumps(
            {
                "client_event_id": client_event_id,
                "agent_id": agent_id,
                "agent_instance_id": INSTANCE_ID,
                "event_type": "file_created",
                "file_path": "C:/tmp/a.bin",
                "sha256": "a" * 64,
                "hash_status": "ok",
                "file_size": file_size,
                "disclosure": {"tier": "T0", "content_bytes": 0},
            }
        ).encode("utf-8")

        response = client.post(
            "/api/events",
            content=body,
            headers={
                "Content-Type": "application/json",
                auth_service.AGENT_KEY_HEADER: client.issued_keys[agent_id],
                WIRE_INSTANCE_HEADER: INSTANCE_ID,
            },
        )
        assert response.status_code == 200, response.text

        return len(body), response.json()

    def test_the_route_records_the_content_length_of_the_request(
        self, client, registered_agent_id
    ):
        sent, response = self._send_event(client, registered_agent_id)

        assert event_store.envelope_bytes_by_event() == {
            response["event"]["event_id"]: sent
        }

    def test_the_response_does_not_carry_the_body_bytes(
        self, client, registered_agent_id
    ):
        sent, response = self._send_event(client, registered_agent_id)

        assert sent not in response["event"].values()

    def test_the_published_denominator_uses_the_wire_envelope(
        self, client, registered_agent_id
    ):
        sent, _ = self._send_event(client, registered_agent_id, file_size=900)

        body = client.get("/api/metrics/disclosure").json()

        assert body["progressive"]["numerator_source"] == "measured"
        assert body["always_upload"]["envelope_source"] == "measured"
        assert body["always_upload"]["envelope_bytes"] == sent
        assert body["ratio"]["sent_over_always_upload"] == pytest.approx(
            round(sent / (900 + sent), 6)
        )
