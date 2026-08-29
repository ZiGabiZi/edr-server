"""
Teste pentru numărătorul măsurat și factorul de calibrare (pasul 1.3b.6).
=========================================================================

METRICS.md §7 începe cu o cerință: numărătorul trebuie să fie **măsurat, nu
estimat**. Până aici totul a fost pregătire — serializare explicită, registru pe
agent, anteturi, contabilizare pe server, reconciliere. Pasul acesta e cel care
o îndeplinește: cifra publicată în `progressive.total_bytes` vine din octeții pe
care serverul i-a numărat pe canalul de evenimente.

Trei lucruri se apără aici, în ordinea în care ar face cifra să mintă:

    1. **Zero măsurat nu e o măsurătoare.** Contabilizarea trăiește în memoria
       procesului; un agent care nu-și declară încarnarea dă zero octeți
       măsurați lângă evenimente reale. Publicat, zero ar însemna „acest
       endpoint n-a divulgat nimic" — cea mai flatantă minciună posibilă despre
       un sistem de confidențialitate.

    2. **Cifra își declară natura.** `numerator_source` spune „measured" sau
       „estimated" în același obiect cu numărul, ca nimeni să nu publice o
       estimare drept măsurătoare (§8).

    3. **Factorul de calibrare nu e curat.** El amestecă eroarea estimatorului
       cu retransmisiile, iar confundătorul se raportează alături, nu se ascunde
       înăuntru.
"""

import json

import pytest

from app.services import auth_service, wire_accounting
from app.services.disclosure_metrics import compute_disclosure_metrics
from app.wire_middleware import WIRE_INSTANCE_HEADER


INSTANCE_ID = "incarnare-de-test"


def _event(agent_id="agent-1", **overrides):
    event = {
        "agent_id": agent_id,
        "event_type": "file_created",
        "file_path": "C:/tmp/a.bin",
        "sha256": "a" * 64,
        "hash_status": "ok",
        "file_size": 4096,
        "disclosure": {"tier": "T1", "content_bytes": 0},
    }
    event.update(overrides)
    return event


class TestTheNumeratorBecomesMeasured:
    def test_without_a_measurement_the_numerator_stays_the_estimate(self):
        metrics = compute_disclosure_metrics([_event()])

        assert metrics["progressive"]["numerator_source"] == "estimated"
        assert (
            metrics["progressive"]["total_bytes"]
            == metrics["progressive"]["estimated_bytes"]
        )
        assert metrics["progressive"]["measured_bytes"] is None

    def test_with_a_measurement_the_numerator_is_the_measured_value(self):
        metrics = compute_disclosure_metrics([_event()], measured_channel_bytes=5_000)

        assert metrics["progressive"]["numerator_source"] == "measured"
        assert metrics["progressive"]["total_bytes"] == 5_000

    def test_a_zero_measurement_is_treated_as_no_measurement(self):
        # Cazul periculos: evenimente reale in store, zero octeti contabilizati.
        # Se intampla cu un agent care nu-si declara incarnarea. Publicat ca
        # numarator, zero ar spune ca endpoint-ul n-a divulgat nimic.
        metrics = compute_disclosure_metrics([_event()], measured_channel_bytes=0)

        assert metrics["progressive"]["numerator_source"] == "estimated"
        assert metrics["progressive"]["total_bytes"] > 0

    def test_the_ratio_follows_the_published_numerator(self):
        metrics = compute_disclosure_metrics([_event()], measured_channel_bytes=5_000)

        denominator = metrics["always_upload"]["bytes"]
        assert metrics["ratio"]["sent_over_always_upload"] == pytest.approx(
            round(5_000 / denominator, 6), rel=1e-9
        )
        assert metrics["ratio"]["bytes_saved"] == denominator - 5_000

    def test_content_is_a_breakdown_of_the_measured_number_not_an_addend(self):
        # Estimatul e plic + continut, pentru ca plicul reserializeaza
        # evenimentul stocat iar continutul e declarat separat. Masuratoarea e
        # corpul intreg al cererii: cand T2/T3 vor trimite continut, el va
        # calatori IN corp, deci e deja inauntru. Adunat pe deasupra, ar fi
        # numarat de doua ori.
        events = [_event(disclosure={"tier": "T2", "content_bytes": 900})]

        metrics = compute_disclosure_metrics(events, measured_channel_bytes=5_000)

        assert metrics["progressive"]["total_bytes"] == 5_000
        assert metrics["progressive"]["content_bytes"] == 900


class TestCalibration:
    def test_the_factor_is_measured_over_estimated(self):
        metrics = compute_disclosure_metrics([_event()], measured_channel_bytes=5_000)

        estimated = metrics["calibration"]["estimated_bytes"]
        assert metrics["calibration"]["factor"] == pytest.approx(
            round(5_000 / estimated, 6), rel=1e-9
        )

    def test_there_is_no_factor_without_a_measurement(self):
        # None, nu 1.0: un factor de 1 ar spune ca estimatorul e exact, ceea ce
        # e o afirmatie, nu o absenta.
        assert compute_disclosure_metrics([_event()])["calibration"]["factor"] is None

    def test_lifecycle_events_count_in_the_metered_denominator(self):
        # events_metered nu e len(file_events): estimatorul numara si
        # evenimentele de ciclu de viata, care au traversat aceeasi retea.
        events = [_event(), {"agent_id": "agent-1", "event_type": "agent_startup"}]

        metrics = compute_disclosure_metrics(events)

        assert metrics["calibration"]["events_metered"] == 2
        assert metrics["progressive"]["events_counted"] == 1

    def test_the_retransmission_confounder_is_reported_next_to_the_factor(self):
        # Doua mesaje masurate pentru un singur eveniment stocat inseamna ca o
        # parte din factor descrie retransmisii, nu eroarea estimatorului.
        metrics = compute_disclosure_metrics(
            [_event()], measured_channel_bytes=5_000, measured_channel_messages=2
        )

        assert metrics["calibration"]["messages_per_metered_event"] == 2.0

    def test_a_clean_exchange_shows_one_message_per_event(self):
        metrics = compute_disclosure_metrics(
            [_event()], measured_channel_bytes=5_000, measured_channel_messages=1
        )

        assert metrics["calibration"]["messages_per_metered_event"] == 1.0


class TestThroughTheRoute:
    def _send_event(self, client, agent_id, client_event_id="ev-1"):
        body = json.dumps(
            {
                "client_event_id": client_event_id,
                "agent_id": agent_id,
                "agent_instance_id": INSTANCE_ID,
                "event_type": "file_created",
                "file_path": "C:/tmp/a.bin",
                "sha256": "a" * 64,
                "hash_status": "ok",
                "file_size": 4096,
                "disclosure": {"tier": "T1", "content_bytes": 0},
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
        return len(body)

    def test_the_route_publishes_the_measured_numerator(
        self, client, registered_agent_id
    ):
        sent = self._send_event(client, registered_agent_id)

        body = client.get("/api/metrics/disclosure").json()

        assert body["progressive"]["numerator_source"] == "measured"
        assert body["progressive"]["total_bytes"] == sent

    def test_the_measured_numerator_is_the_events_channel_alone(
        self, client, registered_agent_id
    ):
        # par. 1.4: heartbeat-urile sunt prag separat, nu divulgare. Daca ar
        # intra in numarator, cifra afirmatiei centrale ar creste cu timpul, nu
        # cu fisierele.
        sent = self._send_event(client, registered_agent_id)
        client.post(
            f"/api/agents/{registered_agent_id}/heartbeat",
            content=json.dumps(
                {"agent_instance_id": INSTANCE_ID, "sequence": 1}
            ).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                auth_service.AGENT_KEY_HEADER: client.issued_keys[registered_agent_id],
                WIRE_INSTANCE_HEADER: INSTANCE_ID,
            },
        )

        body = client.get("/api/metrics/disclosure").json()

        assert body["progressive"]["total_bytes"] == sent
        assert body["measured"]["by_channel"]["control"]["bytes"] > 0
        assert body["measured"]["by_channel"]["events"]["bytes"] == sent

    def test_the_control_floor_is_measured_not_estimated_on_paper(
        self, client, registered_agent_id
    ):
        client.post(
            f"/api/agents/{registered_agent_id}/heartbeat",
            content=json.dumps(
                {"agent_instance_id": INSTANCE_ID, "sequence": 1}
            ).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                auth_service.AGENT_KEY_HEADER: client.issued_keys[registered_agent_id],
                WIRE_INSTANCE_HEADER: INSTANCE_ID,
            },
        )

        channels = client.get("/api/metrics/disclosure").json()["measured"]["by_channel"]

        assert set(channels) == set(wire_accounting.CHANNELS)
        assert channels["control"]["messages"] == 1

    def test_an_agent_without_accounting_falls_back_to_the_estimate(
        self, client, registered_agent_id
    ):
        # Fara antetul de incarnare octetii raman neatribuibili, deci canalul
        # masurat e gol. Metrica trebuie sa spuna „estimated", nu sa publice
        # zero ca numarator.
        client.post(
            "/api/events",
            json={
                "agent_id": registered_agent_id,
                "event_type": "file_created",
                "file_path": "C:/tmp/a.bin",
                "sha256": "a" * 64,
                "hash_status": "ok",
                "file_size": 4096,
            },
        )

        body = client.get("/api/metrics/disclosure").json()

        assert body["progressive"]["numerator_source"] == "estimated"
        assert body["progressive"]["total_bytes"] > 0
