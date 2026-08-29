"""
Teste pentru reconcilierea agent↔server (pasul 1.3b.5).
========================================================

Contabilizarea de la 1.3b.4 spune cât a primit serverul. Reconcilierea răspunde
la întrebarea de dedesubt: **poate fi crezută cifra?** METRICS.md §7.2 pune
răspunsul sub forma unei încadrări, nu a unei diferențe:

    delivered_raportat  ≤  primit_de_server  ≤  attempted_raportat

Cele două margini rupte înseamnă lucruri diferite și de aceea nu se contopesc
niciodată într-o valoare absolută. Marginea de sus ruptă e cazul grav: serverul
a primit mai mult decât a trimis agentul, adică ori cineva trimite în numele
lui, ori există un canal necontabilizat.

Testul care contează cel mai mult e
`test_the_enrollment_hole_shows_up_as_a_broken_lower_bound`. El reproduce
edr-agent#19 — o violare reală, permanentă, de mărime și cauză cunoscute. Dacă
metrica n-o vede, metrica e greșită, iar restul testelor de aici verifică doar
că aritmetica se adună.
"""

import json

import pytest

from app.services import auth_service, wire_accounting
from app.wire_middleware import (
    WIRE_ATTEMPTED_HEADER,
    WIRE_DELIVERED_HEADER,
    WIRE_INSTANCE_HEADER,
)


INSTANCE_ID = "incarnare-de-test"


def _event_body(agent_id: str, client_event_id: str = "ev-1") -> bytes:
    payload = {
        "client_event_id": client_event_id,
        "agent_id": agent_id,
        "agent_instance_id": INSTANCE_ID,
        "event_type": "agent_startup",
        "occurred_at": "2026-01-01T00:00:00+00:00",
    }
    return json.dumps(payload).encode("utf-8")


def _headers(agent_key, attempted=None, delivered=None, instance_id=INSTANCE_ID):
    headers = {
        "Content-Type": "application/json",
        auth_service.AGENT_KEY_HEADER: agent_key,
        WIRE_INSTANCE_HEADER: instance_id,
    }

    if attempted is not None:
        headers[WIRE_ATTEMPTED_HEADER] = str(attempted)
    if delivered is not None:
        headers[WIRE_DELIVERED_HEADER] = str(delivered)

    return headers


def _row(agent_id=None):
    report = wire_accounting.reconciliation(agent_id=agent_id)
    assert report["incarnations"], "Nicio incarnare contabilizata."
    return report["incarnations"][0]


def _send_two(client, agent_id, attempted, delivered):
    """
    Trimite doua cereri; a doua poarta raportul care va fi comparat.

    Prima exista ca sa produca o masuratoare nenula: raportul celei de-a doua se
    compara cu cat masurase serverul INAINTE de ea, adica exact cu prima.
    """
    key = client.issued_keys[agent_id]
    first = _event_body(agent_id, "ev-1")
    second = _event_body(agent_id, "ev-2")

    client.post("/api/events", content=first, headers=_headers(key, 0, 0))
    client.post(
        "/api/events", content=second, headers=_headers(key, attempted, delivered)
    )

    return len(first)


class TestTheThreeStates:
    def test_a_clean_exchange_stays_within_bounds(self, client, registered_agent_id):
        # Agent onest, fara nimic in zbor: cele doua margini se inchid exact
        # peste masuratoare, deci ambele diferente sunt zero. Un zero exact e o
        # afirmatie mai puternica decat o inegalitate — arata ca reconcilierea
        # compara perechea corecta, nu doua cifre care se intampla sa incapa.
        _send_two(client, registered_agent_id, attempted=None, delivered=None)

        key = client.issued_keys[registered_agent_id]
        total_before = wire_accounting.account_for(
            registered_agent_id, INSTANCE_ID
        ).received_bytes

        client.post(
            "/api/events",
            content=_event_body(registered_agent_id, "ev-3"),
            headers=_headers(key, attempted=total_before, delivered=total_before),
        )

        row = _row()
        assert row["verdict"] == wire_accounting.VERDICT_WITHIN
        assert row["delivered_over_received"] == 0
        assert row["received_over_attempted"] == 0
        assert total_before > 0

    def test_the_server_receiving_more_than_reported_is_the_grave_direction(
        self, client, registered_agent_id
    ):
        # Serverul a masurat mai mult decat declara agentul ca a trimis. Ori
        # cineva trimite in numele lui, ori exista un canal necontabilizat.
        _send_two(client, registered_agent_id, attempted=1, delivered=1)

        row = _row()
        assert row["verdict"] == wire_accounting.VERDICT_ABOVE
        assert row["received_over_attempted"] > 0

    def test_the_agent_claiming_more_delivered_than_received_breaks_the_lower_bound(
        self, client, registered_agent_id
    ):
        measured = _send_two(
            client, registered_agent_id, attempted=10_000, delivered=10_000
        )

        row = _row()
        assert row["verdict"] == wire_accounting.VERDICT_BELOW
        assert row["delivered_over_received"] == 10_000 - measured

    def test_an_agent_that_has_not_reported_yet_is_not_a_violation(
        self, client, registered_agent_id
    ):
        # Un agent vechi, sau unul aflat la prima cerere, nu e o problema — e o
        # stare de tranzitie. Contopita cu violarile, ar umple raportul cu
        # zgomot exact cand parcul se actualizeaza.
        key = client.issued_keys[registered_agent_id]

        client.post(
            "/api/events",
            content=_event_body(registered_agent_id),
            headers=_headers(key),
        )

        row = _row()
        assert row["verdict"] == wire_accounting.VERDICT_UNREPORTED
        assert row["delivered_over_received"] is None


class TestTheKnownHole:
    def test_the_enrollment_hole_shows_up_as_a_broken_lower_bound(
        self, client, registered_agent_id
    ):
        """
        edr-agent#19, vazut prin metrica.

        Agentul contorizeaza inrolarea pe canalul `enrollment`, iar anteturile
        poarta totalul peste canale. Serverul pune octetii aceia in galeata
        `no_instance`, care nu e tinuta pe incarnare. Deci prima cerere cu
        incarnare declarata raporteaza octeti livrati pe care contul incarnarii
        nu i-a vazut niciodata.

        Nu e slack tolerabil: e marginea de jos rupta, din prima cerere a
        fiecarei incarnari, permanent.
        """
        enrollment_bytes = 300
        key = client.issued_keys[registered_agent_id]

        client.post(
            "/api/events",
            content=_event_body(registered_agent_id),
            headers=_headers(key, attempted=enrollment_bytes, delivered=enrollment_bytes),
        )

        row = _row()
        assert row["verdict"] == wire_accounting.VERDICT_BELOW
        assert row["compared_against_received_bytes"] == 0
        assert row["delivered_over_received"] == enrollment_bytes


class TestWhatTheRowSays:
    def test_the_undelivered_gap_is_what_left_into_nothing(
        self, client, registered_agent_id
    ):
        # Nu o discrepanta, ci volumul plecat fara raspuns, dupa propriile
        # contoare ale agentului. El explica o parte din jocul dintre margini.
        _send_two(client, registered_agent_id, attempted=900, delivered=400)

        assert _row()["reported_undelivered_bytes"] == 500

    def test_the_comparison_uses_the_measurement_that_preceded_the_report(
        self, client, registered_agent_id
    ):
        measured = _send_two(client, registered_agent_id, attempted=0, delivered=0)
        row = _row()

        # Totalul de acum include si cererea care a adus raportul; cifra
        # comparata e cea de dinaintea ei.
        assert row["compared_against_received_bytes"] == measured
        assert row["received_bytes"] > measured

    def test_a_malformed_report_is_visible_in_the_row(
        self, client, registered_agent_id
    ):
        key = client.issued_keys[registered_agent_id]

        client.post(
            "/api/events",
            content=_event_body(registered_agent_id),
            headers=_headers(key, attempted="nu-e-numar", delivered="nici-asta"),
        )

        row = _row()
        assert row["malformed_reports"] == 1
        assert row["verdict"] == wire_accounting.VERDICT_UNREPORTED


class TestScope:
    def test_filtering_by_agent_keeps_the_unattributable_bucket_whole(
        self, client, registered_agent_id
    ):
        # Octetii de acolo n-au proprietar prin definitie. Un raport filtrat
        # care i-ar ascunde ar sugera ca pentru agentul acela nu exista trafic
        # necontabilizat, ceea ce nu se poate sti.
        client.post("/api/events", content=b"{}", headers={"Content-Type": "application/json"})

        report = wire_accounting.reconciliation(agent_id=registered_agent_id)

        assert report["scope"] == registered_agent_id
        assert report["unattributable"]["scope"] == "all_agents"
        # Doua, nu una: inrolarea din fixture nu poarta nici ea cheie de agent,
        # pentru ca aceea abia urmeaza sa fie emisa.
        assert report["unattributable"]["reasons"]["no_key"]["messages"] == 2

    def test_every_verdict_appears_in_the_summary_even_at_zero(self, client):
        verdicts = wire_accounting.reconciliation()["verdicts"]

        assert set(verdicts) == set(wire_accounting.VERDICTS)
        assert all(count == 0 for count in verdicts.values())


class TestTheRoute:
    def test_the_disclosure_metric_carries_the_reconciliation(
        self, client, registered_agent_id
    ):
        _send_two(client, registered_agent_id, attempted=10_000, delivered=10_000)

        body = client.get("/api/metrics/disclosure").json()

        assert "reconciliation" in body
        assert (
            body["reconciliation"]["verdicts"][wire_accounting.VERDICT_BELOW] == 1
        )

    def test_the_route_passes_the_agent_filter_down(self, client, registered_agent_id):
        _send_two(client, registered_agent_id, attempted=0, delivered=0)

        body = client.get(
            "/api/metrics/disclosure", params={"agent_id": "alt-agent"}
        ).json()

        assert body["reconciliation"]["scope"] == "alt-agent"
        assert body["reconciliation"]["incarnations"] == []
