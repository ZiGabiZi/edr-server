"""
Teste pentru contabilizarea octeților primiți (pasul 1.3b.4).
=============================================================

Testul care justifică tot mecanismul e cel cu cheia necunoscută. O cerere cu
cheie greșită e respinsă cu 401 de dependency-ul de autentificare și nu ajunge
niciodată la ruta de evenimente — dar octeții ei au părăsit endpoint-ul, au
traversat rețeaua și au ajuns aici. Cu numărătoare în rute ar fi dispărut din
contabilitate exact traficul care contează cel mai mult: un agent cu credențiale
stricate care trimite ore în șir divulgă tot ce trimite, fără să scrie nimic
nicăieri.

Restul testelor apără disciplina care face cifra utilizabilă: fiecare octet
primit ajunge într-o găleată cu motiv, raportul agentului se compară cu
măsurătoarea de dinaintea cererii care l-a adus, iar un raport stricat pierde
raportul, nu octeții.

Corpurile se trimit cu `content=`, nu cu `json=`, ca dimensiunea să fie fixată
de test, nu de felul în care serializează httpx în versiunea instalată.
"""

import json

import pytest
from starlette.datastructures import Headers

from app.services import auth_service, wire_accounting
from app.wire_middleware import (
    WIRE_ATTEMPTED_HEADER,
    WIRE_DELIVERED_HEADER,
    WIRE_INSTANCE_HEADER,
    account_for_request,
)


INSTANCE_ID = "incarnare-de-test"

JSON_HEADERS = {"Content-Type": "application/json"}


def _event_body(agent_id: str, client_event_id: str = "ev-1") -> bytes:
    payload = {
        "client_event_id": client_event_id,
        "agent_id": agent_id,
        "agent_instance_id": INSTANCE_ID,
        "event_type": "agent_startup",
        "occurred_at": "2026-01-01T00:00:00+00:00",
    }
    return json.dumps(payload).encode("utf-8")


def _headers(agent_key=None, instance_id=INSTANCE_ID, attempted=None, delivered=None):
    headers = dict(JSON_HEADERS)

    if agent_key is not None:
        headers[auth_service.AGENT_KEY_HEADER] = agent_key
    if instance_id is not None:
        headers[WIRE_INSTANCE_HEADER] = instance_id
    if attempted is not None:
        headers[WIRE_ATTEMPTED_HEADER] = attempted
    if delivered is not None:
        headers[WIRE_DELIVERED_HEADER] = delivered

    return headers


def _unattributable(reason: str) -> dict:
    return wire_accounting.snapshot()["unattributable"][reason]


class TestAttributedTraffic:
    def test_a_post_with_key_and_incarnation_is_attributed(
        self, client, registered_agent_id
    ):
        body = _event_body(registered_agent_id)
        key = client.issued_keys[registered_agent_id]

        response = client.post("/api/events", content=body, headers=_headers(key))

        assert response.status_code == 200, response.text
        account = wire_accounting.account_for(registered_agent_id, INSTANCE_ID)
        assert account is not None
        assert account.received_bytes == len(body)
        assert account.received_messages == 1

    def test_the_measured_size_is_the_body_not_the_headers(
        self, client, registered_agent_id
    ):
        # METRICS.md par. 1.2: anteturile HTTP sunt cost de transport, identic
        # sub ambele politici, deci s-ar aduna la fel in numarator si numitor.
        # Aceeasi cerere cu un antet suplimentar lung trebuie sa masoare la fel.
        body = _event_body(registered_agent_id)
        key = client.issued_keys[registered_agent_id]
        headers = _headers(key)
        headers["X-Long-Irrelevant-Header"] = "x" * 500

        client.post("/api/events", content=body, headers=headers)

        account = wire_accounting.account_for(registered_agent_id, INSTANCE_ID)
        assert account.received_bytes == len(body)

    def test_two_incarnations_of_the_same_agent_are_counted_apart(
        self, client, registered_agent_id
    ):
        # Contoarele agentului repornesc de la zero la fiecare pornire. Cu o
        # cheie doar pe agent_id, repornirea ar arata ca o discrepanta grava.
        key = client.issued_keys[registered_agent_id]
        first = _event_body(registered_agent_id, "ev-1")
        second = _event_body(registered_agent_id, "ev-2")

        client.post("/api/events", content=first, headers=_headers(key))
        client.post(
            "/api/events",
            content=second,
            headers=_headers(key, instance_id="a-doua-incarnare"),
        )

        assert (
            wire_accounting.account_for(registered_agent_id, INSTANCE_ID).received_bytes
            == len(first)
        )
        assert (
            wire_accounting.account_for(
                registered_agent_id, "a-doua-incarnare"
            ).received_bytes
            == len(second)
        )


class TestTrafficThatNeverReachesARoute:
    def test_a_request_with_an_unknown_key_is_counted_anyway(
        self, client, registered_agent_id
    ):
        # Motivul pentru care contabilizarea sta in middleware si nu in rute.
        body = _event_body(registered_agent_id)

        response = client.post(
            "/api/events", content=body, headers=_headers("cheie-inventata")
        )

        assert response.status_code == 401
        counters = _unattributable(wire_accounting.UNATTRIBUTABLE_UNKNOWN_KEY)
        assert counters["messages"] == 1
        assert counters["bytes"] == len(body)

    def test_a_request_without_a_key_is_counted_as_no_key(self, client):
        body = _event_body("agent-necunoscut")

        response = client.post("/api/events", content=body, headers=dict(JSON_HEADERS))

        assert response.status_code == 401
        assert _unattributable(wire_accounting.UNATTRIBUTABLE_NO_KEY)["bytes"] == len(body)

    def test_a_request_refused_by_the_schema_is_still_counted(
        self, client, registered_agent_id
    ):
        # 422: corpul e stricat, dar a ajuns. Ce a plecat de pe endpoint a
        # plecat, indiferent daca serverul a putut face ceva cu el.
        body = b'{"agent_id": "agent-1"}'
        key = client.issued_keys[registered_agent_id]

        response = client.post("/api/events", content=body, headers=_headers(key))

        assert response.status_code == 422
        account = wire_accounting.account_for(registered_agent_id, INSTANCE_ID)
        assert account.received_bytes == len(body)


class TestNothingDisappears:
    def test_a_first_enrollment_lands_in_no_key(self, client):
        # O inrolare se autentifica cu secretul de inrolare, nu cu o cheie de
        # agent — aceea abia urmeaza sa fie emisa. Deci nu e cheie de cautat, si
        # motivul corect e no_key, nu unknown_key: nimeni n-a prezentat nimic
        # gresit.
        response = client.post(
            "/api/agents/register",
            json={
                "agent_id": "agent-nou",
                "hostname": "HOST",
                "operating_system": "windows",
                "architecture": "x64",
                "os_architecture": "x64",
                "machine_id_type": "hash",
                "machine_id_hash": "hash-agent-nou",
            },
        )

        assert response.status_code == 200, response.text
        assert _unattributable(wire_accounting.UNATTRIBUTABLE_NO_KEY)["messages"] == 1
        assert _unattributable(wire_accounting.UNATTRIBUTABLE_NO_KEY)["bytes"] > 0
        assert _unattributable(wire_accounting.UNATTRIBUTABLE_UNKNOWN_KEY)["messages"] == 0

    def test_a_reregistration_that_declares_its_incarnation_is_attributed(
        self, client, registered_agent_id
    ):
        # Contractul interzice agent_instance_id in CORPUL inregistrarii, dar
        # agentul il trimite pe antet (edr-agent#19). Antetul nu trece prin
        # schema, deci baseline-ul de repornire ramane neatins, iar octetii de
        # reinregistrare devin atribuibili.
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
            },
            headers={WIRE_INSTANCE_HEADER: INSTANCE_ID},
        )

        assert response.status_code == 200, response.text
        assert _unattributable(wire_accounting.UNATTRIBUTABLE_NO_INSTANCE)["messages"] == 0
        assert (
            wire_accounting.account_for(registered_agent_id, INSTANCE_ID).received_bytes
            > 0
        )

    def test_a_request_that_does_not_declare_an_incarnation_lands_in_no_instance(
        self, client, registered_agent_id
    ):
        # Regula generala ramane: agent cunoscut, incarnare nedeclarata. Azi o
        # produce un agent mai vechi decat antetul, nu inregistrarea.
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
            },
        )

        assert response.status_code == 200, response.text
        assert _unattributable(wire_accounting.UNATTRIBUTABLE_NO_INSTANCE)["messages"] == 1
        assert _unattributable(wire_accounting.UNATTRIBUTABLE_NO_INSTANCE)["bytes"] > 0

    def test_every_reason_appears_in_the_snapshot_even_at_zero(self, client):
        # Zero afirmat e verificabil; o cheie lipsa nu se distinge de un motiv
        # care n-a fost niciodata implementat.
        unattributable = wire_accounting.snapshot()["unattributable"]

        assert set(unattributable) == set(wire_accounting.UNATTRIBUTABLE_REASONS)
        for counters in unattributable.values():
            assert counters == {"messages": 0, "bytes": 0}

    def test_an_unknown_reason_raises_instead_of_opening_a_bucket(self):
        with pytest.raises(ValueError):
            wire_accounting.record_unattributable("motiv-inventat", 10)

    def test_a_get_request_carries_no_body_and_is_not_counted(self, client):
        client.get("/health")
        client.get("/api/events")

        snapshot = wire_accounting.snapshot()
        assert snapshot["incarnations"] == []
        assert all(
            counters["messages"] == 0 for counters in snapshot["unattributable"].values()
        )


class TestReportPairing:
    def test_the_report_is_paired_with_the_measurement_before_it(
        self, client, registered_agent_id
    ):
        # Anteturile poarta totalul de DINAINTEA cererii curente. Comparate cu
        # totalul masurat DUPA ce s-a adunat cererea, ar arata mereu o diferenta
        # egala cu mesajul curent — o discrepanta fabricata de propria noastra
        # ordine de operatii.
        key = client.issued_keys[registered_agent_id]
        first = _event_body(registered_agent_id, "ev-1")
        second = _event_body(registered_agent_id, "ev-2")

        client.post(
            "/api/events",
            content=first,
            headers=_headers(key, attempted="0", delivered="0"),
        )
        client.post(
            "/api/events",
            content=second,
            headers=_headers(key, attempted=str(len(first)), delivered=str(len(first))),
        )

        account = wire_accounting.account_for(registered_agent_id, INSTANCE_ID)
        assert account.received_bytes == len(first) + len(second)
        assert account.received_bytes_at_last_report == len(first)
        assert account.reported_attempted_bytes == len(first)
        assert account.reported_delivered_bytes == len(first)

    def test_the_sandwich_holds_on_a_clean_exchange(self, client, registered_agent_id):
        # METRICS.md par. 7.2: delivered raportat <= primit de server <=
        # attempted raportat, socotite inaintea cererii curente.
        key = client.issued_keys[registered_agent_id]
        first = _event_body(registered_agent_id, "ev-1")
        second = _event_body(registered_agent_id, "ev-2")

        client.post(
            "/api/events",
            content=first,
            headers=_headers(key, attempted="0", delivered="0"),
        )
        client.post(
            "/api/events",
            content=second,
            headers=_headers(key, attempted=str(len(first)), delivered=str(len(first))),
        )

        account = wire_accounting.account_for(registered_agent_id, INSTANCE_ID)
        assert (
            account.reported_delivered_bytes
            <= account.received_bytes_at_last_report
            <= account.reported_attempted_bytes
        )

    def test_a_malformed_report_loses_the_report_not_the_bytes(
        self, client, registered_agent_id
    ):
        body = _event_body(registered_agent_id)
        key = client.issued_keys[registered_agent_id]

        client.post(
            "/api/events",
            content=body,
            headers=_headers(key, attempted="nu-e-numar", delivered="-5"),
        )

        account = wire_accounting.account_for(registered_agent_id, INSTANCE_ID)
        assert account.received_bytes == len(body)
        assert account.reported_attempted_bytes is None
        assert account.malformed_reports == 1

    def test_an_agent_that_reports_nothing_is_not_counted_as_broken(
        self, client, registered_agent_id
    ):
        # Un agent vechi, fara anteturi de raportare, nu e acelasi lucru cu unul
        # care trimite gunoi. Primul nu stie sa raporteze, al doilea are un bug.
        body = _event_body(registered_agent_id)
        key = client.issued_keys[registered_agent_id]

        client.post("/api/events", content=body, headers=_headers(key))

        account = wire_accounting.account_for(registered_agent_id, INSTANCE_ID)
        assert account.malformed_reports == 0
        assert account.reported_attempted_bytes is None


class _FakeRequest:
    """
    Cerere minimală, pentru cazurile pe care un client HTTP real nu le produce.

    `Headers` din starlette, nu un dicționar: căutarea antetelor e insensibilă la
    majuscule, iar un dicționar simplu ar face testul să treacă din motive care
    n-au legătură cu codul testat.
    """

    def __init__(self, method: str = "POST", headers: dict | None = None) -> None:
        self.method = method
        self.headers = Headers(headers or {})


class TestSizeless:
    """
    Corpuri fără `Content-Length` — cazul pe care nu-l poate produce TestClient.

    Middleware-ul nu citește corpul, deliberat: ar consuma fluxul așteptat de
    ruta de după el. Deci nu are de unde ști cât cântărește o cerere care nu-și
    declară dimensiunea. Fără găleata `unsized`, mesajul acela ar dispărea
    complet; cu ea, se vede că a fost, chiar dacă nu se știe cât.
    """

    def test_a_body_without_content_length_is_counted_as_unsized(self, client):
        account_for_request(_FakeRequest(headers={"X-Agent-Key": "orice"}))

        counters = _unattributable(wire_accounting.UNATTRIBUTABLE_UNSIZED)
        assert counters["messages"] == 1
        # Zero pentru ca dimensiunea e NECUNOSCUTA, nu pentru ca ar fi zero.
        # De asta are motiv propriu: numarul de mesaje spune ca acolo lipsesc
        # octeti, in loc sa lase impresia ca nu erau.
        assert counters["bytes"] == 0

    def test_a_malformed_content_length_is_treated_as_missing(self, client):
        account_for_request(_FakeRequest(headers={"Content-Length": "nu-e-numar"}))

        assert _unattributable(wire_accounting.UNATTRIBUTABLE_UNSIZED)["messages"] == 1

    def test_an_empty_body_is_not_counted_at_all(self, client):
        account_for_request(_FakeRequest(headers={"Content-Length": "0"}))

        snapshot = wire_accounting.snapshot()
        assert all(
            counters["messages"] == 0 for counters in snapshot["unattributable"].values()
        )

    def test_a_method_without_a_body_is_skipped_before_anything_else(self, client):
        account_for_request(_FakeRequest(method="GET", headers={"Content-Length": "10"}))

        snapshot = wire_accounting.snapshot()
        assert all(
            counters["messages"] == 0 for counters in snapshot["unattributable"].values()
        )


class TestParsing:
    @pytest.mark.parametrize("raw", [None, "", "  ", "abc", "-1", "1.5"])
    def test_unusable_report_values_become_none(self, raw):
        assert wire_accounting.parse_reported_bytes(raw) is None

    @pytest.mark.parametrize("raw,expected", [("0", 0), ("42", 42), (" 42 ", 42)])
    def test_usable_report_values_are_parsed(self, raw, expected):
        assert wire_accounting.parse_reported_bytes(raw) == expected
