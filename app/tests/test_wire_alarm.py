"""
Teste pentru alarma de discrepanță (ultimul pas din 1.3b).
===========================================================

Alarma asta nu seamănă cu cea de autentificare, și testele arată de ce.
`AuthFailureAlarm` numără eșecuri consecutive — are evenimente discrete de
numărat. Discrepanța n-are niciun eveniment: e o diferență între două numere
care se compară abia când sosește o cerere nouă. Nu eșuează nimic; pur și simplu
două contoare nu se potrivesc.

De aceea ce se testează aici e altceva: **pragul** (relativ, cu două condiții
simultane), **direcțiile** (semnate și cu sensibilități diferite), și
**limitarea emiterii** (o dată la interval, per încarnare și per direcție).

Cel mai important test e
`test_the_first_enrollment_residue_stays_below_the_threshold`. Reziduul cunoscut
din §7.5 rupe marginea de jos la fiecare mașină nouă. Dacă alarma ar suna pentru
el, ar suna pentru fiecare instalare — iar o alarmă care sună mereu nu mai e o
alarmă, e o linie de log pe care înveți s-o filtrezi.
"""

import pytest

from app.services import wire_accounting
from app.services.wire_accounting import IncarnationAccount
from app.services.wire_alarm import WireDiscrepancyAlarm


class FakeClock:
    """Ceas controlat de test, ca la AuthFailureAlarm."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _account(
    received_bytes: int,
    received_messages: int,
    reported_attempted: int,
    reported_delivered: int,
    at_last_report: int,
) -> IncarnationAccount:
    return IncarnationAccount(
        received_bytes=received_bytes,
        received_messages=received_messages,
        reported_attempted_bytes=reported_attempted,
        reported_delivered_bytes=reported_delivered,
        received_bytes_at_last_report=at_last_report,
    )


class TestTheThreshold:
    def test_a_gap_of_one_message_does_not_breach(self):
        # O cerere in zbor produce mereu o diferenta mica si legitima.
        account = _account(
            received_bytes=10_000,
            received_messages=100,  # tipic: 100 de octeti
            reported_attempted=10_100,
            reported_delivered=10_100,
            at_last_report=10_000,
        )

        assert wire_accounting.threshold_breach(account) is None

    def test_a_gap_over_both_conditions_breaches(self):
        # Peste 3 mesaje tipice (300) SI peste 5% din volumul masurat (500).
        account = _account(
            received_bytes=10_000,
            received_messages=100,
            reported_attempted=11_000,
            reported_delivered=11_000,
            at_last_report=10_000,
        )

        breach = wire_accounting.threshold_breach(account)

        assert breach["verdict"] == wire_accounting.VERDICT_BELOW
        assert breach["gap_bytes"] == 1_000

    def test_both_conditions_must_hold_at_once(self):
        # Gol de 400: peste cele 3 mesaje tipice (300), dar sub 5% din volum
        # (500). Un prag cu SAU ar suna aici; cu SI, nu.
        account = _account(
            received_bytes=10_000,
            received_messages=100,
            reported_attempted=10_400,
            reported_delivered=10_400,
            at_last_report=10_000,
        )

        assert wire_accounting.threshold_breach(account) is None

    def test_a_quiet_agent_is_not_alarmed_by_a_tiny_absolute_gap(self):
        # Acelasi gol de 400 la un agent care a trimis putin: 5% din 1000 e 50,
        # deci conditia de volum e depasita — dar mesajele lui sunt mari, iar
        # conditia de mesaj tipic il apara. Un prag absolut ar fi sunat.
        account = _account(
            received_bytes=1_000,
            received_messages=2,  # tipic: 500 de octeti
            reported_attempted=1_400,
            reported_delivered=1_400,
            at_last_report=1_000,
        )

        assert wire_accounting.threshold_breach(account) is None

    def test_nothing_is_evaluated_before_the_first_message(self):
        # Fara mesaje nu exista dimensiune tipica, iar o valoare implicita
        # ghicita ar deveni pragul.
        assert wire_accounting.typical_message_bytes(IncarnationAccount()) is None
        assert wire_accounting.threshold_breach(IncarnationAccount()) is None

    def test_an_agent_that_has_not_reported_cannot_breach(self):
        account = IncarnationAccount(received_bytes=10_000, received_messages=100)

        assert wire_accounting.threshold_breach(account) is None


class TestTheDirectionsAreNotSymmetric:
    def _gap_needed(self, verdict_over: str, gap: int) -> IncarnationAccount:
        base = dict(
            received_bytes=100_000,
            received_messages=1_000,  # tipic: 100 de octeti
            at_last_report=100_000,
        )

        if verdict_over == wire_accounting.VERDICT_ABOVE:
            # Serverul a masurat mai mult decat declara agentul ca a trimis.
            return _account(
                reported_attempted=100_000 - gap,
                reported_delivered=100_000 - gap,
                **base,
            )

        return _account(
            reported_attempted=100_000 + gap, reported_delivered=100_000 + gap, **base
        )

    def test_the_grave_direction_fires_at_a_smaller_gap(self):
        # 2000 de octeti: peste 1% (1000) dar sub 5% (5000).
        above = wire_accounting.threshold_breach(
            self._gap_needed(wire_accounting.VERDICT_ABOVE, 2_000)
        )
        below = wire_accounting.threshold_breach(
            self._gap_needed(wire_accounting.VERDICT_BELOW, 2_000)
        )

        assert above is not None
        assert above["verdict"] == wire_accounting.VERDICT_ABOVE
        # Aceeasi marime a golului, in cealalta directie, nu ajunge la prag.
        assert below is None

    def test_the_tolerant_direction_still_fires_when_large_enough(self):
        below = wire_accounting.threshold_breach(
            self._gap_needed(wire_accounting.VERDICT_BELOW, 10_000)
        )

        assert below is not None
        assert below["verdict"] == wire_accounting.VERDICT_BELOW


class TestTheKnownResidue:
    def test_the_first_enrollment_residue_stays_below_the_threshold(self):
        # Reziduul din par. 7.5: la prima inrolare a unei masini, octetii de
        # inregistrare raman in no_key, dar agentul ii numara in totalul
        # raportat. Golul e de un mesaj.
        #
        # Daca alarma ar suna pentru el, ar suna la fiecare instalare de agent.
        # De asta s-a inchis edr-agent#19 INAINTE de a calibra pragul: cu golul
        # la fiecare incarnare, pragul ar fi trebuit largit ca sa-l tolereze, si
        # ar fi ramas prea larg dupa.
        enrollment_bytes = 300
        account = _account(
            received_bytes=10_000,
            received_messages=50,  # tipic: 200 de octeti
            reported_attempted=10_000 + enrollment_bytes,
            reported_delivered=10_000 + enrollment_bytes,
            at_last_report=10_000,
        )

        assert wire_accounting.threshold_breach(account) is None


class TestEmission:
    def _breaching(self) -> IncarnationAccount:
        return _account(
            received_bytes=10_000,
            received_messages=100,
            reported_attempted=20_000,
            reported_delivered=20_000,
            at_last_report=10_000,
        )

    def test_a_breach_is_emitted_once_and_then_held(self):
        clock = FakeClock()
        alarm = WireDiscrepancyAlarm(repeat_alarm_seconds=300.0, clock=clock)
        account = self._breaching()

        assert alarm.observe("agent-1", "inc-1", account) is not None
        # Verificarea se face la fiecare cerere; emiterea, nu. Un log care se
        # repeta la nesfarsit e un log pe care inveti sa-l filtrezi.
        assert alarm.observe("agent-1", "inc-1", account) is None

    def test_the_alarm_speaks_again_after_the_interval(self):
        clock = FakeClock()
        alarm = WireDiscrepancyAlarm(repeat_alarm_seconds=300.0, clock=clock)
        account = self._breaching()

        alarm.observe("agent-1", "inc-1", account)
        clock.advance(299.0)
        assert alarm.observe("agent-1", "inc-1", account) is None
        clock.advance(2.0)
        assert alarm.observe("agent-1", "inc-1", account) is not None

    def test_the_other_direction_is_news_not_a_repeat(self):
        # Daca o incarnare trece de la o margine la cealalta, a doua trebuie
        # spusa imediat: directiile nu se acopera una pe alta.
        clock = FakeClock()
        alarm = WireDiscrepancyAlarm(repeat_alarm_seconds=300.0, clock=clock)

        alarm.observe("agent-1", "inc-1", self._breaching())
        flipped = _account(
            received_bytes=10_000,
            received_messages=100,
            reported_attempted=1_000,
            reported_delivered=1_000,
            at_last_report=10_000,
        )

        breach = alarm.observe("agent-1", "inc-1", flipped)

        assert breach is not None
        assert breach["verdict"] == wire_accounting.VERDICT_ABOVE

    def test_each_incarnation_is_rate_limited_on_its_own(self):
        clock = FakeClock()
        alarm = WireDiscrepancyAlarm(repeat_alarm_seconds=300.0, clock=clock)
        account = self._breaching()

        assert alarm.observe("agent-1", "inc-1", account) is not None
        assert alarm.observe("agent-1", "inc-2", account) is not None

    def test_a_healthy_incarnation_never_emits(self):
        clock = FakeClock()
        alarm = WireDiscrepancyAlarm(clock=clock)
        healthy = _account(
            received_bytes=10_000,
            received_messages=100,
            reported_attempted=10_000,
            reported_delivered=10_000,
            at_last_report=10_000,
        )

        assert alarm.observe("agent-1", "inc-1", healthy) is None

    def test_the_alarm_logs_at_error_level(self, caplog):
        clock = FakeClock()
        alarm = WireDiscrepancyAlarm(clock=clock)

        with caplog.at_level("ERROR"):
            alarm.observe("agent-1", "inc-1", self._breaching())

        assert any(record.levelname == "ERROR" for record in caplog.records)
        assert "agent-1" in caplog.text


class TestTheMetricAgrees:
    def test_the_breach_shows_up_in_the_reconciliation_row(self, client):
        # Alarma si metrica folosesc aceeasi functie de prag. Daca ar avea
        # praguri separate, log-ul si /api/metrics/disclosure ar putea spune
        # lucruri diferite despre aceeasi incarnare.
        wire_accounting.record_attributed(
            agent_id="agent-1",
            agent_instance_id="inc-1",
            byte_count=10_000,
            channel=wire_accounting.CHANNEL_EVENTS,
            reported_attempted=0,
            reported_delivered=0,
        )
        wire_accounting.record_attributed(
            agent_id="agent-1",
            agent_instance_id="inc-1",
            byte_count=100,
            channel=wire_accounting.CHANNEL_EVENTS,
            reported_attempted=50_000,
            reported_delivered=50_000,
        )

        report = wire_accounting.reconciliation()
        row = report["incarnations"][0]

        assert row["threshold_breach"] is not None
        assert row["threshold_breach"]["verdict"] == wire_accounting.VERDICT_BELOW
        assert report["threshold_breaches"] == 1

    def test_a_broken_bound_below_the_threshold_is_reported_but_not_a_breach(
        self, client
    ):
        # Distinctia care face metrica utilizabila: incadrarea e rupta, dar
        # ruptura e cat zgomotul cererilor in zbor. Verdictul o arata, pragul nu.
        wire_accounting.record_attributed(
            agent_id="agent-1",
            agent_instance_id="inc-1",
            byte_count=10_000,
            channel=wire_accounting.CHANNEL_EVENTS,
            reported_attempted=0,
            reported_delivered=0,
        )
        wire_accounting.record_attributed(
            agent_id="agent-1",
            agent_instance_id="inc-1",
            byte_count=100,
            channel=wire_accounting.CHANNEL_EVENTS,
            reported_attempted=10_050,
            reported_delivered=10_050,
        )

        row = wire_accounting.reconciliation()["incarnations"][0]

        assert row["verdict"] == wire_accounting.VERDICT_BELOW
        assert row["threshold_breach"] is None
