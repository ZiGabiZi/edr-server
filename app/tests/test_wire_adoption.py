"""
Teste pentru adopția unei încarnări prinse din mers (edr-server#11).
====================================================================

Cazul care le-a impus: **serverul repornește, agentul nu.** Contabilizarea
trăiește în memoria procesului, deci încarnarea dispare de pe server — dar
contoarele agentului sunt per încarnare, nu per conexiune, și cresc mai departe.
Prima cerere de după repornire aduce un total mare lângă un cont cu zero măsurat.

Comparat direct, golul e tot ce a trimis agentul până atunci, iar alarma sună
pentru fiecare agent care rulează, după fiecare deploy. Exact zgomotul pe care
alarma trebuia să-l prevină.

E oglinda unei probleme deja rezolvate. Repornirea **agentului** e tratată:
încarnare nouă înseamnă contoare pornite de la zero pe ambele părți simultan.
Repornirea **serverului** resetează doar o parte, deci diferența trebuie scoasă
din comparație explicit.

Ce apără testele de aici, în ordinea în care ar face rău dacă ar ceda:

    1. Adopția nu lasă alarma să sune pentru ce n-a apucat serverul să măsoare.
    2. Adopția NU se aplică unei încarnări care chiar începe acum — altfel am
       ascunde începutul real al unei încarnări văzute de la capăt.
    3. După adopție, încadrarea se închide pe creșteri, deci o discrepanță
       reală tot se vede.
    4. Cât s-a pierdut se raportează. Fără cifra aceea am fi înlocuit o alarmă
       falsă cu o tăcere falsă.
"""

from app.services import wire_accounting
from app.services.wire_accounting import IncarnationAccount
from app.services.wire_alarm import WireDiscrepancyAlarm


AGENT = "endpoint-01"
INCARNATION = "incarnare-care-a-supravietuit"


def _post(byte_count: int, attempted=None, delivered=None) -> None:
    wire_accounting.record_attributed(
        agent_id=AGENT,
        agent_instance_id=INCARNATION,
        byte_count=byte_count,
        channel=wire_accounting.CHANNEL_EVENTS,
        reported_attempted=attempted,
        reported_delivered=delivered,
    )


def _account() -> IncarnationAccount:
    account = wire_accounting.account_for(AGENT, INCARNATION)
    assert account is not None
    return account


class TestTheServerRestart:
    def test_a_survivor_does_not_trip_the_alarm_on_its_first_request(self, client):
        # Scenariul din issue: agentul a trimis deja 50 KB, serverul a repornit
        # si nu stie nimic despre incarnarea asta.
        _post(400, attempted=50_000, delivered=50_000)

        account = _account()
        assert wire_accounting.reconcile(account)["verdict"] == (
            wire_accounting.VERDICT_WITHIN
        )
        assert wire_accounting.threshold_breach(account) is None

    def test_the_alarm_stays_silent_for_a_survivor(self, client):
        alarm = WireDiscrepancyAlarm()
        _post(400, attempted=50_000, delivered=50_000)

        assert alarm.observe(AGENT, INCARNATION, _account()) is None

    def test_the_lost_prefix_is_reported_not_swallowed(self, client):
        # Fara cifra asta, „am prins incarnarea tarziu" si „totul se potriveste"
        # ar arata identic. Octetii aceia sunt divulgare reala pe care ACEST
        # server n-a masurat-o.
        _post(400, attempted=50_000, delivered=50_000)

        report = wire_accounting.reconciliation()
        row = report["incarnations"][0]

        assert row["adoption"]["adopted_mid_flight"] is True
        assert row["adoption"]["unmeasured_before_adoption_bytes"] == 50_000
        assert report["adopted_mid_flight"] == 1
        assert report["unmeasured_before_adoption_bytes"] == 50_000


class TestAdoptionDoesNotHideRealProblems:
    def test_growth_after_adoption_is_compared_exactly(self, client):
        # Dupa adoptie, comparatia se face pe cresteri. O incarnare sanatoasa
        # inchide incadrarea exact, la zero, ca si cum serverul ar fi masurat-o
        # de la inceput.
        _post(400, attempted=50_000, delivered=50_000)
        _post(600, attempted=50_400, delivered=50_400)

        comparison = wire_accounting.reconcile(_account())
        assert comparison["verdict"] == wire_accounting.VERDICT_WITHIN
        assert comparison["delivered_over_received"] == 0
        assert comparison["received_over_attempted"] == 0

    def test_a_real_discrepancy_after_adoption_is_still_caught(self, client):
        # Agentul sustine ca a livrat cu 20 KB mai mult decat a primit serverul,
        # DUPA adoptie. Aceea nu mai e o parte pierduta, e o nepotrivire.
        _post(400, attempted=50_000, delivered=50_000)
        _post(600, attempted=70_000, delivered=70_000)

        account = _account()
        assert wire_accounting.reconcile(account)["verdict"] == (
            wire_accounting.VERDICT_BELOW
        )
        assert wire_accounting.threshold_breach(account) is not None

    def test_the_grave_direction_survives_adoption_too(self, client):
        # Serverul masoara mesaj dupa mesaj, dar cifra raportata de agent nu mai
        # creste: ori altcineva trimite in numele lui, ori are un canal
        # necontabilizat. Directia grava nu are voie sa fie amortizata de adoptie.
        #
        # Mesajele sunt de aceeasi marime deliberat. O prima versiune a testului
        # strecurase printre ele unul de 20 KB, ceea ce ridica „dimensiunea
        # tipica" la 7000 si pragul de zbor la 21000 — testul cadea, dar din
        # cauza datelor lui, nu a codului. Pragul e relativ la mesajul tipic
        # tocmai ca sa nu poata fi pacalit de volum.
        _post(400, attempted=50_000, delivered=50_000)

        for _ in range(10):
            _post(400, attempted=50_400, delivered=50_400)

        account = _account()
        assert wire_accounting.reconcile(account)["verdict"] == (
            wire_accounting.VERDICT_ABOVE
        )
        assert wire_accounting.threshold_breach(account) is not None


class TestWhoGetsAdopted:
    def test_an_incarnation_that_starts_now_is_not_adopted(self, client):
        # Zerouri la primul raport inseamna inceput real de incarnare.
        _post(400, attempted=0, delivered=0)

        assert _account().was_adopted is False

    def test_adoption_happens_only_once(self, client):
        # Al doilea raport nu re-adopta: linia de baza se fixeaza o data, altfel
        # fiecare cerere ar sterge istoria de dinaintea ei si nicio discrepanta
        # n-ar mai fi vizibila vreodata.
        _post(400, attempted=50_000, delivered=50_000)
        _post(600, attempted=99_000, delivered=99_000)

        assert _account().adopted_attempted_bytes == 50_000

    def test_bytes_measured_before_the_first_report_are_subtracted_too(self, client):
        # Cereri fara anteturi de raportare, sosite inaintea primului raport
        # lizibil: octetii lor sunt deja in totalul raportat de agent, deci
        # scaderea trebuie facuta pe ambele parti ca sa ramana comparabile.
        _post(400)  # fara raport
        _post(600, attempted=50_000, delivered=50_000)

        account = _account()
        assert account.received_bytes_at_adoption == 400
        assert wire_accounting.reconcile(account)["verdict"] == (
            wire_accounting.VERDICT_WITHIN
        )
