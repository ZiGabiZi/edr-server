import logging
import tempfile
from pathlib import Path

import pytest

import app.services.agent_service as agent_service
import app.services.auth_service as auth_service
import app.services.event_service as event_service
import app.services.measurement_run as measurement_run
import app.services.prevalence as prevalence
import app.services.reputation_disposition as reputation_disposition
import app.services.reputation_store as reputation_store
import app.services.wire_accounting as wire_accounting
import app.services.wire_alarm as wire_alarm
from app.tests.support import make_test_client


# Jurnalul suitei, deviat din server.log.
# =======================================
#
# De ce e nevoie:
#     Suita exercită alarma de discrepanță, care emite la nivel ERROR. Fără
#     devierea asta, `server.log` se umple cu incidente fabricate — agenți
#     numiți `agent-1`, încarnări `inc-1`, praguri rotunde — amestecate printre
#     cele reale. Cine caută peste o lună un incident adevărat, cu
#     `grep "Wire discrepancy"`, găsește ambele feluri și n-are cum să le
#     deosebească. Un jurnal în care nu poți avea încredere e mai rău decât unul
#     care lipsește: primul te face să tragi concluzii.
#
# De ce se scot handlerele explicit, în loc de un basicConfig() pus mai sus:
#     Prima versiune făcea exact asta și NU funcționa, într-un mod care merită
#     ținut minte: `logging.basicConfig()` nu face nimic dacă logger-ul rădăcină
#     are deja handlere. La rularea suitei întregi, pytest și le instalează pe
#     ale lui înainte de importul acestui fișier, deci apelul devenea o
#     operațiune goală; la rularea unui singur fișier de test, nu, și atunci
#     funcționa. Adică un comportament care depindea de câte teste rulezi.
#
#     Codul de aici nu întreabă cine a ajuns primul: caută handlerul care scrie
#     în server.log, îl scoate și îl închide, apoi pune al lui. Rezultatul e
#     același indiferent de ordinea importurilor.
#
# De ce un fișier și nu tăcere completă:
#     Un handler nul ar ascunde exact liniile utile când un test pică din motive
#     de logică. Fișierul stă în directorul temporar al sistemului, se rescrie la
#     fiecare rulare, și nu intră niciodată în repo.
TEST_LOG_PATH = Path(tempfile.gettempdir()) / "edr-server-tests.log"
SERVER_LOG_PATH = Path(__file__).resolve().parent.parent / "server.log"


def _redirect_logging_away_from_server_log() -> None:
    root = logging.getLogger()

    for handler in list(root.handlers):
        if Path(getattr(handler, "baseFilename", "")) == SERVER_LOG_PATH:
            root.removeHandler(handler)
            handler.close()

    root.addHandler(
        logging.FileHandler(TEST_LOG_PATH, mode="w", encoding="utf-8")
    )
    root.setLevel(logging.INFO)


_redirect_logging_away_from_server_log()


@pytest.fixture(autouse=True)
def isolated_reputation_snapshot(tmp_path, monkeypatch):
    """
    Niciun test nu citește instantaneul real de pe mașina care rulează suita.

    Calea implicită e `storage/reputation.db`, iar acolo stă instantaneul de
    producție — 3,28 GB azi. Fără izolarea de aici, două lucruri s-ar întâmpla
    la prima consultare din suită, amândouă grave și niciunul zgomotos:

        - fiecare deschidere ar amprenta 3,28 GB, deci suita ar încetini cu
          ordine de mărime fără nicio cauză vizibilă în teste;
        - rezultatele ar depinde de CE conține instantaneul acelei mașini. Un
          test care afirmă „hash necunoscut → `unknown`" ar trece pe un laptop
          și ar pica pe altul, iar cifra n-ar mai fi despre cod.

    Calea arată către un fișier care nu există, deci comportamentul implicit al
    suitei e `reputation_unavailable` — starea onestă pentru „n-am ce întreba".
    Testele care au nevoie de răspunsuri își construiesc propriul instantaneu și
    suprascriu variabila, ca `test_reputation_store.py`.
    """
    monkeypatch.setenv(
        reputation_store.SNAPSHOT_PATH_ENV, str(tmp_path / "fara-instantaneu.db")
    )
    reputation_store.reset_for_tests()
    reputation_disposition.reset_for_tests()

    yield

    reputation_store.reset_for_tests()
    reputation_disposition.reset_for_tests()


@pytest.fixture
def client():
    agent_service.agents_store.clear()

    # Depozitul de evenimente e persistent din 1.4.2, deci golirea lui nu mai e
    # o listă ștearsă: baza se aruncă și se redeschide în memorie. Fără asta,
    # suita ar scrie edr_server.db în rădăcina repo-ului și ar duce evenimente
    # dintr-o rulare a suitei în următoarea — aceeași grijă ca la cheile de
    # agent, dezactivate mai jos.
    event_service.reset_for_tests()

    # Registrul de prevalență trăiește în aceeași bază, deci se golește odată cu
    # ea — dar cache-ul de proces care ține minte ce rulări au poziția de plecare
    # consemnată nu. Fără golire, a doua rulare cu aceeași etichetă ar sări peste
    # consemnare, iar testul ar trece sau ar pica după ordinea în care rulează.
    prevalence.reset_for_tests()

    # Golește depozitul de chei ȘI dezactivează persistența lui: fără asta,
    # suita ar scrie agent_keys.json în rădăcina repo-ului și ar duce credențiale
    # dintr-o rulare în următoarea.
    auth_service.reset_for_tests()

    # Contabilizarea e stare de proces, ca store-urile de mai sus: fara golire,
    # octetii unui test s-ar aduna peste ai urmatorului, iar testele ar trece
    # sau ar cadea dupa ordinea in care ruleaza.
    wire_accounting.reset_for_tests()
    wire_alarm.reset_for_tests()

    # Registrul etichetelor de rulare e la fel de global ca store-urile de mai
    # sus, cu o consecinta proprie: o eticheta folosita de un test ramane
    # consemnata, iar al doilea test care o cere ar primi 409. Fara golire,
    # suita ar trece sau ar cadea dupa ordinea in care ruleaza.
    measurement_run.reset_for_tests()

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
