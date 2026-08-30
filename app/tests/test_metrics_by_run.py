"""
Metrica filtrată pe rulare — că descrie un experiment, și că spune care.

De ce contează mai mult decât pare:
    Fără filtrare, persistența ar fi făcut rău net. `GET /api/metrics/disclosure`
    ar fi amestecat o probă cu 444 de fișiere, o rulare de depanare cu trei și
    un test de parc cu douăzeci de agenți într-o singură cifră care nu descrie
    niciunul dintre ele — și ar fi arătat exact ca înainte.

    A doua jumătate e declarația. METRICS.md §8 cere ca orice cifră publicată să
    vină cu corpusul ei; o metrică ce filtrează corect dar nu spune ce a filtrat
    mută obligația pe umerii cititorului, care n-are cum să o ducă.

Cazurile păzite aici:
    1. implicit = rularea curentă (decizia D2);
    2. altă rulare se poate cere, iar cifrele ei nu se amestecă cu ale celei curente;
    3. agregatul peste tot se cere EXPLICIT și își declară rulările componente;
    4. o etichetă necunoscută primește 404, nu un rezultat gol care ar arăta ca
       un experiment fără nicio divulgare;
    5. numărătorul MĂSURAT nu se lipește pe o rulare pe care procesul n-a văzut-o.
"""

import app.services.event_store as event_store
import app.services.measurement_run as measurement_run
from app.wire_middleware import WIRE_INSTANCE_HEADER


PROBA = "proba-mica"
DEPANARE = "sesiune-depanare"

INSTANCE_ID = "inst-A"


def _post_file_event(client, agent_id: str, client_event_id: str, file_size: int):
    # Antetul de încarnare e ce face middleware-ul să ATRIBUIE octeții, nu doar
    # să îi numere. Fără el, orice cerere ar cădea la `no_instance`, iar
    # numărătorul măsurat ar fi zero peste tot — adică testele de mai jos ar
    # trece din motivul greșit, fără să atingă vreodată întrebarea pusă.
    return client.post(
        "/api/events",
        headers={WIRE_INSTANCE_HEADER: INSTANCE_ID},
        json={
            "agent_id": agent_id,
            "agent_instance_id": INSTANCE_ID,
            "event_type": "file_created",
            "client_event_id": client_event_id,
            "file_path": f"C:/tmp/{client_event_id}.txt",
            "sha256": client_event_id.ljust(64, "0"),
            "hash_status": "ok",
            "file_size": file_size,
            "disclosure": {"tier": "T0", "content_bytes": 0},
            "description": "proba",
            "occurred_at": "2026-08-31T10:00:00+00:00",
        },
    )


def _disclosure(client, **params):
    response = client.get("/api/metrics/disclosure", params=params)
    assert response.status_code == 200, response.text

    return response.json()


def _two_runs(client, agent_id):
    """Un experiment de 1000 de octeți, apoi unul de depanare de 7 octeți."""
    assert client.post(f"/api/runs/{PROBA}").status_code == 200
    assert _post_file_event(client, agent_id, "evt-a", 1000).status_code == 200

    assert client.post(f"/api/runs/{DEPANARE}").status_code == 200
    assert _post_file_event(client, agent_id, "evt-b", 7).status_code == 200


# ---------------------------------------------------------------------------
# 1-2. Filtrarea
# ---------------------------------------------------------------------------


def test_the_default_describes_the_current_run(client, registered_agent_id):
    _two_runs(client, registered_agent_id)

    metrics = _disclosure(client)

    assert metrics["run"]["run_id"] == DEPANARE
    assert metrics["run"]["is_current"] is True
    assert metrics["always_upload"]["content_bytes"] == 7, (
        "Implicitul a inclus si evenimente din alta rulare: exact amestecul pe "
        "care notiunea de rulare exista ca sa il impiedice."
    )


def test_another_run_can_be_asked_for_by_name(client, registered_agent_id):
    """
    Legătura cu jurnalul devine folosibilă abia aici: iei numele intrării de
    montaj și primești chiar cifrele acelui experiment, nu ale ultimului.
    """
    _two_runs(client, registered_agent_id)

    metrics = _disclosure(client, run_id=PROBA)

    assert metrics["run"]["run_id"] == PROBA
    assert metrics["run"]["is_current"] is False
    assert metrics["run"]["source"] == measurement_run.SOURCE_OPERATOR
    assert metrics["always_upload"]["content_bytes"] == 1000
    assert metrics["run"]["events_in_scope"] == 1


def test_the_two_runs_do_not_leak_into_each_other(client, registered_agent_id):
    _two_runs(client, registered_agent_id)

    proba = _disclosure(client, run_id=PROBA)
    depanare = _disclosure(client, run_id=DEPANARE)

    assert proba["always_upload"]["content_bytes"] == 1000
    assert depanare["always_upload"]["content_bytes"] == 7


# ---------------------------------------------------------------------------
# 3. Agregatul se cere explicit și se declară
# ---------------------------------------------------------------------------


def test_the_aggregate_is_explicit_and_names_the_runs_it_covers(
    client, registered_agent_id
):
    """
    Decizia D2: tot istoricul e mai util operațional și mai periculos pentru
    teză. Se poate cere — dar cifra trebuie să spună din ce e făcută, altfel e
    o medie peste experimente cu distribuții diferite, prezentată ca un rezultat.
    """
    _two_runs(client, registered_agent_id)

    metrics = _disclosure(client, all_runs=True)

    assert metrics["run"]["selection"] == "all_runs"
    assert metrics["run"]["run_id"] is None
    assert metrics["always_upload"]["content_bytes"] == 1007

    covered = {item["run_id"]: item["events"] for item in metrics["run"]["runs_covered"]}
    assert covered == {PROBA: 1, DEPANARE: 1}


def test_run_id_and_all_runs_together_are_refused(client):
    """
    O contradicție, nu o preferință cu câștigător: oricare am alege în locul
    celui care a cerut, i-am da jumătate din ce a vrut, tăcut.
    """
    response = client.get(
        "/api/metrics/disclosure", params={"run_id": PROBA, "all_runs": True}
    )

    assert response.status_code == 400, response.text


# ---------------------------------------------------------------------------
# 4. O etichetă necunoscută nu primește un rezultat gol
# ---------------------------------------------------------------------------


def test_an_unknown_label_is_refused_instead_of_answered_with_zero(client):
    """
    Un răspuns gol pentru o etichetă scrisă greșit ar arăta exact ca un
    experiment care n-a divulgat nimic — cea mai flatantă cifră posibilă despre
    un sistem de confidențialitate, obținută dintr-o greșeală de tastare.
    """
    response = client.get(
        "/api/metrics/disclosure", params={"run_id": "masuratoare-scrisa-gresit"}
    )

    assert response.status_code == 404, response.text


def test_a_run_that_exists_but_has_no_events_answers_with_zero(client):
    """
    Distincția care face 404-ul de mai sus onest: o rulare deschisă și goală
    chiar a măsurat nimic, iar asta e un rezultat, nu o greșeală.
    """
    assert client.post(f"/api/runs/{PROBA}").status_code == 200

    metrics = _disclosure(client, run_id=PROBA)

    assert metrics["run"]["events_in_scope"] == 0
    assert metrics["ratio"]["sent_over_always_upload"] is None, (
        "Un raport fara numitor trebuie sa fie None, nu zero: zero ar arata ca "
        "un rezultat bun."
    )


# ---------------------------------------------------------------------------
# 5. Numărătorul măsurat nu se lipește pe orice rulare
# ---------------------------------------------------------------------------


def test_the_measured_numerator_applies_when_the_process_saw_only_this_run(
    client, registered_agent_id
):
    """
    Cazul unei măsurători adevărate: pornești serverul, numești rularea, apoi
    trimiți corpusul. Rularea generată la pornire rămâne goală, deci octeții
    numărați de proces descriu chiar experimentul.
    """
    assert client.post(f"/api/runs/{PROBA}").status_code == 200
    assert _post_file_event(client, registered_agent_id, "evt-a", 1000).status_code == 200

    metrics = _disclosure(client, run_id=PROBA)

    assert metrics["measured"]["applies_to_numerator"] is True
    assert metrics["progressive"]["numerator_source"] == "measured"


def test_the_measured_numerator_is_withheld_when_the_process_saw_other_runs(
    client, registered_agent_id
):
    """
    Miezul acestui pas.

    Contabilizarea de fir numără de la pornirea procesului și nu știe nimic
    despre rulări. Lipită pe o rulare care e doar o parte din ce a văzut
    procesul, ar publica numărul altcuiva cu autoritatea unei măsurători —
    aceeași familie cu regula deja scrisă la §7.5, ca zero măsurat să nu treacă
    drept măsurătoare.
    """
    _two_runs(client, registered_agent_id)

    metrics = _disclosure(client, run_id=PROBA)

    assert metrics["measured"]["applies_to_numerator"] is False
    assert metrics["progressive"]["numerator_source"] == "estimated"
    assert metrics["measured"]["attribution"], "Refuzul trebuie sa spuna de ce."

    # Cifrele masurate raman raportate ca diagnostic al procesului: ascunse, ar
    # face imposibil de vazut de ce numaratorul a revenit la estimare.
    assert metrics["measured"]["by_channel"]["events"]["bytes"] > 0


def test_the_aggregate_never_publishes_a_measured_numerator(
    client, registered_agent_id
):
    _two_runs(client, registered_agent_id)

    metrics = _disclosure(client, all_runs=True)

    assert metrics["measured"]["applies_to_numerator"] is False
    assert metrics["progressive"]["numerator_source"] == "estimated"


def test_a_run_from_before_this_process_gets_no_measured_numerator(
    client, registered_agent_id
):
    """
    Rularea e pe disc, octeții ei nu sunt nicăieri: procesul care i-a numărat
    s-a oprit. Cererea trebuie să răspundă, dar cu estimare declarată.
    """
    assert client.post(f"/api/runs/{PROBA}").status_code == 200
    assert _post_file_event(client, registered_agent_id, "evt-a", 1000).status_code == 200

    # Repornire simulată: contabilizarea de fir și mulțimea rulărilor observate
    # sunt stare de proces, depozitul nu.
    import app.services.event_service as event_service
    import app.services.wire_accounting as wire_accounting

    events_before = event_store.all_events(PROBA)
    wire_accounting.reset_for_tests()
    with event_service._runs_observed_lock:
        event_service._runs_observed.clear()
    measurement_run.reset_for_tests()

    metrics = _disclosure(client, run_id=PROBA)

    assert len(events_before) == 1, "Depozitul trebuia sa supravietuiasca."
    assert metrics["run"]["events_in_scope"] == 1
    assert metrics["measured"]["applies_to_numerator"] is False
    assert metrics["progressive"]["numerator_source"] == "estimated"


# ---------------------------------------------------------------------------
# Ruta de evenimente poartă aceeași selecție
# ---------------------------------------------------------------------------


def test_the_event_stream_carries_the_same_selection(client, registered_agent_id):
    """
    Aceiași parametri pe ambele rute de citire, dintr-un motiv practic: cine
    verifică o cifră vrea să vadă evenimentele din care a ieșit, iar două
    selecții diferite ar face comparația imposibilă.
    """
    _two_runs(client, registered_agent_id)

    current = client.get("/api/events").json()
    named = client.get("/api/events", params={"run_id": PROBA}).json()
    everything = client.get("/api/events", params={"all_runs": True}).json()

    assert current["run"]["run_id"] == DEPANARE and current["count"] == 1
    assert named["run"]["run_id"] == PROBA and named["count"] == 1
    assert everything["run"]["selection"] == "all_runs" and everything["count"] == 2


def test_the_run_catalogue_reports_how_many_events_each_run_holds(
    client, registered_agent_id
):
    _two_runs(client, registered_agent_id)

    listed = client.get("/api/runs").json()
    events_by_run = {run["run_id"]: run["events"] for run in listed["runs"]}

    assert events_by_run[PROBA] == 1
    assert events_by_run[DEPANARE] == 1
    assert listed["current"] == DEPANARE

    generated = [
        run
        for run in listed["runs"]
        if run["source"] == measurement_run.SOURCE_GENERATED
    ]
    assert generated and all(run["events"] == 0 for run in generated), (
        "Eticheta generata la pornire trebuie sa apara in catalog, cu zero "
        "evenimente: altfel intervalul dinaintea primei etichete de operator ar "
        "disparea din istoric."
    )
