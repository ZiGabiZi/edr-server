"""
Depozitul persistent — ce supraviețuiește unei reporniri, și ce nu are voie să apară de două ori.

De ce testele de aici închid conexiunea în loc să simuleze o repornire:
    `event_store.close()` urmat de o citire e singurul mod onest de a verifica
    ce e pe DISC. Un test care ar citi din aceeași conexiune ar trece și dacă
    datele n-ar fi fost scrise niciodată — ar dovedi doar că SQLite are un cache.

Cele trei invariante care devin cerințe de corectitudine odată cu discul:
    1. o retransmisie de după o repornire NU produce un al doilea rând; altfel
       ar dubla file_size în numitorul metricii de divulgare;
    2. event_id nu repornește de la 1; altfel s-ar ciocni cu rândurile scrise
       înainte;
    3. registrul etichetelor de rulare supraviețuiește; altfel refuzul de
       refolosire s-ar goli exact la repornirea care face refolosirea probabilă.
"""

import pytest

import app.services.event_store as event_store
import app.services.measurement_run as measurement_run


@pytest.fixture
def store_on_disk(tmp_path, monkeypatch):
    """
    Un depozit pe un fișier real, aruncat la sfârșitul testului.

    Fișierul trebuie să fie real: o bază din memorie dispare odată cu
    conexiunea, deci ar face imposibil de deosebit ce a fost scris de ce a fost
    doar ținut minte — adică exact întrebarea testelor de aici.
    """
    monkeypatch.setenv(event_store.DB_PATH_ENV, str(tmp_path / "masuratoare.db"))
    event_store.close()

    yield

    event_store.reset_for_tests()
    measurement_run.reset_for_tests()


def _event(client_event_id, run_id="rulare-1", agent_id="agent-1", **extra):
    event = {
        "agent_id": agent_id,
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
        "run_id": run_id,
        "status": "received",
    }
    event.update(extra)

    return event


# ---------------------------------------------------------------------------
# Persistența însăși
# ---------------------------------------------------------------------------


def test_events_survive_a_restart(store_on_disk):
    event_store.insert_event(_event("evt-1"))
    event_store.insert_event(_event("evt-2"))

    event_store.close()

    stored = event_store.all_events()

    assert [event["client_event_id"] for event in stored] == ["evt-1", "evt-2"]


def test_the_stored_event_comes_back_exactly_as_it_went_in(store_on_disk):
    """
    Payload-ul e adevărul, coloanele sunt copii derivate din el.

    Dacă round-trip-ul ar pierde blocul `disclosure`, metrica ar continua să
    răspundă — cu zero octeți de conținut și zero trepte atribuite, adică cu
    cea mai flatantă cifră posibilă despre un sistem de confidențialitate.
    """
    original = _event("evt-1", measurements={"hash_ms": 12.5})

    event_store.close()
    stored = event_store.insert_event(original)
    event_store.close()

    (read_back,) = event_store.all_events()

    assert read_back == stored
    assert read_back["disclosure"] == {"tier": "T0", "content_bytes": 0}
    assert read_back["measurements"] == {"hash_ms": 12.5}

    # event_id e singurul câmp adăugat de depozit; restul trebuie să fie identic.
    assert {k: v for k, v in read_back.items() if k != "event_id"} == original


# ---------------------------------------------------------------------------
# 1. Deduplicarea vine din bază
# ---------------------------------------------------------------------------


def test_a_retransmission_after_a_restart_does_not_create_a_second_row(store_on_disk):
    """
    Cazul care motivează constrângerea UNIQUE.

    Dicționarul din memorie se golea la repornire, deci un agent care retrimite
    după un restart de server ar fi scris al doilea rând pentru același
    eveniment — iar rândul acela ar fi adăugat încă un file_size în numitorul
    metricii, fără ca nimic să pară stricat.
    """
    first = event_store.insert_event(_event("evt-1"))

    event_store.close()

    second = event_store.insert_event(_event("evt-1"))

    assert second["event_id"] == first["event_id"]
    assert event_store.count_events() == 1


def test_an_event_without_a_client_event_id_is_never_deduplicated(store_on_disk):
    """
    NULL nu se ciocnește cu NULL în SQLite, exact ca garda de dinainte.

    Evenimentele de ciclu de viață pot sosi fără identificator de client; dacă
    UNIQUE le-ar contopi, al doilea agent_startup din viața serverului ar
    dispărea tăcut.
    """
    event_store.insert_event(_event(None))
    event_store.insert_event(_event(None))

    assert event_store.count_events() == 2


# ---------------------------------------------------------------------------
# 2. event_id vine din bază
# ---------------------------------------------------------------------------


def test_event_id_does_not_restart_at_one_after_a_restart(store_on_disk):
    """
    Contorul de proces de dinainte repornea de la 1, deci ar fi produs
    identificatori care se ciocnesc cu rândurile deja scrise. Un event_id
    duplicat într-un depozit de măsurători nu strică nimic vizibil: strică
    orice analiză care se sprijină pe el ca să deosebească două evenimente.
    """
    first = event_store.insert_event(_event("evt-1"))

    event_store.close()

    second = event_store.insert_event(_event("evt-2"))

    assert second["event_id"] > first["event_id"]


# ---------------------------------------------------------------------------
# 3. Filtrarea pe rulare, în SQL
# ---------------------------------------------------------------------------


def test_events_can_be_read_one_run_at_a_time(store_on_disk):
    event_store.insert_event(_event("evt-1", run_id="proba-mica"))
    event_store.insert_event(_event("evt-2", run_id="proba-mica"))
    event_store.insert_event(_event("evt-3", run_id="proba-mare"))

    event_store.close()

    assert event_store.count_events() == 3
    assert event_store.count_events(run_id="proba-mica") == 2
    assert [
        event["client_event_id"] for event in event_store.all_events("proba-mare")
    ] == ["evt-3"]


# ---------------------------------------------------------------------------
# 4. Registrul rulărilor
# ---------------------------------------------------------------------------


def test_the_run_register_survives_a_restart(store_on_disk):
    """
    Miezul lui 1.4.2 pentru partea de etichete.

    Un registru în memorie s-ar fi golit exact la repornirea de după care
    refolosirea unei etichete devine periculoasă: evenimentele vechi sunt încă
    pe disc, deci cele noi s-ar amesteca în ele sub același nume.
    """
    assert event_store.register_run("masuratoare-t0", "operator", "2026-08-30T10:00:00")

    event_store.close()

    assert not event_store.register_run(
        "masuratoare-t0", "operator", "2026-08-31T10:00:00"
    )
    assert event_store.run_exists("masuratoare-t0")


def test_a_run_reopened_after_a_restart_is_refused_by_the_service(store_on_disk):
    """
    Aceeași proprietate, dar prin drumul pe care îl parcurge operatorul.

    `reset_for_tests` al serviciului uită rularea curentă fără să atingă
    registrul — adică simulează exact o repornire de server: procesul își pierde
    indicatorul, discul își păstrează catalogul.
    """
    measurement_run.start_run("masuratoare-t0-corpus-444")

    event_store.close()
    measurement_run.reset_for_tests()

    with pytest.raises(measurement_run.RunLabelError) as refusal:
        measurement_run.start_run("masuratoare-t0-corpus-444")

    assert refusal.value.reason == measurement_run.RunLabelError.REASON_ALREADY_USED


def test_a_restart_opens_a_new_generated_run(store_on_disk):
    """
    Registrul persistă, indicatorul spre rularea curentă nu — deliberat.

    O rulare de operator care ar rămâne deschisă peste restarturi ar aduna
    tăcut, peste săptămâni, tot ce trimite parcul, inclusiv sesiuni de depanare
    fără legătură cu experimentul.
    """
    named = measurement_run.start_run("masuratoare-t0-corpus-444")["run_id"]

    event_store.close()
    measurement_run.reset_for_tests()

    resumed = measurement_run.current_run()

    assert resumed["run_id"] != named
    assert resumed["source"] == measurement_run.SOURCE_GENERATED

    labels = [run["run_id"] for run in measurement_run.known_runs()]
    assert named in labels, "Registrul a pierdut o etichetă folosită."
    assert resumed["run_id"] in labels
