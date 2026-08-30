"""
Eticheta de rulare — că există mereu, că nu se poate refolosi, și că nu migrează.

De ce merită teste proprii:
    Mecanismul are un singur scop, iar scopul e negativ: să nu se poată
    amesteca două experimente într-o cifră. Un mecanism de igienă stricat nu
    produce erori, produce numere plauzibile — deci nimic nu-l prinde în afara
    unei suite care întreabă explicit dacă mai desparte ce trebuie despărțit.

Cele patru proprietăți păzite aici:
    1. nimic nu rămâne neetichetat, nici dacă operatorul uită de mecanism;
    2. o etichetă folosită o dată nu se mai poate deschide;
    3. evenimentele deja sosite NU migrează spre rularea nou deschisă;
    4. partea măsurată nu poate renumi măsurătoarea.
"""

import app.services.measurement_run as measurement_run


JOURNAL_LABEL = "masuratoare-t0-corpus-444"


def _post_file_event(client, agent_id: str, client_event_id: str):
    return client.post(
        "/api/events",
        json={
            "agent_id": agent_id,
            "agent_instance_id": "inst-A",
            "event_type": "file_created",
            "client_event_id": client_event_id,
            "file_path": "C:/tmp/proba.txt",
            "sha256": "a" * 64,
            "hash_status": "ok",
            "file_size": 1024,
            "description": "proba",
            "occurred_at": "2026-08-30T10:00:00+00:00",
        },
    )


def _stored_events(client):
    response = client.get("/api/events")
    assert response.status_code == 200, response.text

    return response.json()["events"]


# ---------------------------------------------------------------------------
# 1. Plasa de siguranță
# ---------------------------------------------------------------------------


def test_a_run_exists_without_anyone_naming_it(client):
    """
    Comportamentul de azi se păstrează gratuit: o pornire = un experiment nou.

    Dacă testul ăsta cade, evenimentele pot ajunge în depozit fără etichetă —
    iar la 1.4.2, când depozitul devine persistent, exact ele sunt cele care nu
    mai pot fi separate de nimic, niciodată.
    """
    response = client.get("/api/runs/current")

    assert response.status_code == 200, response.text
    run = response.json()["run"]

    assert run["run_id"].startswith(measurement_run.GENERATED_LABEL_PREFIX)
    assert run["source"] == measurement_run.SOURCE_GENERATED
    assert run["opened_at"]


def test_an_event_carries_the_current_label(client, registered_agent_id):
    response = _post_file_event(client, registered_agent_id, "evt-1")

    assert response.status_code == 200, response.text
    assert response.json()["event"]["run_id"] == measurement_run.current_run_id()


# ---------------------------------------------------------------------------
# 2. Instrumentul
# ---------------------------------------------------------------------------


def test_the_operator_can_name_the_run_after_the_journal_entry(client):
    """
    Legătura verificabilă cu jurnalul: numele intrării de montaj devine eticheta.

    Fără asta, afirmația că o cifră din lucrare vine dintr-un anume experiment
    rămâne pe încredere; cu ea, oricine ia numele din jurnal și cere serverului
    aceleași cifre.
    """
    response = client.post(f"/api/runs/{JOURNAL_LABEL}")

    assert response.status_code == 200, response.text
    run = response.json()["run"]

    assert run["run_id"] == JOURNAL_LABEL
    assert run["source"] == measurement_run.SOURCE_OPERATOR
    assert measurement_run.current_run_id() == JOURNAL_LABEL


def test_the_generated_run_stays_in_the_register_after_being_replaced(client):
    """
    Intervalul dintre pornire și prima etichetă de operator nu dispare.

    Evenimentele sosite în el poartă eticheta generată; dacă aceea n-ar fi
    consemnată, ele ar purta un nume care nu apare nicăieri în listă — adică
    date pe care nimeni nu le-ar mai găsi căutând.
    """
    generated = measurement_run.current_run_id()

    assert client.post(f"/api/runs/{JOURNAL_LABEL}").status_code == 200

    listed = client.get("/api/runs").json()
    labels = [run["run_id"] for run in listed["runs"]]

    assert generated in labels
    assert JOURNAL_LABEL in labels
    assert listed["current"] == JOURNAL_LABEL


# ---------------------------------------------------------------------------
# 3. Refuzul refolosirii
# ---------------------------------------------------------------------------


def test_a_used_label_cannot_be_reopened(client):
    """
    Singurul mod în care mecanismul poate minți, închis cu 409.

    O etichetă redeschisă toarnă date noi în cifre deja citate, iar răspunsul
    arată identic: același nume, alte numere.
    """
    assert client.post(f"/api/runs/{JOURNAL_LABEL}").status_code == 200

    again = client.post(f"/api/runs/{JOURNAL_LABEL}")

    assert again.status_code == 409, again.text
    assert measurement_run.current_run_id() == JOURNAL_LABEL, (
        "Refuzul n-are voie să schimbe rularea curentă: o cerere respinsă care "
        "totuși mută eticheta e mai rea decât una acceptată."
    )


def test_the_generated_prefix_is_refused_to_the_operator(client):
    """
    Cine a numit rularea trebuie să rămână o întrebare cu răspuns, peste luni.
    """
    response = client.post(f"/api/runs/{measurement_run.GENERATED_LABEL_PREFIX}manual")

    assert response.status_code == 400, response.text


def test_a_malformed_label_is_refused(client):
    """
    Alfabetul îngust nu e pedanterie: eticheta ajunge în cale, în jurnal și în
    numele fișierelor de export. Un spațiu scris o dată e o legătură ruptă.
    """
    response = client.post("/api/runs/corpus 444")

    assert response.status_code == 400, response.text


def test_the_reserved_word_current_cannot_name_a_run(client):
    response = client.post("/api/runs/current")

    assert response.status_code == 400, response.text


# ---------------------------------------------------------------------------
# 4. Evenimentele nu migrează
# ---------------------------------------------------------------------------


def test_events_keep_the_run_they_arrived_in(client, registered_agent_id):
    """
    Eticheta se pune la INGESTIE, nu la citirea metricii.

    Dacă s-ar aplica la citire, fiecare experiment nou ar goli experimentele
    vechi mutându-le evenimentele la el — iar cifrele publicate ieri s-ar
    schimba azi, fără ca nimeni să fi atins datele.
    """
    assert _post_file_event(client, registered_agent_id, "evt-inainte").status_code == 200
    generated = measurement_run.current_run_id()

    assert client.post(f"/api/runs/{JOURNAL_LABEL}").status_code == 200
    assert _post_file_event(client, registered_agent_id, "evt-dupa").status_code == 200

    by_client_id = {
        event["client_event_id"]: event["run_id"] for event in _stored_events(client)
    }

    assert by_client_id["evt-inainte"] == generated
    assert by_client_id["evt-dupa"] == JOURNAL_LABEL


def test_a_retransmission_keeps_the_run_of_its_first_arrival(
    client, registered_agent_id
):
    """
    Coada agentului e at-least-once (METRICS.md §1.3), deci același eveniment
    poate sosi de două ori, eventual peste granița unei rulări noi.

    A doua sosire n-a observat nimic: e același fișier, la aceeași oră. Mutată
    în rularea nouă, ar umfla corpusul unui experiment cu observații făcute
    înainte ca el să înceapă.
    """
    assert _post_file_event(client, registered_agent_id, "evt-1").status_code == 200
    generated = measurement_run.current_run_id()

    assert client.post(f"/api/runs/{JOURNAL_LABEL}").status_code == 200

    again = _post_file_event(client, registered_agent_id, "evt-1")

    assert again.status_code == 200, again.text
    assert again.json()["event"]["run_id"] == generated

    events = _stored_events(client)
    assert len(events) == 1, "Deduplicarea a încetat să mai funcționeze."


# ---------------------------------------------------------------------------
# 5. Partea măsurată nu renumește măsurătoarea
# ---------------------------------------------------------------------------


def test_opening_a_run_requires_the_operator_secret(client):
    """
    Fără pază, orice endpoint monitorizat ar putea muta evenimentele unui
    experiment în corpusul altuia — iar rezultatul n-ar arăta stricat, ci ca o
    măsurătoare cu alte numere.
    """
    before = measurement_run.current_run_id()

    response = client.post(
        f"/api/runs/{JOURNAL_LABEL}",
        headers={"X-Enrollment-Secret": "secret-gresit"},
    )

    assert response.status_code == 401, response.text
    assert measurement_run.current_run_id() == before
