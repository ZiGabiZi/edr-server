"""
Memoria parcului: ce numără, ce nu numără, și ce rămâne fixat după ce a numărat.

Testele de aici fixează SENSUL prevalenței. Mecanica — că se scrie un rând —
ar trece la fel de bine cu o cifră greșită, iar cifrele greșite de aici sunt
toate în direcția care flatează afirmația centrală:

    1. dacă ar număra evenimente în loc de mașini, o mașină care rescrie un
       fișier ar arăta ca un parc;
    2. dacă endpoint-ul care raportează nu s-ar număra pe sine, primul ar primi
       zero, indistinct de „n-a fost numărat";
    3. dacă poziția de plecare s-ar consemna după primul eveniment, o rulare pe
       bază goală ar declara o memorie pe care n-o avea;
    4. dacă retransmisia ar recalcula, același eveniment ar avea două adevăruri.
"""

import hashlib

import app.services.event_store as event_store
import app.services.measurement_run as measurement_run


HASH_COMUN = hashlib.sha256(b"fisier-raspandit").hexdigest()
HASH_UNIC = hashlib.sha256(b"fisier-doar-pe-o-masina").hexdigest()


def _inroleaza(client, agent_id: str):
    raspuns = client.post(
        "/api/agents/register",
        json={
            "agent_id": agent_id,
            "hostname": f"HOST-{agent_id}",
            "operating_system": "windows",
            "architecture": "x64",
            "os_architecture": "x64",
            "machine_id_type": "hash",
            "machine_id_hash": f"hash-{agent_id}",
        },
    )
    assert raspuns.status_code == 200, raspuns.text
    return agent_id


def _fisier(client, agent_id: str, digest_hex: str, client_event_id: str, **extra):
    payload = {
        "agent_id": agent_id,
        "event_type": "file_created",
        "client_event_id": client_event_id,
        "file_path": "C:\\EDR_Test\\proba.exe",
        "sha256": digest_hex,
        "hash_status": "ok",
        "file_size": 4096,
        "occurred_at": "2026-09-02T10:00:00+00:00",
    }
    payload.update(extra)

    return client.post("/api/events", json=payload)


def _prevalenta(raspuns):
    assert raspuns.status_code == 200, raspuns.text
    return raspuns.json()["event"]["prevalence"]


# ── Ce numără ────────────────────────────────────────────────────────────────

def test_the_first_endpoint_counts_itself(client, registered_agent_id):
    """
    `1`, niciodată `0`. Întrebarea e pe câte mașini se știe că EXISTĂ conținutul,
    iar mașina care tocmai l-a raportat e una dintre ele. Un zero n-ar putea fi
    deosebit de „n-a fost numărat".
    """
    p = _prevalenta(_fisier(client, registered_agent_id, HASH_COMUN, "evt-1"))

    assert p["agents"] == 1
    assert p["park_agents"] == 1
    assert p["first_seen"], "prima vedere a parcului trebuie consemnată"


def test_prevalence_grows_with_machines_not_with_events(client, registered_agent_id):
    """
    Efectul de parc, în forma lui minimă: al treilea endpoint primește 3.

    Și contra-proba, în același test: aceeași mașină care raportează același
    conținut a doua oară NU crește cifra. O mașină care rescrie un fișier de 500
    de ori nu e un parc, iar greșeala n-ar produce nicio eroare — doar un număr
    mai mare în direcția care flatează afirmația.
    """
    _fisier(client, registered_agent_id, HASH_COMUN, "evt-1")

    al_doilea = _inroleaza(client, "agent-2")
    p2 = _prevalenta(_fisier(client, al_doilea, HASH_COMUN, "evt-2"))
    assert p2["agents"] == 2

    al_treilea = _inroleaza(client, "agent-3")
    p3 = _prevalenta(_fisier(client, al_treilea, HASH_COMUN, "evt-3"))
    assert p3["agents"] == 3

    din_nou = _prevalenta(_fisier(client, al_treilea, HASH_COMUN, "evt-4"))
    assert din_nou["agents"] == 3, (
        "A doua vedere pe aceeași mașină a crescut prevalența. Registrul numără "
        "mașini distincte, nu atingeri."
    )


def test_park_agents_is_the_denominator_and_counts_reporters(
    client, registered_agent_id
):
    """
    „3 mașini" înseamnă altceva într-un parc de 5 decât în unul de 500.

    Numitorul crește cu mașinile care raportează, nu cu fișierele: al doilea
    endpoint care trimite un fișier COMPLET DIFERIT tot mărește parcul.
    """
    p1 = _prevalenta(_fisier(client, registered_agent_id, HASH_COMUN, "evt-1"))
    assert p1["park_agents"] == 1

    al_doilea = _inroleaza(client, "agent-2")
    p2 = _prevalenta(_fisier(client, al_doilea, HASH_UNIC, "evt-2"))

    assert p2["agents"] == 1, "fișierul e pe o singură mașină"
    assert p2["park_agents"] == 2, "dar parcul are acum două mașini care raportează"


def test_first_seen_is_the_parks_first_sighting_not_the_latest(
    client, registered_agent_id
):
    """
    Vechimea intră în scor împreună cu prevalența: prezent pe 400 de mașini de
    trei luni ≠ apărut pe 50 de mașini în zece minute. Dacă `first_seen` ar fi
    împrospătat la fiecare vedere, distincția aia ar dispărea tăcut.
    """
    intai = _prevalenta(_fisier(client, registered_agent_id, HASH_COMUN, "evt-1"))

    al_doilea = _inroleaza(client, "agent-2")
    dupa = _prevalenta(_fisier(client, al_doilea, HASH_COMUN, "evt-2"))

    assert dupa["first_seen"] == intai["first_seen"]


# ── Ce NU numără ─────────────────────────────────────────────────────────────

def test_an_event_without_a_hash_has_no_prevalence(client, registered_agent_id):
    """Fără conținut identificat nu există nimic de numărat — ca la `reputation`."""
    raspuns = client.post(
        "/api/events",
        json={
            "agent_id": registered_agent_id,
            "event_type": "agent_startup",
            "client_event_id": "evt-pornire",
        },
    )

    assert raspuns.status_code == 200, raspuns.text
    assert raspuns.json()["event"]["prevalence"] is None


def test_an_agent_cannot_declare_its_own_prevalence(client, registered_agent_id):
    """
    `prevalence` e interzis pe cerere. Un endpoint care și-ar declara singur
    prevalența și-ar putea fabrica propria închidere la T0, iar memoria partajată
    ar depinde de ce afirmă mașina observată.

    Cheia trimisă oricum e aruncată de `WireModel` și logată cu numele ei, deci
    ce ajunge în store e ce a calculat serverul.
    """
    raspuns = _fisier(
        client,
        registered_agent_id,
        HASH_COMUN,
        "evt-mincinos",
        prevalence={"agents": 999, "park_agents": 999},
    )

    p = _prevalenta(raspuns)

    assert p["agents"] == 1, "serverul a preluat prevalența declarată de agent"
    assert p["park_agents"] == 1


# ── Ce rămâne fixat ──────────────────────────────────────────────────────────

def test_a_retransmission_keeps_the_prevalence_of_the_first_arrival(
    client, registered_agent_id
):
    """
    Invarianta M9, geamăna lui F9. Între cele două sosiri, alt endpoint vede
    același conținut, deci prevalența curentă se schimbă — dar evenimentul stocat
    rămâne cu ce știa serverul când a răspuns. Altfel același eveniment ar avea
    două adevăruri, iar „câte mașini îl știau atunci" n-ar mai fi reconstruibil.
    """
    prima = _fisier(client, registered_agent_id, HASH_COMUN, "evt-retransmis")
    intai = _prevalenta(prima)
    assert intai["agents"] == 1

    al_doilea = _inroleaza(client, "agent-2")
    assert _prevalenta(_fisier(client, al_doilea, HASH_COMUN, "evt-2"))["agents"] == 2

    a_doua = _fisier(client, registered_agent_id, HASH_COMUN, "evt-retransmis")

    assert a_doua.json()["event"]["event_id"] == prima.json()["event"]["event_id"], (
        "A doua cerere a inserat un eveniment nou; deduplicarea nu a fost "
        "exercitată, deci testul n-a verificat nimic."
    )
    assert _prevalenta(a_doua) == intai, (
        "Retransmisia a raportat prevalența de acum, nu pe cea de la prima sosire."
    )


def test_the_run_baseline_is_recorded_before_the_first_event(
    client, registered_agent_id
):
    """
    Poziția de plecare se consemnează ÎNAINTE de prima vedere a rulării.

    Consemnată după, o rulare pornită pe o bază goală ar declara o memorie de un
    hash și un agent — pe care n-o avea. Diferența e mică în cifre și totală în
    înțeles: poziția de plecare e tocmai ce separă o rulare rece de una caldă.
    """
    _fisier(client, registered_agent_id, HASH_COMUN, "evt-1")

    (consemnat,) = event_store.run_prevalences(measurement_run.current_run_id())

    assert consemnat["distinct_hashes"] == 0
    assert consemnat["agents"] == 0


def _parc_de_proba(client, primul_agent):
    """Un conținut pe trei mașini, altul pe una. Patru evenimente, două conținuturi."""
    _fisier(client, primul_agent, HASH_COMUN, "evt-1")

    al_doilea = _inroleaza(client, "agent-2")
    _fisier(client, al_doilea, HASH_COMUN, "evt-2")

    al_treilea = _inroleaza(client, "agent-3")
    _fisier(client, al_treilea, HASH_COMUN, "evt-3")

    _fisier(client, primul_agent, HASH_UNIC, "evt-4")


def _cifra(client):
    raspuns = client.get("/api/metrics/disclosure")
    assert raspuns.status_code == 200, raspuns.text
    return raspuns.json()


def test_the_histogram_counts_contents_not_events(client, registered_agent_id):
    """
    Numitorul histogramei e altul decât al celorlalte două tabele.

    Patru evenimente cu hash, dar două conținuturi distincte: un fișier pe trei
    mașini produce trei evenimente și UN rând în histogramă. Adunate, procentele
    s-ar raporta la o mulțime care nu există.
    """
    _parc_de_proba(client, registered_agent_id)

    m = _cifra(client)
    p = m["prevalence"]

    assert p["histogram"] == {"1": 1, "3": 1}
    assert p["distinct_hashes"] == 2
    assert p["placements"] == 4
    assert p["machines_per_hash"] == 2.0
    assert p["park_agents"] == 3

    assert m["reputation"]["events_with_hash"] == 4, (
        "Cele două tabele trebuie să rămână pe numitori diferiți: patru "
        "evenimente cu hash, două conținuturi distincte."
    )


def test_what_was_answered_then_is_reported_apart_from_the_final_state(
    client, registered_agent_id
):
    """
    Histograma descrie starea de ACUM; ce s-a răspuns atunci se raportează separat.

    Amestecate, o distribuție peste valorile răspunsurilor ar descrie în bună
    parte ordinea sosirii, nu parcul. Aici: două evenimente au fost prima vedere
    a unui conținut, două au sosit la un conținut pe care parcul îl știa deja.
    """
    _parc_de_proba(client, registered_agent_id)

    p = _cifra(client)["prevalence"]

    assert p["events_at_first_sighting"] == 2
    assert p["events_with_prior_sighting"] == 2
    assert p["hashed_events_without_prevalence"] == 0


def test_the_published_figure_declares_the_starting_position(
    client, registered_agent_id
):
    """
    Registrul nu se amprentează, deci poziția de plecare e tot ce poate fi
    declarat — iar fără ea două rulări cu memorii diferite ar publica cifre
    incomparabile fără ca nimic să spună de ce.
    """
    _parc_de_proba(client, registered_agent_id)

    (baza,) = _cifra(client)["prevalence"]["baselines"]

    assert baza["run_id"] == measurement_run.current_run_id()
    assert baza["distinct_hashes"] == 0
    assert baza["agents"] == 0


def test_the_published_figure_claims_no_saving(client, registered_agent_id):
    """
    „Câte escaladări a evitat parcul" cere să se știe care evenimente ar fi
    escaladat, iar decizia aia e a benzii de incertitudine. Cifra numără; nu
    interpretează.
    """
    _parc_de_proba(client, registered_agent_id)

    chei = set(_cifra(client)["prevalence"])
    interzise = {"saved", "savings", "avoided_escalations", "escalations_avoided", "score"}

    assert not interzise & chei, (
        f"Cifra publică o economie: {sorted(interzise & chei)}. Interpretarea "
        f"aparține benzii, nu tabelului."
    )


def test_the_baseline_of_a_later_run_carries_the_memory_of_the_earlier_one(
    client, registered_agent_id
):
    """
    Registrul e GLOBAL peste rulări: memoria parcului nu se golește când
    operatorul redenumește experimentul. A doua rulare pornește deci cu poziția
    lăsată de prima, iar cifra ei trebuie citită știind asta.
    """
    _fisier(client, registered_agent_id, HASH_COMUN, "evt-1")

    assert client.post("/api/runs/a-doua-rulare").status_code == 200

    _fisier(client, registered_agent_id, HASH_UNIC, "evt-2")

    (consemnat,) = event_store.run_prevalences("a-doua-rulare")

    assert consemnat["distinct_hashes"] == 1, (
        "A doua rulare a pornit cu memoria goală; registrul nu mai e global."
    )
    assert consemnat["agents"] == 1
