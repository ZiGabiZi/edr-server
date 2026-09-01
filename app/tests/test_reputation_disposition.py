"""
Consultarea depozitului la ingestie: ce se știe la T0, spus pe fir.

Testele de aici fixează SENSUL dispoziției, nu mecanica ei. Mecanica — că
`lookup()` chiar e chemat — ar trece la fel de bine cu un vocabular greșit, iar
un vocabular greșit e singurul mod în care pasul ăsta poate strica o cifră fără
să producă vreo eroare:

    1. un hash din RDS nu are voie să primească niciun termen de benignitate;
    2. celula de suprapunere nu are voie să se colapseze în `known_malicious`;
    3. „depozitul nu știe" și „depozitul n-a putut fi întrebat" nu au voie să fie
       aceeași valoare;
    4. o retransmisie nu are voie să raporteze alt instantaneu decât cel care a
       răspuns prima dată.
"""

import hashlib
import re

import pytest

import app.services.event_store as event_store
import app.services.measurement_run as measurement_run
import app.services.reputation_build as reputation_build
import app.services.reputation_disposition as reputation_disposition
import app.services.reputation_store as reputation_store


RDS = "NSRL RDS"
BAZAAR = "MalwareBazaar"

MALICIOS = hashlib.sha256(b"doar-amenintare").digest()
SOFTWARE = hashlib.sha256(b"doar-software").digest()
AMBELE = hashlib.sha256(b"ambele-axe").digest()
ABSENT = hashlib.sha256(b"nicaieri").digest()

# Vocabularul interzis, în ambele limbi. Garda se uită la FORMĂ, ca
# test_event_model_never_carries_file_content: nu poate opri un termen strecurat
# sub alt nume, dar poate opri termenul însuși, oriunde ar apărea.
BENIGNITATE = re.compile(r"clean|benign|safe|curat", re.IGNORECASE)


def _populeaza(connection):
    software_id = reputation_build.record_source(
        connection, RDS, "software", "2026.03.1", 2
    )
    threat_id = reputation_build.record_source(
        connection, BAZAAR, "threat", "inventar-2026-08", 2
    )

    connection.execute(
        "INSERT INTO reputation (sha256, known_software, software_source, "
        "known_malicious, threat_source, family) VALUES (?, 0, NULL, 1, ?, ?)",
        (MALICIOS, threat_id, "AgentTesla"),
    )
    connection.execute(
        "INSERT INTO reputation (sha256, known_software, software_source, "
        "known_malicious, threat_source) VALUES (?, 1, ?, 0, NULL)",
        (SOFTWARE, software_id),
    )
    connection.execute(
        "INSERT INTO reputation (sha256, known_software, software_source, "
        "known_malicious, threat_source) VALUES (?, 1, ?, 1, ?)",
        (AMBELE, software_id, threat_id),
    )
    connection.commit()


@pytest.fixture
def instantaneu(tmp_path, monkeypatch):
    """Un instantaneu sigilat cu cele trei celule ocupate ale 2×2-ului."""
    lucru = reputation_build.create_working_database(tmp_path / "lucru.db")
    _populeaza(lucru)

    destinatie = tmp_path / "reputatie.db"
    reputation_build.seal(lucru, destinatie)
    lucru.close()

    monkeypatch.setenv(reputation_store.SNAPSHOT_PATH_ENV, str(destinatie))
    reputation_store.reset_for_tests()
    reputation_disposition.reset_for_tests()

    yield destinatie

    reputation_store.reset_for_tests()


def _eveniment(client, agent_id, digest_hex, client_event_id="evt-1"):
    return client.post(
        "/api/events",
        json={
            "agent_id": agent_id,
            "event_type": "file_created",
            "client_event_id": client_event_id,
            "file_path": "C:\\EDR_Test\\proba.exe",
            "sha256": digest_hex,
            "hash_status": "ok",
            "file_size": 2048,
            "occurred_at": "2026-09-02T10:00:00+00:00",
        },
    )


def _dispozitie(raspuns):
    assert raspuns.status_code == 200, raspuns.text
    return raspuns.json()["event"]["reputation"]


# ── Cele patru celule ────────────────────────────────────────────────────────

def test_a_hash_from_the_threat_source_is_known_malicious_with_provenance(
    client, registered_agent_id, instantaneu
):
    reputatie = _dispozitie(_eveniment(client, registered_agent_id, MALICIOS.hex()))

    assert reputatie["disposition"] == reputation_disposition.KNOWN_MALICIOUS
    assert reputatie["source"] == BAZAAR, (
        "Un răspuns fără proveniență nu poate fi exclus dintr-o ablație, iar "
        "ablația rece/semiînzestrat e singura măsurătoare care separă "
        "contribuția protocolului de cea a artei anterioare."
    )


def test_a_hash_from_rds_is_known_software_and_never_a_benign_word(
    client, registered_agent_id, instantaneu
):
    """
    `CORPUS.md` §5.4: RDS e o listă de software CUNOSCUT, nu de software BUN.

    A doua aserțiune se uită la TOT răspunsul, nu doar la dispoziție: enumul
    refuzat în depozit la R1 s-ar putea întoarce pe fir sub orice cheie, iar
    interdicția din contract acoperă doar numele câmpurilor de prim nivel.
    """
    raspuns = _eveniment(client, registered_agent_id, SOFTWARE.hex())
    reputatie = _dispozitie(raspuns)

    assert reputatie["disposition"] == reputation_disposition.KNOWN_SOFTWARE
    assert reputatie["source"] is None, (
        "Proveniența RDS n-are ce căuta pe fir: apartenența la o listă de "
        "software cunoscut nu poate justifica nicio acțiune, deci ar fi octeți "
        "plătiți ca să se spună „cunoscut, dar asta nu înseamnă nimic”."
    )

    gasit = BENIGNITATE.search(raspuns.text)
    assert gasit is None, (
        f"Răspunsul poartă un termen de benignitate ({gasit.group(0)!r} în "
        f"{raspuns.text[:200]!r}). Apartenența la RDS nu poate produce verdictul "
        f"„curat” — vezi CORPUS.md §5.4."
    )


def test_a_hash_absent_from_every_source_is_unknown(
    client, registered_agent_id, instantaneu
):
    """`unknown` nu e un eșec: e starea care numește candidatul la T1."""
    reputatie = _dispozitie(_eveniment(client, registered_agent_id, ABSENT.hex()))

    assert reputatie["disposition"] == reputation_disposition.UNKNOWN
    assert reputatie["source"] is None


def test_a_hash_on_both_axes_is_not_collapsed(
    client, registered_agent_id, instantaneu
):
    """
    Celula de suprapunere e chiar cea pentru care depozitul a refuzat enumul.

    Colapsată în `known_malicious`, contorul de suprapunere ar deveni imposibil
    de reconstruit din evenimente — exact pierderea pe care cele două axe au fost
    alese să o prevină, mutată din depozit pe fir.
    """
    reputatie = _dispozitie(_eveniment(client, registered_agent_id, AMBELE.hex()))

    assert reputatie["disposition"] == reputation_disposition.BOTH_AXES
    assert reputatie["source"] == BAZAAR


# ── Ce NU se consultă ────────────────────────────────────────────────────────

def test_an_event_without_a_hash_is_never_looked_up(
    client, registered_agent_id, instantaneu
):
    """
    Fără `sha256` nu există nimic de căutat, iar o dispoziție pusă acolo ar fi o
    afirmație despre un fișier pe care nimeni nu l-a identificat. Evenimentele de
    ciclu de viață cad toate aici, ca la blocul `disclosure`.
    """
    raspuns = client.post(
        "/api/events",
        json={
            "agent_id": registered_agent_id,
            "event_type": "agent_startup",
            "client_event_id": "evt-pornire",
            "description": "Agent started successfully",
        },
    )

    assert raspuns.status_code == 200, raspuns.text
    assert raspuns.json()["event"]["reputation"] is None


# ── Indisponibilitatea, care nu e necunoaștere ───────────────────────────────

def test_an_unreachable_snapshot_is_not_unknown(client, registered_agent_id):
    """
    Fără instantaneu (fixture-ul implicit din conftest), evenimentul se acceptă
    și primește `reputation_unavailable`.

    Cele două aserțiuni spun lucruri diferite și amândouă contează. Acceptarea:
    altfel disponibilitatea telemetriei ar fi cuplată de cea a reputației, iar
    coada at-least-once ar reîncerca la nesfârșit un eveniment valid.
    Distincția: contopită cu `unknown`, o pană a depozitului ar arăta identic cu
    un corpus genuin nou — adică exact variabila de care depinde afirmația
    centrală.
    """
    reputatie = _dispozitie(_eveniment(client, registered_agent_id, ABSENT.hex()))

    assert reputatie["disposition"] == reputation_disposition.REPUTATION_UNAVAILABLE
    assert reputatie["disposition"] != reputation_disposition.UNKNOWN


def test_a_run_that_never_consulted_the_store_records_no_snapshot(
    client, registered_agent_id
):
    """O rulare care n-a întrebat nimic n-a folosit niciun instantaneu."""
    _eveniment(client, registered_agent_id, ABSENT.hex())

    assert event_store.run_snapshot(measurement_run.current_run_id()) is None


# ── Ce se persistă lângă eveniment ───────────────────────────────────────────

def test_the_run_records_the_snapshot_that_answered_it(
    client, registered_agent_id, instantaneu
):
    """
    `METRICS.md` §8: orice cifră care a folosit depozitul declară pe ce
    instantaneu a rulat. Identitatea stă pe RULARE, nu pe eveniment — o rulare
    vede exact un instantaneu, iar repetată pe fiecare eveniment ar fi aceeași
    repetiție pe care schema de reputație a refuzat-o stocând sursa ca întreg.
    """
    _eveniment(client, registered_agent_id, MALICIOS.hex())

    consemnat = event_store.run_snapshot(measurement_run.current_run_id())

    assert consemnat is not None
    assert consemnat["fingerprint"] == reputation_store.fingerprint(str(instantaneu))
    assert [s["name"] for s in consemnat["identity"]["sources"]] == [RDS, BAZAAR]


def test_the_disposition_survives_in_the_stream_not_just_in_the_reply(
    client, registered_agent_id, instantaneu
):
    """
    Dispoziția se PERSISTĂ, nu se lipește pe răspuns. Fără asta, „câte fișiere
    s-au închis la T0 în rularea X" ar fi imposibil de reconstruit după ce
    răspunsul a plecat.
    """
    _eveniment(client, registered_agent_id, MALICIOS.hex())

    evenimente = client.get("/api/events").json()["events"]

    assert evenimente[-1]["reputation"]["disposition"] == (
        reputation_disposition.KNOWN_MALICIOUS
    )


def test_a_retransmission_keeps_the_disposition_of_the_first_arrival(
    client, registered_agent_id, instantaneu, tmp_path, monkeypatch
):
    """
    Invarianta F9, singura pe care ordinea codului o poate rupe tăcut.

    Aceeași retransmisie, sosită după un schimb de instantaneu, ar raporta altă
    dispoziție decât cea persistată dacă răspunsul s-ar construi din consultarea
    proaspătă în loc de din evenimentul stocat. Același eveniment ar avea două
    adevăruri, iar „câte s-au închis la T0" n-ar mai putea fi reconstruit.

    Instantaneul al doilea e GOL: dacă răspunsul ar veni din el, dispoziția ar
    cădea în `unknown`, adică într-o valoare vizibil diferită.
    """
    prima = _eveniment(client, registered_agent_id, MALICIOS.hex(), "evt-retransmis")
    intai = _dispozitie(prima)
    assert intai["disposition"] == reputation_disposition.KNOWN_MALICIOUS

    gol = tmp_path / "instantaneu-gol.db"
    reputation_build.build_empty_snapshot(gol)
    monkeypatch.setenv(reputation_store.SNAPSHOT_PATH_ENV, str(gol))
    reputation_store.reset_for_tests()

    a_doua = _eveniment(client, registered_agent_id, MALICIOS.hex(), "evt-retransmis")
    a_doua_oara = _dispozitie(a_doua)

    # Fără asta, testul ar putea trece fiindcă a doua cerere a inserat un rând
    # nou care s-a nimerit identic — adică fără să atingă vreodată calea de
    # deduplicare pe care o descrie.
    assert a_doua.json()["event"]["event_id"] == prima.json()["event"]["event_id"], (
        "A doua cerere a inserat un eveniment nou; deduplicarea după "
        "client_event_id nu a fost exercitată, deci testul n-a verificat nimic."
    )

    assert a_doua_oara == intai, (
        "Retransmisia a raportat instantaneul de acum, nu pe cel care a răspuns "
        "prima dată. Dispoziția trebuie citită din evenimentul stocat, nu din "
        "consultarea proaspătă."
    )


# ── Cifra publicată ──────────────────────────────────────────────────────────

def _metrica(client):
    raspuns = client.get("/api/metrics/disclosure")
    assert raspuns.status_code == 200, raspuns.text
    return raspuns.json()["reputation"]


def test_the_published_figure_counts_the_cells_and_declares_the_snapshot(
    client, registered_agent_id, instantaneu
):
    """
    Criteriul de ieșire, jumătatea care se poate interoga: dispoziția e
    numărabilă per rulare, lângă amprenta instantaneului care a răspuns
    (`METRICS.md` §8).
    """
    _eveniment(client, registered_agent_id, MALICIOS.hex(), "evt-1")
    _eveniment(client, registered_agent_id, SOFTWARE.hex(), "evt-2")
    _eveniment(client, registered_agent_id, AMBELE.hex(), "evt-3")
    _eveniment(client, registered_agent_id, ABSENT.hex(), "evt-4")

    reputatie = _metrica(client)

    assert reputatie["events_with_hash"] == 4
    assert reputatie["dispositions"] == {
        reputation_disposition.BOTH_AXES: 1,
        reputation_disposition.KNOWN_MALICIOUS: 1,
        reputation_disposition.KNOWN_SOFTWARE: 1,
        reputation_disposition.REPUTATION_UNAVAILABLE: 0,
        reputation_disposition.UNKNOWN: 1,
    }

    (declarat,) = reputatie["snapshots"]
    assert declarat["fingerprint"] == reputation_store.fingerprint(str(instantaneu))
    assert [s["name"] for s in declarat["identity"]["sources"]] == [RDS, BAZAAR]


def test_the_published_figure_keeps_unavailable_apart_from_unknown(
    client, registered_agent_id
):
    """
    Fără instantaneu, cele patru evenimente nu se adună în `unknown`.

    Dacă s-ar aduna, o pană a depozitului ar publica exact cifra unui corpus
    complet nou — adică rezultatul cel mai favorabil lucrării, produs de o
    defecțiune. Și `snapshots` rămâne gol: n-a răspuns nimeni.
    """
    _eveniment(client, registered_agent_id, MALICIOS.hex(), "evt-1")
    _eveniment(client, registered_agent_id, ABSENT.hex(), "evt-2")

    reputatie = _metrica(client)

    assert reputatie["dispositions"][reputation_disposition.UNKNOWN] == 0
    assert reputatie["dispositions"][reputation_disposition.REPUTATION_UNAVAILABLE] == 2
    assert reputatie["snapshots"] == []


def test_the_denominator_is_events_with_a_hash_not_every_event(
    client, registered_agent_id, instantaneu
):
    """
    Numitorul propriu, exact ca la `by_tier`. Un eveniment de ciclu de viață n-a
    avut niciodată ce căuta în depozit, deci nu are ce umfla numitorul.
    """
    _eveniment(client, registered_agent_id, ABSENT.hex(), "evt-1")
    client.post(
        "/api/events",
        json={
            "agent_id": registered_agent_id,
            "event_type": "agent_startup",
            "client_event_id": "evt-pornire",
        },
    )

    reputatie = _metrica(client)

    assert reputatie["events_with_hash"] == 1
    assert sum(reputatie["dispositions"].values()) == 1


def test_events_from_before_the_lookup_are_a_declared_gap_not_unknowns(
    client, registered_agent_id, instantaneu
):
    """
    Un eveniment scris înainte de v8 are hash și n-are dispoziție.

    Numărat ca `unknown`, o rulare veche ar arăta ca un corpus complet nou — la
    fel ca la confuzia dintre indisponibil și necunoscut, dar pe axa timpului.
    Intră deci într-un gol declarat, ca `file_events_without_tier` la §2.1.
    """
    event_store.insert_event(
        {
            "agent_id": registered_agent_id,
            "event_type": "file_created",
            "client_event_id": "evt-vechi",
            "sha256": MALICIOS.hex(),
            "hash_status": "ok",
            "file_size": 10,
            "received_at": "2026-08-01T00:00:00+00:00",
            "run_id": measurement_run.current_run_id(),
            "status": "received",
        }
    )

    reputatie = _metrica(client)

    assert reputatie["events_with_hash"] == 1
    assert reputatie["hashed_events_without_disposition"] == 1
    assert sum(reputatie["dispositions"].values()) == 0


def test_the_published_figure_carries_no_benign_term_and_no_closure_rate(
    client, registered_agent_id, instantaneu
):
    """
    Două interdicții în aceeași aserțiune, fiindcă au aceeași cauză.

    Niciun termen de benignitate: `known_software` nu poate deveni „curat"
    într-o cifră, după ce structura depozitului a interzis-o în date. Și nicio
    rată de închidere: maparea dispoziție → închis e decizia benzii (§L2.7), iar
    scrisă aici ar fi al doilea mecanism de decizie din sistem.
    """
    _eveniment(client, registered_agent_id, SOFTWARE.hex(), "evt-1")

    brut = client.get("/api/metrics/disclosure").text
    gasit = BENIGNITATE.search(brut)

    assert gasit is None, f"Metrica publică un termen de benignitate: {gasit!r}"

    reputatie = _metrica(client)
    chei = set(reputatie)

    assert not {"closed", "closed_at_t0", "closure_rate", "escalated"} & chei, (
        f"Metrica publică o rată de închidere: {sorted(chei)}. Maparea "
        f"dispoziție → închis aparține benzii de incertitudine, nu acestui tabel."
    )


# ── Pornirea ─────────────────────────────────────────────────────────────────

def test_the_snapshot_is_warmed_at_startup_not_on_the_first_event(instantaneu):
    """
    Amprentarea instantaneului nu are voie să cadă pe calea de ingestie.

    Pe instantaneul real, calculul durează 8,3 secunde, iar timeout-ul agentului
    e de 5. Lăsată leneșă, prima cerere cu hash a fiecărei porniri expira
    garantat, iar retransmisia intra în numărătorul măsurat — o cifră stricată
    sistematic, de noi.

    Testul verifică efectul, nu durata: după încălzire, identitatea e deja
    disponibilă, deci nimic nu mai rămâne de calculat la prima consultare.
    """
    from app.main import warm_reputation_snapshot

    warm_reputation_snapshot()

    assert reputation_store.snapshot_identity()["fingerprint"] == (
        reputation_store.fingerprint(str(instantaneu))
    )


def test_a_missing_snapshot_does_not_stop_the_server_from_starting():
    """
    Un server fără depozit răspunde `reputation_unavailable` — stare declarată,
    nu defect. Oprit la pornire, ar cupla disponibilitatea telemetriei de cea a
    reputației, adică exact decizia refuzată la F4, mutată cu un nivel mai sus.
    """
    from app.main import warm_reputation_snapshot

    warm_reputation_snapshot()  # fixture-ul din conftest lasă calea spre un fișier absent


# ── Vocabularul, ca mulțime închisă ──────────────────────────────────────────

def test_the_vocabulary_carries_no_benign_term():
    """
    Aceeași regulă ca la `Knowledge`, o treaptă mai sus: interdicția din depozit
    n-ar apăra nimic dacă valoarea produsă din el ar reintroduce termenul.
    """
    for valoare in reputation_disposition.VALID_DISPOSITIONS:
        assert not BENIGNITATE.search(valoare), (
            f"Dispoziția {valoare!r} conține un termen de benignitate."
        )


def test_the_vocabulary_is_a_bijection_with_the_two_axes():
    """
    Patru celule plus indisponibilitatea. O valoare în plus sau în minus
    înseamnă ori o celulă pierdută — adică enumul refuzat la R1 — ori o stare
    inventată, pe care nimic din depozit n-o poate produce.
    """
    assert len(reputation_disposition.VALID_DISPOSITIONS) == 5
