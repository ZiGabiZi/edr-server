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
