"""
Banda minimă la T0 (P2.6): ce decide, ce nu decide, și unde NU ajunge.

Testele fixează SENSUL deciziilor B1–B10. Mecanica — că se scrie un rând — ar
trece la fel de bine cu un tabel greșit, iar tabelele greșite de aici sunt toate
în direcția care flatează afirmația centrală sau ascunde o ratare:

    1. dacă prevalența ar putea depăși axa de amenințare, un malware răspândit
       ar ieși închis ca orice fișier comun;
    2. dacă a doua vedere pe aceeași mașină ar escalada din nou, banda ar plăti
       de două ori același conținut;
    3. dacă reputația indisponibilă ar escalada sau ar moșteni, o pană a
       depozitului ar arăta ca un corpus nou;
    4. dacă decizia ar urca pe fir, contractul s-ar schimba fără versiune.
"""

import hashlib
import re

import pytest

import app.services.event_store as event_store
import app.services.reputation_build as reputation_build
import app.services.reputation_disposition as reputation_disposition
import app.services.reputation_store as reputation_store
import app.services.uncertainty_band as band
from app.services.band_metrics import compute_band_metrics


MALICIOS = hashlib.sha256(b"banda-amenintare").digest()
SOFTWARE = hashlib.sha256(b"banda-software").digest()
AMBELE = hashlib.sha256(b"banda-ambele").digest()
NECUNOSCUT = hashlib.sha256(b"banda-nicaieri").digest()

BENIGNITATE = re.compile(r"clean|benign|safe|curat", re.IGNORECASE)


@pytest.fixture
def instantaneu(tmp_path, monkeypatch):
    """Un instantaneu sigilat cu cele trei celule ocupate ale 2×2-ului."""
    lucru = reputation_build.create_working_database(tmp_path / "lucru.db")
    software_id = reputation_build.record_source(lucru, "NSRL RDS", "software", "t", 2)
    threat_id = reputation_build.record_source(lucru, "MalwareBazaar", "threat", "t", 2)

    lucru.execute(
        "INSERT INTO reputation (sha256, known_software, software_source, "
        "known_malicious, threat_source) VALUES (?, 0, NULL, 1, ?)",
        (MALICIOS, threat_id),
    )
    lucru.execute(
        "INSERT INTO reputation (sha256, known_software, software_source, "
        "known_malicious, threat_source) VALUES (?, 1, ?, 0, NULL)",
        (SOFTWARE, software_id),
    )
    lucru.execute(
        "INSERT INTO reputation (sha256, known_software, software_source, "
        "known_malicious, threat_source) VALUES (?, 1, ?, 1, ?)",
        (AMBELE, software_id, threat_id),
    )
    lucru.commit()

    destinatie = tmp_path / "reputatie.db"
    reputation_build.seal(lucru, destinatie)
    lucru.close()

    monkeypatch.setenv(reputation_store.SNAPSHOT_PATH_ENV, str(destinatie))
    reputation_store.reset_for_tests()
    reputation_disposition.reset_for_tests()

    yield destinatie

    reputation_store.reset_for_tests()


def _inroleaza(client, agent_id):
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


def _fisier(client, agent_id, digest, client_event_id):
    raspuns = client.post(
        "/api/events",
        json={
            "agent_id": agent_id,
            "event_type": "file_created",
            "client_event_id": client_event_id,
            "file_path": "C:\\EDR_Test\\proba.exe",
            "sha256": digest.hex(),
            "hash_status": "ok",
            "file_size": 2048,
            "occurred_at": "2026-11-17T10:00:00+00:00",
        },
    )
    assert raspuns.status_code == 200, raspuns.text
    return raspuns


def _parc(client, primul, cate):
    """Primul agent plus încă `cate - 1`, în ordinea fixată."""
    return [primul] + [_inroleaza(client, f"agent-{i}") for i in range(2, cate + 1)]


def _decizii():
    return [row["decision"] for _, row in sorted(event_store.band_by_event().items())]


def _banda(client):
    raspuns = client.get("/api/metrics/disclosure")
    assert raspuns.status_code == 200, raspuns.text
    return raspuns.json()["band"]


# ── Tabelul, pur ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("policy", band.POLICIES)
@pytest.mark.parametrize("prior", [False, True])
@pytest.mark.parametrize(
    "disposition",
    [reputation_disposition.KNOWN_MALICIOUS, reputation_disposition.BOTH_AXES],
)
def test_the_threat_axis_closes_as_threat_whatever_the_prevalence(
    disposition, prior, policy
):
    """B2: rândul de amenințare e primul, deci prevalența nu-l poate depăși."""
    assert band.decide(disposition, prior, policy) == band.CLOSE_THREAT


@pytest.mark.parametrize("policy", band.POLICIES)
@pytest.mark.parametrize("prior", [False, True])
def test_an_unavailable_reputation_is_held_never_escalated_nor_inherited(
    prior, policy
):
    """
    B4: o pană a depozitului nu e noutate. Escaladată, ar arăta ca un corpus
    nou; moștenită, ar ascunde că nimeni n-a fost întrebat.
    """
    decision = band.decide(reputation_disposition.REPUTATION_UNAVAILABLE, prior, policy)

    assert decision == band.HOLD


def test_a_value_outside_the_vocabulary_gets_no_decision():
    """O valoare nouă absorbită într-o celulă veche ar schimba cifra fără urmă."""
    assert band.decide("o_dispozitie_noua", False) is None
    assert band.decide(None, False) is None


def test_the_strict_policy_treats_known_software_as_novel():
    """B10: varianta strictă e cealaltă politică pre-înregistrată."""
    soft = reputation_disposition.KNOWN_SOFTWARE

    assert band.decide(soft, False) == band.CLOSE_KNOWN
    assert band.decide(soft, True) == band.CLOSE_KNOWN
    assert band.decide(soft, False, band.STRICT_POLICY) == band.ESCALATE
    assert band.decide(soft, True, band.STRICT_POLICY) == band.INHERIT


def test_no_decision_and_no_policy_row_carries_a_benign_word():
    """B3: `close_known` spune că nu escaladează pentru noutate, nu că e bun."""
    texte = list(band.DECISIONS) + [
        str(band.describe_policy(policy)) for policy in band.POLICIES
    ]

    for text in texte:
        assert BENIGNITATE.search(text) is None, text


# ── Pe calea de ingestie ─────────────────────────────────────────────────────

def test_a_malicious_file_on_five_machines_is_closed_as_threat_on_each(
    client, registered_agent_id, instantaneu
):
    """Cazul cerut explicit: răspândirea nu face dintr-o amenințare un fișier comun."""
    for i, agent in enumerate(_parc(client, registered_agent_id, 5), 1):
        _fisier(client, agent, MALICIOS, f"evt-{i}")

    assert _decizii() == [band.CLOSE_THREAT] * 5


def test_an_unknown_file_on_five_machines_escalates_exactly_once(
    client, registered_agent_id, instantaneu
):
    """
    „Un fișier escaladează o dată, parcul primește la T0": o escaladare, patru
    moșteniri. Dacă e malițios, se compară pe amprentă (`METRICS.md` §4.1), deci
    o eventuală ratare e una, nu cinci.
    """
    for i, agent in enumerate(_parc(client, registered_agent_id, 5), 1):
        _fisier(client, agent, NECUNOSCUT, f"evt-{i}")

    assert _decizii() == [band.ESCALATE] + [band.INHERIT] * 4

    tabel = _banda(client)
    assert tabel["decisions"][band.POLICY][band.ESCALATE] == 1
    assert tabel["decisions"][band.POLICY][band.INHERIT] == 4
    assert tabel["inherited_without_escalation"] == 0
    assert tabel["stored_matches_table"] is True


def test_a_second_sighting_on_the_same_machine_does_not_escalate_again(
    client, registered_agent_id, instantaneu
):
    """
    B5: a doua vedere pe ACEEAȘI mașină are tot `agents == 1`. Decisă după
    `agents`, banda ar escalada de două ori același conținut, iar §3.6 ar număra
    două prime vederi pentru un singur conținut.
    """
    _fisier(client, registered_agent_id, NECUNOSCUT, "evt-1")
    a_doua = _fisier(client, registered_agent_id, NECUNOSCUT, "evt-2")

    assert a_doua.json()["event"]["prevalence"]["agents"] == 1
    assert _decizii() == [band.ESCALATE, band.INHERIT]

    prevalenta = client.get("/api/metrics/disclosure").json()["prevalence"]
    assert prevalenta["events_at_first_sighting"] == 1
    assert prevalenta["events_at_first_sighting"] == prevalenta["distinct_hashes"]
    assert prevalenta["first_sighting_inferred_from_agents"] == 0


@pytest.mark.parametrize("cate", [1, 5])
def test_known_software_is_closed_the_same_on_one_machine_and_on_five(
    client, registered_agent_id, instantaneu, cate
):
    """Prevalența nu schimbă nimic pentru RDS: nici nu închide, nici nu deschide."""
    for i, agent in enumerate(_parc(client, registered_agent_id, cate), 1):
        _fisier(client, agent, SOFTWARE, f"evt-{i}")

    assert _decizii() == [band.CLOSE_KNOWN] * cate


def test_a_retransmission_keeps_the_decision_of_the_first_arrival(
    client, registered_agent_id, instantaneu
):
    """M9, la bandă: același eveniment are o singură decizie, nu una per sosire."""
    _fisier(client, registered_agent_id, NECUNOSCUT, "evt-1")
    _fisier(client, registered_agent_id, NECUNOSCUT, "evt-1")

    assert _decizii() == [band.ESCALATE]


def test_without_a_snapshot_the_event_is_held(client, registered_agent_id):
    """Fără instantaneu, depozitul n-a putut fi întrebat: `hold`, nu `escalate`."""
    _fisier(client, registered_agent_id, NECUNOSCUT, "evt-1")

    assert _decizii() == [band.HOLD]


def test_the_decision_never_reaches_the_wire(client, registered_agent_id, instantaneu):
    """
    B6: răspunsul rutei e contract (v12). Decizia stă în `event_band`, iar forma
    ei pe fir e `next_action`, care rămâne "none".
    """
    raspuns = _fisier(client, registered_agent_id, NECUNOSCUT, "evt-1").json()
    text = str(raspuns)

    assert raspuns["next_action"] == "none"
    assert "band" not in raspuns["event"]
    assert "prior_sighting" not in raspuns["event"]["prevalence"]

    for cuvant in band.DECISIONS + (band.POLICY,):
        assert cuvant not in text, f"{cuvant!r} a ajuns pe fir: {text[:200]}"

    evenimente = client.get("/api/events").json()["events"]
    assert all("band" not in e for e in evenimente)


def test_an_inheritance_with_nobody_to_inherit_from_is_counted(
    client, registered_agent_id, instantaneu
):
    """
    Registrul știe conținutul, dar niciun eveniment nu l-a escaladat — o
    sesiune de depanare, o primă vedere `hold`. `inherit` rămâne decizia
    tabelului, iar golul se vede în cifră, nu se repară tăcut.
    """
    event_store.record_and_count_sighting(
        NECUNOSCUT, "agent-de-depanare", "2026-11-01T00:00:00+00:00"
    )

    _fisier(client, registered_agent_id, NECUNOSCUT, "evt-1")

    assert _decizii() == [band.INHERIT]
    assert _banda(client)["inherited_without_escalation"] == 1


# ── Cifra publicată ──────────────────────────────────────────────────────────

def test_the_cells_let_the_strict_policy_be_read_from_the_same_run(
    client, registered_agent_id, instantaneu
):
    """
    B8/B10: tabelul numără celulele, deci cealaltă politică pre-înregistrată se
    citește fără altă rulare.
    """
    parc = _parc(client, registered_agent_id, 3)

    for i, agent in enumerate(parc, 1):
        _fisier(client, agent, SOFTWARE, f"soft-{i}")
        _fisier(client, agent, AMBELE, f"ambele-{i}")

    _fisier(client, parc[0], NECUNOSCUT, "nou-1")

    tabel = _banda(client)
    declarata = tabel["decisions"][band.POLICY]
    stricta = tabel["decisions"][band.STRICT_POLICY]

    assert tabel["events_with_hash"] == tabel["events_with_band"] == 7
    assert declarata[band.CLOSE_KNOWN] == 3
    assert declarata[band.CLOSE_THREAT] == 3
    assert declarata[band.ESCALATE] == 1

    assert stricta[band.CLOSE_KNOWN] == 0
    assert stricta[band.ESCALATE] == 2, "RDS escaladează o dată, apoi moștenește"
    assert stricta[band.INHERIT] == 2
    assert stricta[band.CLOSE_THREAT] == 3

    celule = {
        (c["disposition"], c["prior_sighting"], c["agents_at_arrival"]): c["events"]
        for c in tabel["cells"]
    }
    assert celule[(reputation_disposition.KNOWN_SOFTWARE, True, 3)] == 1


def test_events_written_before_the_band_are_a_gap_not_a_decision():
    """Ca la §2.1: evenimentele fără rând nu primesc o decizie implicită."""
    evenimente = [
        {
            "event_id": 1,
            "sha256": NECUNOSCUT.hex(),
            "reputation": {"disposition": "unknown"},
            "prevalence": {"agents": 1},
        },
        {"event_id": 2, "sha256": None},
        # Scris înainte de P2.3: hash, dar nicio dispoziție.
        {"event_id": 3, "sha256": SOFTWARE.hex(), "prevalence": {"agents": 1}},
    ]

    tabel = compute_band_metrics(evenimente, {}, set())

    assert tabel["events_with_hash"] == 2
    assert tabel["events_with_band"] == 0
    assert tabel["hashed_events_without_band"] == 2
    assert tabel["without_band_by_disposition"] == {
        "unknown": 1,
        "without_disposition": 1,
    }, "lipsa dispoziției nu are voie să apară ca cheia 'None'"
    assert sum(tabel["decisions"][band.POLICY].values()) == 0


def test_a_table_changed_under_a_finished_run_is_reported():
    """
    Decizia scrisă la ingestie trebuie să iasă identic din celule. Dacă tabelul
    din cod s-a schimbat după rulare, cifra ar descrie altă politică decât cea
    care a decis.
    """
    evenimente = [
        {
            "event_id": 1,
            "sha256": SOFTWARE.hex(),
            "reputation": {"disposition": "known_software"},
            "prevalence": {"agents": 1},
        }
    ]
    scris_altfel = {1: {"policy": band.POLICY, "decision": "escalate", "prior_sighting": False}}

    assert compute_band_metrics(evenimente, scris_altfel, set())["stored_matches_table"] is False
