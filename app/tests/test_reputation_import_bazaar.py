"""
Importul MalwareBazaar — axa de amenințare, și capcana pe care o închide.

Cea mai importantă proprietate testată aici nu e o funcționalitate, e un refuz:
modulul nu acceptă un fișier de selecție. Selecția corpusului a fost făcută DIN
inventar, deci un depozit alimentat cu selecția ar conține exact corpusul și
nimic altceva — fiecare potrivire garantată prin construcție, fiecare cifră
lipsită de sens. Un avertisment în documentație ar fi fost citit o dată și sărit
a doua oară; refuzul structural nu se poate sări.

Restul: cele două axe rămân independente când același hash e în amândouă, iar
supra-importul (decizia R2) chiar aduce familia și prima observare.
"""

import json

import pytest

import app.services.reputation_build as reputation_build
import app.services.reputation_import_bazaar as bazaar
import app.services.reputation_import_rds as rds
import app.services.reputation_store as reputation_store


HASHES = [bytes([i]) * 32 for i in range(1, 6)]


def _inventar(tmp_path, chei=None, nume="inventar.json"):
    chei = HASHES if chei is None else chei
    cale = tmp_path / nume
    cale.write_text(
        json.dumps({
            "generated_at": "2026-08-31T11:12:26+00:00",
            "source": "MalwareBazaar (abuse.ch) API v1",
            "count": len(chei),
            "samples": {
                h.hex(): {
                    "sha256": h.hex()[:56],   # trunchiat, ca in inventarul real
                    "signature": "AgentTesla",
                    "first_seen": "2026-08-31 08:34:20",
                    "file_name": "mostra_%d.vbs" % i,
                    "label": "malicious",
                }
                for i, h in enumerate(chei)
            },
        }),
        encoding="utf-8",
    )

    return cale


@pytest.fixture
def depozit(tmp_path):
    connection = reputation_build.create_working_database(tmp_path / "lucru.db")

    yield connection

    connection.close()


# ── Refuzul care contează cel mai mult ──────────────────────────────────────

def test_a_corpus_selection_is_refused(tmp_path, depozit):
    """
    Selecția a fost făcută DIN inventar. Alimentată înapoi, ar face fiecare
    potrivire garantată prin construcție.
    """
    cale = tmp_path / "selectie.json"
    cale.write_text(
        json.dumps({
            "source_inventory": "C:\\Malware_Samples\\inventar\\inventar.json",
            "count": 1,
            "samples": [{"sha256": HASHES[0].hex()}],
        }),
        encoding="utf-8",
    )

    with pytest.raises(bazaar.BazaarImportError) as eroare:
        bazaar.import_bazaar(cale, depozit)

    assert "SELECTION" in str(eroare.value)
    assert "source_inventory" in str(eroare.value)


# ── Ce scrie importul ───────────────────────────────────────────────────────

def test_the_import_writes_only_the_threat_axis(tmp_path, depozit):
    cifre = bazaar.import_bazaar(_inventar(tmp_path), depozit)

    assert cifre["randuri_pe_axa"] == len(HASHES)

    (software,) = depozit.execute(
        "SELECT COUNT(*) FROM reputation WHERE known_software = 1"
    ).fetchone()

    assert software == 0


def test_the_hash_comes_from_the_key_not_the_field(tmp_path, depozit):
    """
    În inventarul real, campul sha256 din interiorul intrarii e trunchiat la
    unele mostre, in timp ce cheia dictionarului e intotdeauna hash-ul intreg.
    Citit din camp, importul ar fi produs randuri care nu se potrivesc niciodata
    cu nimic - fara nicio eroare, doar cu zero potriviri la evaluare.
    """
    bazaar.import_bazaar(_inventar(tmp_path), depozit)

    (gasit,) = depozit.execute(
        "SELECT COUNT(*) FROM reputation WHERE sha256 = ?", (HASHES[0],)
    ).fetchone()

    assert gasit == 1


def test_the_over_import_brings_family_and_first_seen(tmp_path, depozit):
    """Decizia R2: o coloana nefolosita costa spatiu, una lipsa costa reimport."""
    bazaar.import_bazaar(_inventar(tmp_path), depozit)

    familie, prima, nume = depozit.execute(
        "SELECT family, first_seen, representative_name FROM reputation "
        "WHERE sha256 = ?",
        (HASHES[0],),
    ).fetchone()

    assert familie == "AgentTesla"
    assert prima == "2026-08-31 08:34:20"
    assert nume.endswith(".vbs")


def test_the_version_comes_from_the_inventory_not_the_operator(tmp_path, depozit):
    """
    Versiunea e o proprietate a datelor. Un numar tastat de mana ar putea
    descrie alt inventar decat cel citit.
    """
    cifre = bazaar.import_bazaar(_inventar(tmp_path), depozit)

    assert cifre["versiune"] == "2026-08-31T11:12:26+00:00"

    (versiune,) = depozit.execute(
        "SELECT version FROM sources WHERE name = ?", (bazaar.SOURCE_NAME,)
    ).fetchone()

    assert versiune == "2026-08-31T11:12:26+00:00"


# ── Cele două axe împreună ──────────────────────────────────────────────────

def test_a_file_in_both_sources_keeps_both_axes(tmp_path, depozit):
    """
    Celula de suprapunere, de data asta atinsă din cealaltă direcție: RDS întâi,
    apoi MalwareBazaar. Ordinea nu are voie să schimbe rezultatul.
    """
    import sqlite3

    sursa_rds = tmp_path / "rds.db"
    c = sqlite3.connect(str(sursa_rds))
    c.execute("CREATE TABLE FILE (sha256 TEXT)")
    c.executemany("INSERT INTO FILE VALUES (?)", [(HASHES[0].hex().upper(),)])
    c.execute("CREATE INDEX i ON FILE (sha256)")
    c.commit()
    c.close()

    rds.import_rds(sursa_rds, depozit, "2026.03.1")
    cifre = bazaar.import_bazaar(_inventar(tmp_path), depozit)

    assert cifre["suprapunere_cu_rds"] == 1

    software, amenintare = depozit.execute(
        "SELECT known_software, known_malicious FROM reputation WHERE sha256 = ?",
        (HASHES[0],),
    ).fetchone()

    assert (software, amenintare) == (1, 1)


def test_the_reverse_order_gives_the_same_result(tmp_path, depozit):
    """MalwareBazaar întâi, RDS după. Același rezultat, altfel ordinea ar fi un parametru ascuns."""
    import sqlite3

    bazaar.import_bazaar(_inventar(tmp_path), depozit)

    sursa_rds = tmp_path / "rds.db"
    c = sqlite3.connect(str(sursa_rds))
    c.execute("CREATE TABLE FILE (sha256 TEXT)")
    c.executemany("INSERT INTO FILE VALUES (?)", [(HASHES[0].hex().upper(),)])
    c.execute("CREATE INDEX i ON FILE (sha256)")
    c.commit()
    c.close()

    rds.import_rds(sursa_rds, depozit, "2026.03.1")

    software, amenintare, familie = depozit.execute(
        "SELECT known_software, known_malicious, family FROM reputation "
        "WHERE sha256 = ?",
        (HASHES[0],),
    ).fetchone()

    assert (software, amenintare) == (1, 1)
    assert familie == "AgentTesla"


# ── Idempotență ─────────────────────────────────────────────────────────────

def test_a_second_run_changes_nothing(tmp_path, depozit):
    cale = _inventar(tmp_path)

    bazaar.import_bazaar(cale, depozit)
    intai = reputation_store.content_fingerprint(depozit)

    bazaar.import_bazaar(cale, depozit)
    apoi = reputation_store.content_fingerprint(depozit)

    assert intai == apoi


def test_a_lookup_reports_both_sources_by_name(tmp_path, depozit, monkeypatch):
    bazaar.import_bazaar(_inventar(tmp_path), depozit)

    sigilat = tmp_path / "reputation.db"
    reputation_build.seal(depozit, sigilat)

    monkeypatch.setenv(reputation_store.SNAPSHOT_PATH_ENV, str(sigilat))
    reputation_store.close()

    try:
        raspuns = reputation_store.lookup(HASHES[0])

        assert raspuns.known_malicious is True
        assert raspuns.threat_source == bazaar.SOURCE_NAME
        assert raspuns.known_software is False
        assert raspuns.family == "AgentTesla"
    finally:
        reputation_store.reset_for_tests()
