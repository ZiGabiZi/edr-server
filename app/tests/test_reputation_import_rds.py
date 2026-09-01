"""
Importul RDS — idempotent, reluabil, și incapabil să spună curat.

Testele rulează contra unei baze RDS false, construită aici. Nu e o comoditate:
ediția reală are zeci de gigaocteți și se schimbă lunar, deci un test legat de
ea ar fi și lent, și verde-sau-roșu în funcție de ce a publicat NIST săptămâna
asta. Ce se verifică e comportamentul importatorului, iar acela nu depinde de
conținutul listei.

Falsul imită RDSv3 în singurele privințe care contează pentru cod: un tabel FILE
cu sha256 ca text hexazecimal cu majuscule, plus un tabel auxiliar care are și el
o coloană sha256 — ca descoperirea de schemă să aibă pe ce greși.

Cele patru proprietăți:
    1. o a doua rulare nu schimbă nimic — aceeași amprentă;
    2. o rulare întreruptă continuă de unde a rămas și ajunge în aceeași stare;
    3. un hash deja malițios capătă known_software fără să piardă amenințarea;
    4. RDS nu scrie niciodată pe axa de amenințare.
"""

import sqlite3

import pytest

import app.services.reputation_build as reputation_build
import app.services.reputation_import_rds as rds
import app.services.reputation_store as reputation_store


HASHES = [bytes([i]) * 32 for i in range(1, 21)]


@pytest.fixture
def sursa_rds(tmp_path):
    """
    O bază RDS falsă: tabelul FILE, plus unul auxiliar care ar putea deruta
    descoperirea de schemă dacă aceasta ar alege primul candidat, nu pe cel mare.
    """
    cale = tmp_path / "RDS_fals_modern_minimal.db"
    connection = sqlite3.connect(str(cale))

    connection.execute("CREATE TABLE MFG (sha256 TEXT, name TEXT)")
    connection.execute("INSERT INTO MFG VALUES ('deadbeef', 'un producator')")

    connection.execute("CREATE TABLE FILE (sha256 TEXT, file_name TEXT, package_id INT)")
    connection.executemany(
        "INSERT INTO FILE VALUES (?, ?, 1)",
        [(h.hex().upper(), "componenta_%d.dll" % i) for i, h in enumerate(HASHES)],
    )
    # Indexul pe care importul il cere: reluarea citeste in ordinea hash-ului.
    connection.execute("CREATE INDEX idx_file_sha256 ON FILE (sha256)")

    connection.commit()
    connection.close()

    return cale


@pytest.fixture
def depozit(tmp_path):
    connection = reputation_build.create_working_database(tmp_path / "lucru.db")

    yield connection

    connection.close()


def _numara(depozit, unde="1 = 1"):
    (n,) = depozit.execute("SELECT COUNT(*) FROM reputation WHERE " + unde).fetchone()

    return n


# ── Descoperirea schemei sursei ─────────────────────────────────────────────

def test_the_file_table_is_discovered_not_assumed(sursa_rds):
    """
    Editia importata nu exista inca in momentul scrierii codului.

    Un nume de tabel scris de mana ar transforma prima schimbare de format a
    NIST intr-o eroare la mijlocul unui import de ore.
    """
    source = sqlite3.connect(str(sursa_rds))
    tabel, coloana = rds.discover_file_table(source)
    source.close()

    assert (tabel, coloana) == ("FILE", "sha256")


def test_a_source_without_sha256_is_refused(tmp_path):
    strain = tmp_path / "altceva.db"
    connection = sqlite3.connect(str(strain))
    connection.execute("CREATE TABLE lucruri (md5 TEXT)")
    connection.commit()
    connection.close()

    source = sqlite3.connect(str(strain))

    with pytest.raises(rds.RdsImportError):
        rds.discover_file_table(source)

    source.close()


# ── Ce scrie importul, și ce nu ─────────────────────────────────────────────

def test_the_import_writes_only_the_novelty_axis(sursa_rds, depozit):
    """
    CORPUS.md 5.4: potrivirea în RDS nu poate produce verdictul curat, dar nici
    pe cel malițios. RDS spune un singur lucru — fișierul nu e nou.
    """
    rds.import_rds(sursa_rds, depozit, "test-1")

    assert _numara(depozit, "known_software = 1") == len(HASHES)
    assert _numara(depozit, "known_malicious = 1") == 0


def test_an_uppercase_hex_hash_becomes_32_raw_bytes(sursa_rds, depozit):
    """RDS ține hash-urile ca text cu majuscule; depozitul le ține ca octeți."""
    rds.import_rds(sursa_rds, depozit, "test-1")

    (stocat,) = depozit.execute(
        "SELECT sha256 FROM reputation WHERE sha256 = ?", (HASHES[0],)
    ).fetchone()

    assert stocat == HASHES[0]
    assert len(stocat) == 32


def test_an_unreadable_hash_is_skipped_not_fatal(tmp_path, depozit):
    """
    Un rând stricat în sursă nu are voie să oprească un import de ore. Se sare
    peste el și se numără; oprirea ar transforma o imperfecțiune a listei
    externe într-o zi pierdută.
    """
    cale = tmp_path / "stricat.db"
    connection = sqlite3.connect(str(cale))
    connection.execute("CREATE TABLE FILE (sha256 TEXT)")
    connection.executemany(
        "INSERT INTO FILE VALUES (?)",
        [(HASHES[0].hex(),), ("nu-e-un-hash",), (HASHES[1].hex(),)],
    )
    connection.execute("CREATE INDEX idx_file_sha256 ON FILE (sha256)")
    connection.commit()
    connection.close()

    total = rds.import_rds(cale, depozit, "test-1")

    assert total == 2


# ── Suprapunerea celor două axe ─────────────────────────────────────────────

def test_a_known_malicious_file_keeps_its_threat_label(sursa_rds, depozit):
    """
    Celula interesantă din 2x2, și motivul pentru care importul e UPSERT și nu
    INSERT OR IGNORE.

    Cu OR IGNORE, un hash deja marcat malițios ar fi sărit, n-ar primi niciodată
    known_software, iar suprapunerea ar dispărea tăcut — în funcție de ordinea
    importurilor, ceea ce face rezultatul plauzibil în ambele ordini și bug-ul
    aproape imposibil de observat.
    """
    bazaar = reputation_build.record_source(
        depozit, "MalwareBazaar", "threat", "inventar-test", 1
    )
    depozit.execute(
        "INSERT INTO reputation (sha256, known_malicious, threat_source) "
        "VALUES (?, 1, ?)",
        (HASHES[0], bazaar),
    )
    depozit.commit()

    rds.import_rds(sursa_rds, depozit, "test-1")

    (software, amenintare, sursa_amenintare) = depozit.execute(
        "SELECT known_software, known_malicious, threat_source FROM reputation "
        "WHERE sha256 = ?",
        (HASHES[0],),
    ).fetchone()

    assert (software, amenintare) == (1, 1)
    assert sursa_amenintare == bazaar


# ── Idempotență și reluare ──────────────────────────────────────────────────

def test_a_second_run_changes_nothing(sursa_rds, depozit):
    """
    Criteriul de ieșire din P2.2.4: reimportul aceleiași surse nu schimbă nimic.

    Se compară amprenta de CONȚINUT, nu cea a fișierului. Prima versiune a
    testului o compara pe a doua și a picat — corect, fiindcă fișierul poartă
    momentul construirii și al importului, deci două rulări identice la ore
    diferite produc fișiere diferite la octet. Identitatea și reproductibilitatea
    erau două întrebări sub același nume.
    """
    rds.import_rds(sursa_rds, depozit, "test-1")
    intai = reputation_store.content_fingerprint(depozit)

    rds.import_rds(sursa_rds, depozit, "test-1")
    apoi = reputation_store.content_fingerprint(depozit)

    assert intai == apoi


def test_the_file_fingerprint_still_moves_with_the_clock(sursa_rds, depozit, tmp_path):
    """
    Reversul, ca distincția să nu fie doar o vorbă: același conținut, două
    sigilări, două amprente de fișier diferite. De aceea `METRICS.md` 8 cere
    amprenta fișierului — ea spune ce a citit serverul, nu ce ar fi putut citi.
    """
    rds.import_rds(sursa_rds, depozit, "test-1")

    intai = reputation_build.seal(depozit, tmp_path / "intai.db")
    apoi = reputation_build.seal(depozit, tmp_path / "apoi.db")

    assert intai != apoi


def test_a_resumed_import_matches_an_uninterrupted_one(sursa_rds, tmp_path, monkeypatch):
    """
    Reluarea nu e doar terminare, e terminare în ACEEAȘI stare.

    Un import întrerupt și reluat trebuie să dea exact conținutul unuia care a
    mers dintr-o bucată. Altfel reluabilitatea ar fi o promisiune despre timp,
    nu despre rezultat.
    """
    monkeypatch.setattr(rds, "BATCH", 3)

    intrerupt = reputation_build.create_working_database(tmp_path / "intrerupt.db")
    rds.import_rds(sursa_rds, intrerupt, "test-1", limit=3)
    rds.import_rds(sursa_rds, intrerupt, "test-1", limit=3)
    rds.import_rds(sursa_rds, intrerupt, "test-1")

    dintr_o_bucata = reputation_build.create_working_database(tmp_path / "intreg.db")
    rds.import_rds(sursa_rds, dintr_o_bucata, "test-1")

    a = reputation_store.content_fingerprint(intrerupt)
    b = reputation_store.content_fingerprint(dintr_o_bucata)

    intrerupt.close()
    dintr_o_bucata.close()

    assert a == b


def test_an_interrupted_import_resumes_where_it_stopped(sursa_rds, depozit, monkeypatch):
    """
    Zeci de milioane de rânduri nu se importă dintr-o singură încercare fericită.

    Se importă un lot, se oprește, se reia — și rezultatul trebuie să fie
    identic cu al unei rulări neîntrerupte. Lotul e făcut mic ca întreruperea să
    cadă la mijloc, nu după ultimul rând.
    """
    monkeypatch.setattr(rds, "BATCH", 5)

    rds.import_rds(sursa_rds, depozit, "test-1", limit=5)
    dupa_intrerupere = _numara(depozit)

    assert 0 < dupa_intrerupere < len(HASHES)

    total = rds.import_rds(sursa_rds, depozit, "test-1")

    assert total == len(HASHES)


def test_the_cursor_advances_and_is_a_hash(sursa_rds, depozit, monkeypatch):
    monkeypatch.setattr(rds, "BATCH", 5)
    rds.import_rds(sursa_rds, depozit, "test-1", limit=5)

    (cursor,) = depozit.execute(
        "SELECT value FROM snapshot_meta WHERE key = ?", (rds.CURSOR_KEY,)
    ).fetchone()

    assert len(cursor) == 64
    assert bytes.fromhex(cursor) in HASHES


# ── Ce se declară lângă cifră ───────────────────────────────────────────────

def test_the_row_count_describes_the_store_not_the_import(sursa_rds, depozit):
    """
    Un contor incrementat ar număra de două ori rândurile atinse de două rulări
    reluate, iar cifra aia ajunge în METRICS.md 8, lângă rezultate.
    """
    rds.import_rds(sursa_rds, depozit, "test-1")
    rds.import_rds(sursa_rds, depozit, "test-1")

    (randuri,) = depozit.execute(
        "SELECT row_count FROM sources WHERE name = ?", (rds.SOURCE_NAME,)
    ).fetchone()

    assert randuri == len(HASHES)


def test_the_source_version_is_recorded(sursa_rds, depozit, tmp_path):
    """
    Amprenta acoperă fișierul livrat, nu procesul. Versiunea sursei transformă
    nu se poate reproduce în se poate reproduce dacă mai există ediția asta.
    """
    rds.import_rds(sursa_rds, depozit, "2026.03.1")

    sigilat = tmp_path / "sigilat.db"
    reputation_build.seal(depozit, sigilat)

    connection = reputation_store.open_readonly(str(sigilat))
    surse = connection.execute(
        "SELECT name, axis, version FROM sources"
    ).fetchall()
    connection.close()

    assert surse == [(rds.SOURCE_NAME, "software", "2026.03.1")]


def test_a_lookup_reports_the_source_by_name(sursa_rds, depozit, tmp_path, monkeypatch):
    """
    Sursa e stocată ca întreg, dar apelantul primește numele: un identificator
    intern n-ar putea fi selectat într-o ablație.
    """
    rds.import_rds(sursa_rds, depozit, "2026.03.1")

    sigilat = tmp_path / "sigilat.db"
    reputation_build.seal(depozit, sigilat)

    monkeypatch.setenv(reputation_store.SNAPSHOT_PATH_ENV, str(sigilat))
    reputation_store.close()

    try:
        raspuns = reputation_store.lookup(HASHES[0])

        assert raspuns.known_software is True
        assert raspuns.software_source == rds.SOURCE_NAME
        assert raspuns.known_malicious is False
        assert raspuns.novel is False
    finally:
        reputation_store.reset_for_tests()


def test_an_unindexed_source_is_refused_before_the_first_row(tmp_path, depozit):
    """
    Diferenta dintre ore si zile, prinsa inainte de primul rand.

    Fara index pe coloana de hash, fiecare lot ar re-sorta tot tabelul - 432 de
    milioane de randuri, de peste 1400 de ori. Importul n-ar esua, ar parea doar
    lent, iar asta s-ar observa dupa cateva ore, cu 18 GB deja descarcati si 100
    GB deja dezarhivati. Mesajul poarta comanda care repara.
    """
    cale = tmp_path / "neindexat.db"
    connection = sqlite3.connect(str(cale))
    connection.execute("CREATE TABLE FILE (sha256 TEXT)")
    connection.execute("INSERT INTO FILE VALUES (?)", (HASHES[0].hex(),))
    connection.commit()
    connection.close()

    with pytest.raises(rds.RdsImportError) as eroare:
        rds.import_rds(cale, depozit, "test-1")

    assert "CREATE INDEX" in str(eroare.value)
    assert _numara(depozit) == 0
