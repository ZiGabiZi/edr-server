"""
Instantaneul de reputație — ce nu se poate exprima, și ce nu se poate schimba.

Testele de aici nu verifică funcționalitate; verifică IMPOSIBILITĂȚI. Depozitul
e gol la P2.2.3, deci nu există încă nimic de căutat în el. Ce există sunt patru
reguli care, o dată încălcate, nu se mai repară fără reimport — iar reimportul
înseamnă instantaneu nou, deci toate măsurătorile de dinainte descriu alt sistem:

    1. hash-ul e 32 de octeți bruți, nu 64 de caractere hexazecimale;
    2. cele două axe se stochează separat, iar o axă adevărată poartă sursă;
    3. fișierul sigilat refuză scrierea, nu doar o descurajează;
    4. amprenta e stabilă la recalculare și se schimbă dacă fișierul se schimbă.

Plus una care e o regulă de vocabular, nu de date: `Knowledge` nu are câmp
`clean`. `CORPUS.md` §5.4 interzice verdictul „curat" derivat din apartenența la
RDS; un câmp cu numele ăla ar fi folosit exact așa la prima grabă, iar testul e
singurul mod în care interdicția devine imposibil de încălcat din neatenție.
"""

import sqlite3

import pytest

import app.services.reputation_build as reputation_build
import app.services.reputation_store as reputation_store


TEST_HASH = bytes(range(32))
OTHER_HASH = bytes(range(32, 64))

RDS = "NSRL RDS"
BAZAAR = "MalwareBazaar"


def sid(connection, name):
    """Identificatorul unei surse consemnate. Cheia straina cere intregul, nu numele."""
    (source_id,) = connection.execute(
        "SELECT source_id FROM sources WHERE name = ?", (name,)
    ).fetchone()

    return source_id


@pytest.fixture
def snapshot(tmp_path, monkeypatch):
    """
    Un instantaneu gol, sigilat, pe disc real.

    Trebuie să fie pe disc: `mode=ro&immutable=1` e o proprietate a fișierului,
    iar o bază din memorie n-ar putea nici să o aibă, nici să o contrazică.
    """
    destinatie = tmp_path / "reputation.db"
    reputation_build.build_empty_snapshot(destinatie)

    monkeypatch.setenv(reputation_store.SNAPSHOT_PATH_ENV, str(destinatie))
    reputation_store.close()

    yield destinatie

    reputation_store.reset_for_tests()


@pytest.fixture
def working(tmp_path):
    """
    Baza de lucru, nesigilată — singurul loc unde scrierea e permisă.

    Vine cu cele două surse deja consemnate. Fără ele, orice inserare ar cădea
    pe cheia străină, iar testele de mai jos ar trece din alt motiv decât cel pe
    care îl numesc — cea mai inutilă formă de test verde.
    """
    connection = reputation_build.create_working_database(tmp_path / "lucru.db")

    reputation_build.record_source(connection, RDS, "software", "2026.03.1", 0)
    reputation_build.record_source(connection, BAZAAR, "threat", "inventar-2026-08", 0)

    yield connection

    connection.close()


# ── 1. Hash-ul e binar, iar schema o impune ─────────────────────────────────

def test_a_hex_hash_is_refused_by_the_schema(working):
    """
    64 de caractere în loc de 32 de octeți: importul se oprește aici.

    Fără CHECK-ul de lungime, greșeala ar trece, ar dubla spațiul și — mai rău —
    același hash scris cu majuscule și cu minuscule ar fi două rânduri distincte,
    deci prevalența s-ar număra de două ori pentru același fișier.
    """
    with pytest.raises(sqlite3.IntegrityError):
        working.execute(
            "INSERT INTO reputation (sha256, known_software, software_source) "
            "VALUES (?, 1, ?)",
            (TEST_HASH.hex(), sid(working, RDS)),
        )


def test_a_truncated_hash_is_refused_by_the_schema(working):
    with pytest.raises(sqlite3.IntegrityError):
        working.execute(
            "INSERT INTO reputation (sha256) VALUES (?)", (TEST_HASH[:16],)
        )


def test_a_lookup_refuses_a_hex_string(snapshot):
    """Granița se apără și în Python, nu doar în SQL."""
    with pytest.raises(reputation_store.ReputationStoreError):
        reputation_store.lookup(TEST_HASH.hex())


# ── 2. Două axe, fiecare cu proveniența ei ──────────────────────────────────

def test_the_two_axes_are_independent(working):
    """
    Un fișier poate fi pe amândouă — și celula aceea e chiar contorul de
    suprapunere pe care un enum de trei valori l-ar face imposibil de reconstruit.
    """
    working.execute(
        """
        INSERT INTO reputation
            (sha256, known_software, software_source, known_malicious, threat_source)
        VALUES (?, 1, ?, 1, ?)
        """,
        (TEST_HASH, sid(working, RDS), sid(working, BAZAAR)),
    )

    (software, amenintare) = working.execute(
        "SELECT known_software, known_malicious FROM reputation WHERE sha256 = ?",
        (TEST_HASH,),
    ).fetchone()

    assert (software, amenintare) == (1, 1)


def test_an_axis_without_a_source_is_refused(working):
    """
    O afirmație fără proveniență n-ar putea fi exclusă dintr-o ablație, deci
    ablația rece/semiînzestrat ar cere reimport ca să separe sursele.
    """
    with pytest.raises(sqlite3.IntegrityError):
        working.execute(
            "INSERT INTO reputation (sha256, known_software) VALUES (?, 1)",
            (TEST_HASH,),
        )


def test_a_source_without_the_axis_is_refused(working):
    """Și invers: o sursă pe o axă falsă ar umfla lista din `METRICS.md` §8."""
    with pytest.raises(sqlite3.IntegrityError):
        working.execute(
            "INSERT INTO reputation (sha256, known_malicious, threat_source) "
            "VALUES (?, 0, ?)",
            (TEST_HASH, sid(working, BAZAAR)),
        )


def test_a_source_lands_on_a_declared_axis_only(working):
    with pytest.raises(reputation_build.SnapshotBuildError):
        reputation_build.record_source(working, "NSRL", "reputatie", "2026.03", 10)


# ── 3. Fișierul sigilat refuză scrierea ─────────────────────────────────────

def test_a_write_fails_while_the_server_reads(snapshot):
    """
    Criteriul de ieșire din P2.2.3, jumătatea întâi.

    `mode=ro` nu e o convenție între noi: e o eroare de la SQLite. Un depozit
    scriibil în timpul unei măsurători ar putea căpăta rânduri la mijlocul ei,
    iar amprenta declarată lângă cifră ar descrie altceva decât ce s-a citit.
    """
    connection = reputation_store.open_readonly(str(snapshot))

    with pytest.raises(sqlite3.OperationalError):
        connection.execute(
            "INSERT INTO reputation (sha256, known_software, software_source) "
            "VALUES (?, 1, 1)",
            (TEST_HASH,),
        )

    connection.close()


def test_the_sealed_snapshot_is_not_in_wal_mode(snapshot):
    """
    Detaliul care ar fi transformat „imutabil" într-o intenție contrazisă.

    O bază în WAL cere drept de scriere ca să poată fi CITITĂ: cititorul trebuie
    să creeze `-wal` și `-shm`. `VACUUM INTO` scrie în modul jurnal implicit, iar
    testul ăsta e singurul loc unde diferența se vede înainte de producție.
    """
    connection = sqlite3.connect(str(snapshot))
    (mod,) = connection.execute("PRAGMA journal_mode").fetchone()
    connection.close()

    assert mod.lower() != "wal"


def test_a_snapshot_is_never_sealed_over_an_existing_one(tmp_path):
    """
    Aceeași cale cu alt conținut e exact minciuna pe care amprenta o previne.
    """
    destinatie = tmp_path / "reputation.db"
    reputation_build.build_empty_snapshot(destinatie)

    with pytest.raises(reputation_build.SnapshotBuildError):
        reputation_build.build_empty_snapshot(destinatie)


# ── 4. Amprenta ─────────────────────────────────────────────────────────────

def test_the_fingerprint_is_stable_across_recomputation(snapshot):
    """Criteriul de ieșire din P2.2.3, jumătatea a doua."""
    assert reputation_store.fingerprint(str(snapshot)) == \
        reputation_store.fingerprint(str(snapshot))


def test_the_fingerprint_follows_the_content(tmp_path):
    """
    O amprentă care nu se mișcă odată cu fișierul n-ar apăra nimic.

    Se construiesc două instantanee goale în fișiere diferite, iar al doilea
    primește o sursă consemnată. Dacă amprentele ar coincide, ar însemna că
    identitatea instantaneului nu depinde de ce e în el.
    """
    intai = tmp_path / "intai.db"
    apoi = tmp_path / "apoi.db"

    amprenta_goala = reputation_build.build_empty_snapshot(intai)

    lucru = reputation_build.create_working_database(tmp_path / "lucru.db")
    reputation_build.record_source(lucru, "NSRL RDS", "software", "2026.03.1", 0)
    amprenta_cu_sursa = reputation_build.seal(lucru, apoi)
    lucru.close()

    assert amprenta_goala != amprenta_cu_sursa


# ── 5. Ce nu se poate exprima ───────────────────────────────────────────────

def test_knowledge_has_no_clean_verdict():
    """
    `CORPUS.md` §5.4: potrivirea în RDS nu poate produce verdictul „curat".

    Testul nu verifică o valoare, verifică un VOCABULAR. Un câmp numit `clean`
    ar fi citit ca verdict de prima persoană grăbită, iar regula din contract ar
    deveni o convenție — adică ceva ce se încalcă fără să mintă nimeni.
    """
    interzise = {"clean", "benign", "safe", "curat", "trusted", "verdict", "score"}

    expuse = {
        nume for nume in dir(reputation_store.Knowledge)
        if not nume.startswith("_")
    }

    assert not (expuse & interzise), f"vocabular interzis expus: {expuse & interzise}"


def test_an_absent_hash_still_answers_on_both_axes(snapshot):
    """
    Un hash necunoscut primește un răspuns, nu `None`.

    `None` ar invita `if not reputation:`, adică exact boolean-ul pe care tipul
    de retur există să-l împiedice. „Nou și necunoscut ca amenințare" e un
    răspuns cu conținut — e chiar cel care declanșează escaladarea.
    """
    raspuns = reputation_store.lookup(OTHER_HASH)

    assert isinstance(raspuns, reputation_store.Knowledge)
    assert raspuns.known_software is False
    assert raspuns.known_malicious is False
    assert raspuns.novel is True


# ── 6. Identitatea, pentru METRICS.md §8 ────────────────────────────────────

def test_a_snapshot_declares_its_schema_version(snapshot):
    identitate = reputation_store.snapshot_identity()

    assert identitate["schema_version"] == reputation_store.SCHEMA_VERSION
    assert identitate["built_at"] is not None
    assert identitate["fingerprint"] == reputation_store.fingerprint(str(snapshot))
    assert identitate["sources"] == []


def test_a_file_without_a_schema_version_is_refused(tmp_path):
    """
    Un fișier SQLite oarecare nu e un instantaneu.

    Fără verificarea asta, greșeala ar apărea ca „zero potriviri" la mijlocul
    unei măsurători — adică cea mai flatantă cifră posibilă, obținută dintr-o
    cale greșită.
    """
    strain = tmp_path / "altceva.db"
    sqlite3.connect(str(strain)).close()

    with pytest.raises(reputation_store.ReputationStoreError):
        reputation_store.open_readonly(str(strain))


def test_a_missing_snapshot_says_what_to_do(tmp_path):
    with pytest.raises(reputation_store.ReputationStoreError) as eroare:
        reputation_store.open_readonly(str(tmp_path / "nu-exista.db"))

    assert "reputation_build" in str(eroare.value)
