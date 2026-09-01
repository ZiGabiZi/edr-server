"""
Depozitul de reputație: ce se știe despre un fișier înainte de orice analiză.
=============================================================================

Partea de CITIRE. Construirea e în `app/services/reputation_build.py`, rulează
în afara rețelei închise și produce fișierul pe care modulul acesta îl deschide.

De ce e o componentă și nu o rută:
    Afirmația principală a lucrării (§L2.4) spune că divulgarea per endpoint
    scade pe măsură ce parcul crește. Mecanismul care o face literalmente
    adevărată e memoria partajată: un fișier escaladează o dată, pe o mașină,
    iar restul parcului îl primește la T0. Fără depozit, fiecare endpoint
    plătește escaladarea separat și costul per endpoint devine constant în
    dimensiunea parcului — adică afirmația nu slăbește, ci devine falsă.

Două axe, nu trei stări (decizia R1 din intrarea de jurnal din 1 septembrie):
    O bază de reputație pare să ceară un enum `{malițios, curat, necunoscut}`.
    E o colapsare a unui 2×2 care pierde tocmai celula interesantă — fișierul
    prezent și în RDS, și într-o sursă de amenințări:

                              | în RDS               | absent din RDS
        ----------------------|----------------------|-------------------
        în sursă de amenințări| suprapunere, se numără| cunoscut-malițios
        absent                | cunoscut ca software  | necunoscut

    Cu un enum, celula din stânga-sus trebuie să se prăbușească în alta la
    import, iar contorul de suprapunere devine imposibil de reconstruit după
    aceea. Cu două coloane independente nu se pierde nimic, iar contorul e o
    interogare, nu o instrumentare separată.

    Motivul mai adânc e `CORPUS.md` §5.4: RDS e o listă de software CUNOSCUT,
    nu de software BUN, iar NIST avertizează el însuși că lista conține hash-uri
    ale unor aplicații care pot fi considerate malițioase. Potrivirea în RDS nu
    poate produce verdictul „curat". Un enum de trei valori ar încălca regula
    asta la primul import, fără ca cineva să mintă intenționat — pur și simplu
    n-ar avea unde să pună adevărul. Structura de aici face afirmația falsă
    inexprimabilă, în loc s-o interzică printr-un comentariu.

De ce `lookup()` nu întoarce niciodată un boolean și nu are valoare implicită:
    Un `bool` ar readuce enumul pe ușa din dos: apelantul l-ar folosi ca „e
    curat", iar `WHERE tip != 'malicious'` scris peste șase luni ar arăta
    rezonabil. Două tabele separate n-ar apăra nimic — cineva scrie `LEFT JOIN`
    și obține același lucru. Ce apără e TIPUL DE RETUR: `Knowledge` poartă
    ambele axe, iar un hash absent primește tot un `Knowledge`, nu `None`.
    Apelantul e obligat să se uite la amândouă.

    `Knowledge` nu are și nu va avea un câmp `clean`, `benign` sau `safe`.
    Absența lui e testată (`test_reputation_store.py`), fiindcă e singurul mod
    în care o regulă din contract devine imposibil de încălcat prin neatenție.

De ce depozitul NU decide:
    Furnizează dovadă; banda de incertitudine (§L2.7) decide. Momentul în care
    modulul acesta capătă un prag propriu — „peste 0,9 raportez malițios" — e
    momentul în care §L2.7 rămâne fără obiect și există două mecanisme de
    decizie care se contrazic pe tăcute. De aceea aici nu există niciun scor și
    nicio pondere: agregarea e a benzii, cu ponderi înghețate, la P2.3.

De ce hash-ul e BLOB de 32 de octeți și nu text hexazecimal:
    Jumătate din spațiu pe zeci de milioane de rânduri, comparații pe octeți în
    loc de comparații de șiruri, și niciun mod de a scrie același hash în două
    feluri (majuscule/minuscule) care s-ar deduplica prost. Alegerea e
    ireversibilă după import: un depozit populat cu text nu se convertește, se
    reimportă — iar reimportul înseamnă instantaneu nou, deci toate măsurătorile
    de dinainte descriu alt sistem.

De ce fișierul se deschide `mode=ro&immutable=1`:
    Instantaneul e un artefact sigilat, nu o bază de lucru. `mode=ro` face ca
    orice scriere să EȘUEZE, nu să fie doar nepoliticoasă; `immutable=1` spune
    lui SQLite că fișierul nu se schimbă sub el, deci poate sări peste blocaje.
    A doua opțiune e o promisiune pe care o facem noi: dacă fișierul chiar se
    schimbă în timpul unei rulări, rezultatele sunt nedefinite. De aceea
    construirea produce un fișier NOU și schimbul se face prin înlocuire, nu
    prin editare pe loc.

    Detaliul care mușcă, dacă e ratat: o bază SQLite lăsată în modul jurnal WAL
    NU se poate deschide read-only fără drept de scriere, fiindcă cititorul are
    nevoie să creeze `-wal` și `-shm`. De aceea fișierul livrat se produce cu
    `VACUUM INTO`, care scrie o copie compactă în modul jurnal implicit. Fără
    pasul acela, „imutabil" ar fi o intenție pe care prima deschidere o
    contrazice. Testul `test_sealed_snapshot_is_not_in_wal_mode` fixează asta.

De ce amprenta se recalculează și nu se stochează înăuntru:
    O amprentă scrisă în fișier ar face parte din ce se amprentează — un ou
    care-și conține propriul găinaț. Amprenta e SHA-256 peste octeții
    fișierului, calculată la cerere, verificabilă din afară cu `sha256sum`.
    `METRICS.md` §8 cere ca ea să apară lângă orice cifră: peste trei luni,
    întrebarea „ce știa sistemul atunci" are un răspuns de 64 de caractere, nu
    o poveste.
"""

import hashlib
import logging
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, NamedTuple, Optional


logger = logging.getLogger(__name__)


_BASE_DIR = Path(__file__).resolve().parent.parent.parent

DEFAULT_SNAPSHOT_PATH = _BASE_DIR / "storage" / "reputation.db"

# Calea instantaneului, din mediu. Spre deosebire de baza de evenimente, aici
# schimbarea căii NU e o comoditate de test: e felul în care se comută între
# instantanee, iar ablația rece/semiînzestrat din intrarea de decizie se face
# exact așa — două fișiere, două rulări, aceeași cifră comparabilă.
SNAPSHOT_PATH_ENV = "EDR_REPUTATION_DB"

# Versiunea schemei. Crește DOAR când forma tabelelor se schimbă, nu când se
# schimbă conținutul. Serverul refuză un instantaneu cu altă versiune, fiindcă
# alternativa — să citească ce nimerește — ar produce cifre care par corecte.
SCHEMA_VERSION = 1

# Numele cheilor din `snapshot_meta`. Scrise aici, nu în modulul de construire,
# ca partea care citește să fie autoritatea asupra formei.
META_SCHEMA_VERSION = "schema_version"
META_BUILT_AT = "built_at"
META_BUILDER = "builder"

# Cele două axe, ca valori de coloană în `sources`. Un `CHECK` le fixează în
# schemă, deci o sursă nu poate ateriza pe o axă inventată.
AXIS_SOFTWARE = "software"
AXIS_THREAT = "threat"


SCHEMA = (
    # Sursele, ÎNAINTEA tabelului principal: `reputation` trimite spre ele prin
    # cheie străină, iar SQLite cere ca ținta să existe la creare.
    #
    # De ce sursa e un întreg și nu numele ei repetat pe fiecare rând: la 150 de
    # milioane de rânduri, un nume de 18 caractere costă 2,5 GB de repetiție a
    # aceluiași cuvânt. Măsurat, nu presupus — 82 de octeți pe rând cu întreg
    # față de 100 cu text. Invarianta din intrarea de decizie, fiecare rând
    # poartă sursa, rămâne intactă: se poartă prin referință, nu prin copie.
    #
    # `METRICS.md` 8 cere lista surselor lângă orice cifră, iar aici e singurul
    # loc unde poate fi citită fără să fie reconstruită din memoria cuiva.
    """
    CREATE TABLE IF NOT EXISTS sources (
        source_id   INTEGER NOT NULL PRIMARY KEY,
        name        TEXT    NOT NULL UNIQUE,
        axis        TEXT    NOT NULL,
        version     TEXT    NOT NULL,
        imported_at TEXT    NOT NULL,
        row_count   INTEGER NOT NULL,

        CHECK (axis IN ('software', 'threat')),
        CHECK (row_count >= 0)
    )
    """,
    # Tabelul principal. WITHOUT ROWID: cheia primară E hash-ul, deci un rowid
    # separat ar fi un al doilea index peste aceleași date, plătit de zeci de
    # milioane de ori.
    #
    # NU există index pe cele două axe, deși raportul de acoperire de la P2.2.6
    # le agregă. Măsurat, indexul acela costă 39,5 octeți pe rând — exact cât un
    # rând întreg minimal, adică 5,5 GB la 150 de milioane de rânduri — ca să
    # economisească minute într-o raportare rulată o dată. O scanare completă e
    # plata corectă acolo.
    """
    CREATE TABLE IF NOT EXISTS reputation (
        sha256              BLOB    NOT NULL PRIMARY KEY,

        -- Axa de NOUTATE. „Îl știu ca software." RDS scrie doar aici.
        known_software      INTEGER NOT NULL DEFAULT 0,
        software_source     INTEGER REFERENCES sources (source_id),

        -- Axa de AMENINȚARE. Independentă de prima; un fișier poate fi pe
        -- amândouă, iar celula aceea e chiar contorul de suprapunere.
        known_malicious     INTEGER NOT NULL DEFAULT 0,
        threat_source       INTEGER REFERENCES sources (source_id),

        -- Supra-import (decizia R2). Coloanele astea nu se folosesc azi.
        -- Costul unei coloane nefolosite e spațiu; costul unei coloane lipsă e
        -- reimportul, adică instantaneu nou, adică toate măsurătorile de
        -- dinainte descriu alt sistem. Asimetria decide singură.
        family              TEXT,
        first_seen          TEXT,
        representative_name TEXT,
        name_count          INTEGER,

        -- 32 de octeți, nu 64 de caractere. Dacă cineva încearcă să scrie
        -- hexazecimal, importul se oprește aici, nu la analiza rezultatelor.
        CHECK (length(sha256) = 32),

        CHECK (known_software  IN (0, 1)),
        CHECK (known_malicious IN (0, 1)),

        -- O axă adevărată fără sursă ar fi o afirmație fără proveniență, deci
        -- imposibil de exclus dintr-o ablație. Sursa pe fiecare rând e ce face
        -- selecția surselor un parametru de RULARE, nu o proprietate a
        -- depozitului — altfel ablația rece/semiînzestrat ar cere reimport.
        CHECK ((known_software  = 1) = (software_source IS NOT NULL)),
        CHECK ((known_malicious = 1) = (threat_source   IS NOT NULL))
    ) WITHOUT ROWID
    """,
    # Identitatea instantaneului. Versiunea schemei stă aici, nu într-un nume de
    # fișier: numele se schimbă la copiere, conținutul nu.
    """
    CREATE TABLE IF NOT EXISTS snapshot_meta (
        key   TEXT NOT NULL PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
)


class ReputationStoreError(RuntimeError):
    """Instantaneul nu a putut fi deschis, sau nu e ce pretinde că e."""


class Knowledge(NamedTuple):
    """
    Ce știe depozitul despre un hash, pe ambele axe.

    Nu există `clean`, `benign` sau `safe`, și nu vor exista. `CORPUS.md` §5.4
    interzice verdictul „curat" derivat din apartenența la RDS; un câmp cu numele
    ăla ar fi folosit exact așa la prima grabă. Cine vrea o decizie o cere benzii
    (§L2.7), care primește tuplul întreg.

    `software_source` și `threat_source` sunt aici fiindcă un răspuns fără
    proveniență nu se poate exclude dintr-o ablație — iar ablația
    rece/semiînzestrat e singura măsurătoare care separă contribuția protocolului
    de cea a artei anterioare.
    """

    known_software: bool
    known_malicious: bool
    software_source: Optional[str] = None
    threat_source: Optional[str] = None
    family: Optional[str] = None
    first_seen: Optional[str] = None

    @property
    def novel(self) -> bool:
        """Absent din sursele de software cunoscut. Celălalt capăt al axei."""
        return not self.known_software

    @property
    def both_axes(self) -> bool:
        """Suprapunerea: cunoscut ca software ȘI ca amenințare."""
        return self.known_software and self.known_malicious


# Răspunsul pentru un hash pe care depozitul nu-l are. Nu e `None`, deliberat:
# `None` ar invita `if not reputation:`, adică exact boolean-ul evitat mai sus.
# Un hash absent E un răspuns — „nou și necunoscut ca amenințare" — și e chiar
# răspunsul care declanșează escaladarea.
UNKNOWN = Knowledge(known_software=False, known_malicious=False)


_lock = threading.Lock()
_connection: Optional[sqlite3.Connection] = None
_snapshot_path: Optional[str] = None
_fingerprint: Optional[str] = None


def configured_path() -> str:
    """Calea instantaneului, din mediu dacă e dată, altfel cea implicită."""
    return os.environ.get(SNAPSHOT_PATH_ENV) or str(DEFAULT_SNAPSHOT_PATH)


def fingerprint(path: str) -> str:
    """
    SHA-256 peste octeții fișierului, în hexazecimal.

    Se citește în bucăți: instantaneul poate ajunge la 20 GB (pragul R1 din
    intrarea de decizie), iar un `read()` întreg ar cere aceeași memorie.

    Amprenta NU e stocată în fișier. Ar face parte din ce amprentează, deci
    n-ar putea fi calculată fără să se invalideze singură. Calculată din afară,
    e verificabilă cu `sha256sum` de către oricine, fără acest cod.
    """
    digest = hashlib.sha256()

    try:
        with open(path, "rb") as handle:
            for bucata in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(bucata)
    except OSError as error:
        raise ReputationStoreError(
            f"Could not fingerprint the reputation snapshot at {path}: {error}"
        ) from error

    return digest.hexdigest()


def content_fingerprint(connection: sqlite3.Connection) -> str:
    """
    Amprentă peste CONȚINUTUL logic, nu peste octeții fișierului.

    De ce sunt necesare amândouă, și de ce am aflat-o dintr-un test roșu:
        `fingerprint()` acoperă fișierul livrat și răspunde la întrebarea „ce a
        citit serverul când a produs cifra asta". E identitatea, și e verificabilă
        din afară cu sha256sum.

        Dar fișierul conține și momentul construirii, și momentul importului.
        Două importuri identice, rulate la ore diferite, produc fișiere diferite
        la octet — deci `fingerprint()` NU poate demonstra că un import e
        idempotent, și nici că altcineva a reconstruit același lucru.

        Funcția asta răspunde la cealaltă întrebare: „ce e ÎNĂUNTRU". Trece peste
        rânduri în ordinea hash-ului și peste surse în ordinea numelui, sărind
        peste tot ce e ceas: `built_at`, `imported_at`, cursorul de reluare.
        Două depozite cu același conținut dau aceeași valoare oricând ar fi fost
        construite.

        Criteriul de ieșire din P2.2.4 — reimportul aceleiași surse nu schimbă
        nimic — se verifică aici. Criteriul din `METRICS.md` 8 — ce se declară
        lângă o cifră — se verifică cu `fingerprint()`. Erau două întrebări
        diferite sub același nume.

    Costă o scanare completă a tabelului, deci se cere explicit, nu la fiecare
    deschidere.
    """
    digest = hashlib.sha256()
    digest.update(b"reputation-content-v1\n")
    digest.update(("schema=%d\n" % SCHEMA_VERSION).encode("utf-8"))

    for nume, axa, versiune, randuri in connection.execute(
        "SELECT name, axis, version, row_count FROM sources ORDER BY name"
    ):
        digest.update(
            ("sursa\t%s\t%s\t%s\t%d\n" % (nume, axa, versiune, randuri)).encode("utf-8")
        )

    for rand in connection.execute(
        """
        SELECT r.sha256, r.known_software, sw.name, r.known_malicious, th.name,
               r.family, r.first_seen, r.representative_name, r.name_count
          FROM reputation r
          LEFT JOIN sources sw ON sw.source_id = r.software_source
          LEFT JOIN sources th ON th.source_id = r.threat_source
         ORDER BY r.sha256
        """
    ):
        digest.update(rand[0])
        digest.update(
            ("\t%s\n" % "\t".join("" if c is None else str(c) for c in rand[1:]))
            .encode("utf-8")
        )

    return digest.hexdigest()


def _read_only_uri(path: str) -> str:
    """
    URI-ul de deschidere sigilată.

    `Path.as_uri()` cere cale absolută și face codificarea procentuală corect pe
    ambele sisteme — instantaneul se construiește pe gazdă (Windows) și se
    citește pe server (Linux), deci calea trece prin două convenții diferite.
    """
    return Path(path).resolve().as_uri() + "?mode=ro&immutable=1"


def open_readonly(path: str) -> sqlite3.Connection:
    """
    Deschide un instantaneu sigilat. Orice scriere pe conexiunea asta eșuează.

    Verifică versiunea schemei la deschidere, nu la prima interogare: un
    instantaneu cu altă formă ar produce erori la mijlocul unei măsurători, cu
    jumătate din cifre deja scrise.
    """
    if not Path(path).exists():
        raise ReputationStoreError(
            f"There is no reputation snapshot at {path}. "
            f"Build one first (app/services/reputation_build.py)."
        )

    try:
        connection = sqlite3.connect(_read_only_uri(path), uri=True,
                                     check_same_thread=False)
    except sqlite3.Error as error:
        raise ReputationStoreError(
            f"Could not open the reputation snapshot at {path}: {error}"
        ) from error

    versiune = _meta_value(connection, META_SCHEMA_VERSION)

    if versiune is None:
        raise ReputationStoreError(
            f"The file at {path} carries no schema version; it was not produced "
            f"by reputation_build.py."
        )

    if int(versiune) != SCHEMA_VERSION:
        raise ReputationStoreError(
            f"The reputation snapshot at {path} has schema version {versiune}, "
            f"but this server reads version {SCHEMA_VERSION}."
        )

    return connection


def _meta_value(connection: sqlite3.Connection, key: str) -> Optional[str]:
    try:
        rand = connection.execute(
            "SELECT value FROM snapshot_meta WHERE key = ?", (key,)
        ).fetchone()
    except sqlite3.Error:
        # Un fișier care nu are tabelul nu e un instantaneu. Apelantul
        # transformă asta într-un mesaj care spune ce lipsește.
        return None

    return rand[0] if rand else None


def _connection_locked() -> sqlite3.Connection:
    """Conexiunea partajată, deschisă la prima nevoie. Cere _lock deținut."""
    global _connection, _snapshot_path, _fingerprint

    if _connection is None:
        _snapshot_path = configured_path()
        _connection = open_readonly(_snapshot_path)

        # Amprenta se calculează O DATĂ, la deschidere, și se ține până la
        # `close()`. Nu e o optimizare oportunistă, ci consecința promisiunii de
        # deschidere: `immutable=1` spune că fișierul nu se schimbă sub noi, deci
        # o a doua citire a acelorași octeți nu poate da alt răspuns.
        #
        # Fără memorare, `snapshot_identity()` ar reciti tot fișierul la fiecare
        # apel — 3,06 GB azi, până la 20 GB la pragul R1 — iar de la P2.3
        # apelantul e calea de ingestie: primul eveniment cu hash al unei rulări
        # ar fi hash-uit instantaneul de două ori, o dată aici pentru linia de
        # log și o dată acolo, ținând `_lock` de fiecare dată.
        _fingerprint = fingerprint(_snapshot_path)

        logger.info(
            "Reputation snapshot opened at %s (fingerprint %s).",
            _snapshot_path,
            _fingerprint[:16],
        )

    return _connection


def lookup(sha256: bytes) -> Knowledge:
    """
    Ce știe depozitul despre un hash, pe ambele axe.

    Întoarce ÎNTOTDEAUNA un `Knowledge`, niciodată `None` și niciodată un
    boolean. Un hash absent primește `UNKNOWN`, care e un răspuns cu conținut —
    „nou, și necunoscut ca amenințare" — nu o lipsă de răspuns.
    """
    if not isinstance(sha256, (bytes, bytearray)) or len(sha256) != 32:
        raise ReputationStoreError(
            f"A reputation lookup needs 32 raw bytes, got {len(sha256)!r}. "
            f"Hex strings are not accepted; decode them at the boundary."
        )

    with _lock:
        connection = _connection_locked()

        # Cele două LEFT JOIN întorc sursa ca NUME, deși e stocată ca întreg.
        # Apelantul n-are ce face cu un identificator intern, iar tabelul
        # `sources` are o mână de rânduri — costul e o căutare în cache, nu o
        # citire de disc.
        rand = connection.execute(
            """
            SELECT r.known_software, sw.name,
                   r.known_malicious, th.name,
                   r.family, r.first_seen
              FROM reputation r
              LEFT JOIN sources sw ON sw.source_id = r.software_source
              LEFT JOIN sources th ON th.source_id = r.threat_source
             WHERE r.sha256 = ?
            """,
            (bytes(sha256),),
        ).fetchone()

    if rand is None:
        return UNKNOWN

    return Knowledge(
        known_software=bool(rand[0]),
        software_source=rand[1],
        known_malicious=bool(rand[2]),
        threat_source=rand[3],
        family=rand[4],
        first_seen=rand[5],
    )


def snapshot_identity() -> Dict[str, Any]:
    """
    Ce se declară lângă orice cifră care a folosit depozitul (`METRICS.md` §8).

    Amprenta și lista surselor, împreună. Amprenta singură ar spune „acest
    fișier"; sursele spun ce s-a consultat din el, iar ablația rece/semiînzestrat
    e chiar diferența dintre două liste.
    """
    with _lock:
        connection = _connection_locked()
        cale = _snapshot_path
        amprenta = _fingerprint

        surse = [
            {
                "name": nume,
                "axis": axa,
                "version": versiune,
                "imported_at": importat_la,
                "row_count": randuri,
            }
            for nume, axa, versiune, importat_la, randuri in connection.execute(
                """
                SELECT name, axis, version, imported_at, row_count
                  FROM sources
                 ORDER BY axis, name
                """
            )
        ]

        construit_la = _meta_value(connection, META_BUILT_AT)

    return {
        "path": cale,
        "fingerprint": amprenta,
        "schema_version": SCHEMA_VERSION,
        "built_at": construit_la,
        "sources": surse,
    }


def close() -> None:
    """Închide conexiunea partajată, dacă e deschisă."""
    global _connection, _snapshot_path, _fingerprint

    with _lock:
        if _connection is not None:
            _connection.close()

        _connection = None
        _snapshot_path = None
        _fingerprint = None


def reset_for_tests() -> None:
    """Închide conexiunea, ca testul următor să pornească de la zero."""
    close()
