"""
Depozitul persistent: evenimentele și registrul rulărilor, în aceeași bază.
===========================================================================

Ce se schimbă față de lista din memorie:
    `events_store` era o listă Python, iar deduplicarea un dicționar lângă ea.
    Amândouă mureau la repornire, ceea ce ținea ascunse trei probleme care
    devin, odată cu discul, cerințe de corectitudine — nu opțiuni:

    1. DEDUPLICAREA TREBUIE SĂ VINĂ DIN BAZĂ.
       `_events_by_client_id` se golea la repornire. Un agent care retransmite
       după un restart de server ar fi produs un al doilea rând pentru același
       eveniment, iar rândul acela ar fi dublat `file_size` în NUMITORUL
       metricii de divulgare. Retransmisiile se numără pe fir (METRICS.md §1.3,
       registrul le prinde) și acolo e locul lor — dar în depozit un eveniment
       are voie să existe o singură dată. Cele două cifre măsoară lucruri
       diferite, iar confuzia dintre ele umflă exact numitorul.

       De aici constrângerea UNIQUE pe `client_event_id`: nu o optimizare, ci
       invarianta pe care se sprijină o cifră publicată. Un eveniment fără
       `client_event_id` rămâne nededuplicat, prin construcție — NULL nu intră
       în coliziune cu NULL în SQLite, exact ca la garda `if event.client_event_id`
       de dinainte.

    2. `event_id` TREBUIE SĂ VINĂ DIN BAZĂ.
       `itertools.count(1)` repornea de la 1 la fiecare pornire a serverului,
       deci ar fi produs identificatori care se ciocnesc cu rândurile deja
       existente. AUTOINCREMENT, nu doar INTEGER PRIMARY KEY: al doilea reciclează
       rowid-uri după ștergerea rândului maxim, iar un identificator refolosit
       într-un depozit de măsurători e mai rău decât unul lipsă.

    3. REGISTRUL ETICHETELOR DE RULARE TRĂIEȘTE AICI, lângă evenimente.
       În memorie s-ar fi golit exact la repornirea care face refolosirea unei
       etichete probabilă și periculoasă. Vezi app/services/measurement_run.py
       pentru ce apără refuzul de refolosire.

Un singur proces — declarat, nu presupus (decizia D3):
    Conexiunea e una singură, deschisă leneș, partajată între thread-uri
    (`check_same_thread=False`) și serializată de un `threading.Lock` propriu.
    Lock-ul acela serializează THREAD-URI, nu procese. Serverul FastAPI rulează
    azi cu un singur worker, iar restul contabilității depinde de asta mai tare
    decât depozitul:

        - `wire_accounting` ține contoarele în memoria procesului. Cu doi
          workeri, aceeași încarnare ar fi numărată în două locuri, iar
          reconcilierea de la §7.4 ar raporta două jumătăți ca și cum ar fi
          două întreguri.
        - rularea curentă din `measurement_run` e tot per proces, deci doi
          workeri porniți în aceeași secundă ar eticheta evenimente cu două
          nume diferite.

    Ce garantează totuși SQLite peste procese, ca să nu se creadă mai mult sau
    mai puțin decât e: WAL permite mai mulți cititori simultan cu un scriitor,
    iar scrierile concurente se serializează prin blocajele lui proprii — deci
    baza nu se corupe dacă cineva pornește un al doilea proces. Ce NU rezultă de
    aici e că sistemul ar funcționa: partea stricată e contabilitatea din
    memorie, nu fișierul.

    WAL e ales pentru cititor-care-nu-blochează-scriitorul, nu pentru
    concurență între procese. `GET /api/metrics/disclosure` citește tot tabelul;
    fără WAL, citirea aceea ar bloca ingestia de evenimente exact în timpul unei
    măsurători.

De ce synchronous=FULL aici, deși coada agentului folosește NORMAL:
    Oglinda cu edr-agent/services/event_spool.py e deliberată, dar nu oarbă.
    Acolo, un eveniment pierdut la o cădere de curent se retrimite: coada e
    at-least-once și evenimentul e încă în ea până la confirmare. Aici nu mai
    există a doua copie — agentul șterge după confirmare, deci serverul e
    singurul loc unde mai stă. Coada tăiată de o cădere de curent ar micșora
    tăcut numărătorul unei măsurători, adică exact felul de eroare împotriva
    căruia e construit tot traseul. Un fsync per eveniment e ieftin la debitul
    de aici.

Ce NU persistă, și de ce:
    - `agents_store` rămâne volatil. Motivul e scris în auth_service.py: cheile
      au fost scoase din el tocmai pentru că se golește la repornire, iar
      agenții se re-înregistrează singuri prin directiva reregister. Persistat
      acum, ar contrazice o decizie deja luată și ar readuce cheile în raza
      rutei publice GET /api/agents.
    - `wire_accounting` rămâne per încarnare, în memorie (decizia D3).

Forma rândului — coloane promovate peste un payload JSON:
    Adevărul e `payload`: dicționarul evenimentului, serializat întreg.
    Coloanele `run_id`, `agent_id`, `client_event_id`, `received_at` sunt copii
    derivate din el la inserare, ca filtrarea să se facă în SQL, nu în Python.
    Ordinea contează: un depozit care poate întoarce doar tot tabelul ar obliga
    metrica să filtreze în memorie, adică ar anula motivul pentru care datele au
    ajuns pe disc.

    Schema NU e normalizată complet, și e o alegere: forma evenimentului urmează
    contractul de fir, care crește (blocul `disclosure` a apărut în v5). Un tabel
    cu o coloană per câmp ar cere o migrare la fiecare creștere a contractului,
    iar migrarea aceea ar atinge date de măsurătoare deja publicate.
"""

import json
import logging
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional


logger = logging.getLogger(__name__)


_BASE_DIR = Path(__file__).resolve().parent.parent.parent

DEFAULT_DB_PATH = _BASE_DIR / "edr_server.db"

# Calea se poate muta din mediu. Util pentru o măsurătoare care vrea o bază
# curată, fără să șteargă istoricul: o rulare nouă separă logic datele, un
# fișier separat le separă fizic. Prima e regula, a doua e pentru cazul în care
# vrei să poți arhiva un experiment ca fișier.
DB_PATH_ENV = "EDR_SERVER_DB"

# Baza pe care o folosesc testele. Nu atinge discul deloc, deci suita nu poate
# lăsa în urmă un fișier în rădăcina repo-ului și nu poate duce evenimente
# dintr-o rulare a suitei în următoarea.
IN_MEMORY = ":memory:"


_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS events (
        event_id        INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id          TEXT NOT NULL,
        agent_id        TEXT NOT NULL,
        client_event_id TEXT UNIQUE,
        received_at     TEXT NOT NULL,
        payload         TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_events_run_id ON events (run_id)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_events_agent_id ON events (agent_id)
    """,
    """
    CREATE TABLE IF NOT EXISTS measurement_runs (
        run_id    TEXT PRIMARY KEY,
        source    TEXT NOT NULL,
        opened_at TEXT NOT NULL
    )
    """,
    # Instantaneul de reputație pe care a rulat fiecare rulare (`METRICS.md` §8).
    #
    # De ce un tabel NOU și nu o coloană în `measurement_runs`: nu există niciun
    # mecanism de migrare aici, iar `CREATE TABLE IF NOT EXISTS` e aditiv pe o
    # bază deja scrisă — `ALTER TABLE` n-ar fi. O bază de evenimente existentă
    # capătă tabelul gol la prima deschidere și nimic nu se pierde.
    #
    # De ce pe RULARE și nu pe eveniment: identitatea instantaneului nu e o
    # proprietate a evenimentului. Conexiunea la depozit se deschide o dată per
    # proces, `immutable=1` e promisiunea că fișierul nu se schimbă dedesubt, iar
    # o etichetă de rulare nu poate fi redeschisă (cheia primară de mai sus o
    # refuză) — deci o rulare vede exact un instantaneu. Repetată pe fiecare
    # eveniment, lista surselor ar fi aceeași repetiție pe care schema de
    # reputație a refuzat-o stocând sursa ca întreg.
    #
    # `fingerprint` are coloana lui, deși apare și în `identity`: e singura
    # întrebare pusă des — „ce a citit serverul când a produs cifra asta" — și
    # singura pe care o divergență o poate semnala fără să despacheteze JSON.
    """
    CREATE TABLE IF NOT EXISTS run_reputation (
        run_id      TEXT NOT NULL PRIMARY KEY,
        recorded_at TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        identity    TEXT NOT NULL
    )
    """,
)


_INSERT_EVENT = """
    INSERT INTO events (run_id, agent_id, client_event_id, received_at, payload)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT (client_event_id) DO NOTHING
"""


class EventStoreError(RuntimeError):
    """Depozitul nu a putut fi deschis sau interogat."""


_lock = threading.Lock()
_connection: Optional[sqlite3.Connection] = None
_db_path: Optional[str] = None


def configured_path() -> str:
    """Calea bazei, din mediu dacă e dată, altfel cea implicită."""
    return os.environ.get(DB_PATH_ENV) or str(DEFAULT_DB_PATH)


def _connect(path: str) -> sqlite3.Connection:
    connection = sqlite3.connect(path, check_same_thread=False)

    # WAL nu se poate activa pe o bază din memorie, iar încercarea nu e o
    # eroare: acolo nu există jurnal de refăcut și nici cititori de deblocat.
    if path != IN_MEMORY:
        Path(path).parent.mkdir(parents=True, exist_ok=True)

        (mode,) = connection.execute("PRAGMA journal_mode=WAL").fetchone()

        if mode.lower() != "wal":
            # Nu oprim serverul pentru asta: un depozit în mod rollback
            # funcționează, doar că o citire lungă a metricii va bloca
            # ingestia. Dar tăcerea ar face ca lentoarea de mai târziu să pară
            # inexplicabilă.
            logger.warning(
                "The event store could not switch to WAL (journal_mode=%s). "
                "Reads will block writes; check the filesystem hosting %s.",
                mode,
                path,
            )

        connection.execute("PRAGMA synchronous=FULL")

    for statement in _SCHEMA:
        connection.execute(statement)

    connection.commit()

    return connection


def _connection_locked() -> sqlite3.Connection:
    """Conexiunea partajată, deschisă la prima nevoie. Cere _lock deținut."""
    global _connection, _db_path

    if _connection is None:
        _db_path = configured_path()

        try:
            _connection = _connect(_db_path)
        except (sqlite3.Error, OSError) as error:
            raise EventStoreError(
                f"Could not open the event store at {_db_path}: {error}"
            ) from error

        logger.info("Event store opened at %s.", _db_path)

    return _connection


def _row_to_event(event_id: int, payload: str) -> Dict[str, Any]:
    """
    Reface dicționarul evenimentului dintr-un rând.

    `event_id` se pune la sfârșit, ca în forma dinainte de persistență, unde
    era atribuit după construirea dicționarului. Ordinea cheilor nu schimbă
    nicio cifră, dar schimbă diff-ul oricărui răspuns comparat cu unul vechi.
    """
    event: Dict[str, Any] = json.loads(payload)
    event["event_id"] = event_id

    return event


def insert_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Persistă un eveniment și îi întoarce forma stocată, cu event_id din bază.

    Dacă `client_event_id` există deja, NU se scrie nimic și se întoarce
    evenimentul care era deja acolo — aceeași semantică de idempotență ca
    înainte, mutată însă din dicționarul de memorie în constrângerea UNIQUE.
    ON CONFLICT țintește explicit acea constrângere: un INSERT OR IGNORE ar fi
    înghițit la fel de tăcut și o violare de NOT NULL, adică un eveniment
    pierdut fără nicio urmă.

    Deduplicarea e GLOBALĂ, peste toate rulările, nu în interiorul rulării
    curente. Ea descrie firul, nu experimentul: o retransmisie e același
    eveniment chiar dacă sosește după ce s-a deschis o rulare nouă. Nu poate
    goli din greșeală o măsurătoare repetată, pentru că agentul generează un
    uuid4 nou la fiecare detecție.
    """
    payload = json.dumps(event, ensure_ascii=False, default=str)
    parameters = (
        event["run_id"],
        event["agent_id"],
        event.get("client_event_id"),
        event["received_at"],
        payload,
    )

    with _lock:
        connection = _connection_locked()

        try:
            cursor = connection.execute(_INSERT_EVENT, parameters)
            connection.commit()
        except sqlite3.Error as error:
            raise EventStoreError(f"Could not store event: {error}") from error

        if cursor.rowcount == 1:
            stored = dict(event)
            stored["event_id"] = cursor.lastrowid
            return stored

        existing = _event_by_client_id_locked(
            connection, event.get("client_event_id")
        )

    if existing is None:
        # Nu s-a inserat nimic și nici nu se găsește un rând care să explice de
        # ce. Singura cauză plauzibilă ar fi o ștergere concurentă, adică o
        # presupunere ruptă — de raportat, nu de întors ca None către rută.
        raise EventStoreError(
            "The insert was skipped as a duplicate, but no existing event "
            "carries that client_event_id"
        )

    return existing


def _event_by_client_id_locked(
    connection: sqlite3.Connection, client_event_id: Optional[str]
) -> Optional[Dict[str, Any]]:
    if not client_event_id:
        return None

    row = connection.execute(
        "SELECT event_id, payload FROM events WHERE client_event_id = ?",
        (client_event_id,),
    ).fetchone()

    return _row_to_event(row[0], row[1]) if row else None


def event_by_client_id(client_event_id: str) -> Optional[Dict[str, Any]]:
    """Evenimentul deja stocat sub identificatorul dat de agent, dacă există."""
    with _lock:
        connection = _connection_locked()

        try:
            return _event_by_client_id_locked(connection, client_event_id)
        except sqlite3.Error as error:
            raise EventStoreError(f"Could not read event: {error}") from error


def all_events(run_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Evenimentele stocate, în ordinea în care au fost primite.

    `run_id` restrânge la o singură rulare de măsurătoare. Filtrarea se face în
    SQL, nu peste lista întoarsă: pe un depozit care se acumulează peste
    săptămâni, o metrică ce ar citi tot ca să arunce aproape tot ar plăti
    întregul istoric la fiecare interogare.
    """
    query = "SELECT event_id, payload FROM events"
    parameters: tuple = ()

    if run_id is not None:
        query += " WHERE run_id = ?"
        parameters = (run_id,)

    query += " ORDER BY event_id"

    with _lock:
        connection = _connection_locked()

        try:
            rows = connection.execute(query, parameters).fetchall()
        except sqlite3.Error as error:
            raise EventStoreError(f"Could not read events: {error}") from error

    return [_row_to_event(event_id, payload) for event_id, payload in rows]


def count_events(run_id: Optional[str] = None) -> int:
    """Câte evenimente sunt stocate, opțional într-o singură rulare."""
    query = "SELECT COUNT(*) FROM events"
    parameters: tuple = ()

    if run_id is not None:
        query += " WHERE run_id = ?"
        parameters = (run_id,)

    with _lock:
        connection = _connection_locked()

        try:
            (total,) = connection.execute(query, parameters).fetchone()
        except sqlite3.Error as error:
            raise EventStoreError(f"Could not count events: {error}") from error

    return total


# ---------------------------------------------------------------------------
# Registrul rulărilor de măsurătoare
# ---------------------------------------------------------------------------
#
# Stă în ACEEAȘI bază cu evenimentele, nu într-un fișier alături, și nu din
# comoditate: o etichetă și evenimentele ei trebuie să apară sau să dispară
# împreună. Un registru separat s-ar putea pierde singur, iar atunci refolosirea
# unei etichete ar deveni posibilă exact peste datele care o făceau periculoasă.


def register_run(run_id: str, source: str, opened_at: str) -> bool:
    """
    Înscrie o rulare. Întoarce False dacă eticheta a mai fost folosită.

    Refuzul vine din cheia primară, nu dintr-o verificare făcută înainte:
    între o citire și o scriere separate ar încăpea o a doua cerere, iar
    fereastra aceea e fix cazul pe care mecanismul îl apără.
    """
    with _lock:
        connection = _connection_locked()

        try:
            cursor = connection.execute(
                "INSERT INTO measurement_runs (run_id, source, opened_at) "
                "VALUES (?, ?, ?) ON CONFLICT (run_id) DO NOTHING",
                (run_id, source, opened_at),
            )
            connection.commit()
        except sqlite3.Error as error:
            raise EventStoreError(f"Could not register run: {error}") from error

        return cursor.rowcount == 1


def event_counts_by_run() -> List[Dict[str, Any]]:
    """
    Câte evenimente are fiecare rulare, cele mai vechi întâi.

    E declarația de corpus cerută de METRICS.md §8 pentru cazul agregat: o cifră
    peste mai multe rulări nu descrie niciun experiment, iar cine o publică
    trebuie să poată spune din ce e făcută. Rulările fără evenimente nu apar —
    ele n-au contribuit cu nimic la cifră.
    """
    with _lock:
        connection = _connection_locked()

        rows = connection.execute(
            "SELECT run_id, COUNT(*) FROM events GROUP BY run_id "
            "ORDER BY MIN(event_id)"
        ).fetchall()

    return [{"run_id": run_id, "events": events} for run_id, events in rows]


def run_record(run_id: str) -> Optional[Dict[str, str]]:
    """Rularea din registru, cu sursa și ora deschiderii, sau None."""
    with _lock:
        connection = _connection_locked()

        row = connection.execute(
            "SELECT run_id, source, opened_at FROM measurement_runs "
            "WHERE run_id = ?",
            (run_id,),
        ).fetchone()

    if row is None:
        return None

    return {"run_id": row[0], "source": row[1], "opened_at": row[2]}


def run_exists(run_id: str) -> bool:
    with _lock:
        connection = _connection_locked()

        row = connection.execute(
            "SELECT 1 FROM measurement_runs WHERE run_id = ?", (run_id,)
        ).fetchone()

    return row is not None


def known_runs() -> List[Dict[str, str]]:
    """Toate rulările consemnate, cele mai vechi întâi."""
    with _lock:
        connection = _connection_locked()

        rows = connection.execute(
            "SELECT run_id, source, opened_at FROM measurement_runs "
            "ORDER BY opened_at, run_id"
        ).fetchall()

    return [
        {"run_id": run_id, "source": source, "opened_at": opened_at}
        for run_id, source, opened_at in rows
    ]


def record_run_snapshot(
    run_id: str, recorded_at: str, snapshot_fingerprint: str, identity: str
) -> bool:
    """
    Consemnează instantaneul de reputație pe care a rulat o rulare. O singură dată.

    Întoarce True dacă rândul a fost scris acum. Un al doilea apel pentru aceeași
    rulare nu rescrie nimic — prima consemnare e cea corectă, fiindcă ea descrie
    instantaneul care a răspuns primului eveniment.

    Dacă a doua consemnare vine cu ALTĂ amprentă, invarianta „o rulare vede un
    singur instantaneu" e ruptă, iar orice cifră a rulării devine imposibil de
    atribuit. Nu se repară aici și nu se aruncă: evenimentul care a declanșat-o
    e valid și trebuie primit. Se strigă în log, la ERROR, cu ambele amprente —
    o rulare care amestecă două instantanee trebuie aruncată de om, nu corectată
    tăcut de server.
    """
    with _lock:
        connection = _connection_locked()

        try:
            cursor = connection.execute(
                "INSERT INTO run_reputation "
                "(run_id, recorded_at, fingerprint, identity) VALUES (?, ?, ?, ?) "
                "ON CONFLICT (run_id) DO NOTHING",
                (run_id, recorded_at, snapshot_fingerprint, identity),
            )
            connection.commit()

            if cursor.rowcount == 1:
                return True

            existing = connection.execute(
                "SELECT fingerprint FROM run_reputation WHERE run_id = ?",
                (run_id,),
            ).fetchone()
        except sqlite3.Error as error:
            raise EventStoreError(
                f"Could not record the reputation snapshot of run {run_id!r}: {error}"
            ) from error

    if existing is not None and existing[0] != snapshot_fingerprint:
        logger.error(
            "Run %s has already been recorded against reputation snapshot %s, but "
            "an event was just answered by %s. A run must see exactly one "
            "snapshot; every figure of this run is now unattributable and the "
            "run should be discarded, not reused.",
            run_id,
            existing[0][:16],
            snapshot_fingerprint[:16],
        )

    return False


def run_snapshot(run_id: str) -> Optional[Dict[str, Any]]:
    """Instantaneul consemnat al unei rulări, sau None dacă n-a consultat depozitul."""
    with _lock:
        connection = _connection_locked()

        row = connection.execute(
            "SELECT recorded_at, fingerprint, identity FROM run_reputation "
            "WHERE run_id = ?",
            (run_id,),
        ).fetchone()

    if row is None:
        return None

    return {
        "recorded_at": row[0],
        "fingerprint": row[1],
        "identity": json.loads(row[2]),
    }


def close() -> None:
    """
    Închide conexiunea. Următorul acces o redeschide din calea configurată.

    Există pentru că un depozit persistent trebuie să se poată închide — la
    oprirea serverului, și în teste, unde închiderea urmată de o citire e
    singurul mod de a verifica onest ce SUPRAVIEȚUIEȘTE unei reporniri. Un test
    care ar citi din aceeași conexiune n-ar dovedi nimic despre disc.
    """
    global _connection

    with _lock:
        if _connection is not None:
            _connection.close()
            _connection = None


def reset_for_tests() -> None:
    """
    Închide baza curentă și repornește pe una din memorie.

    Nu golește tabelele: le aruncă. O bază din memorie dispare odată cu
    conexiunea, deci suita nu poate scrie niciodată în fișierul serverului și
    nu poate duce evenimente dintr-un test în următorul — aceeași grijă ca la
    `auth_service.reset_for_tests`, care dezactivează persistența cheilor.
    """
    global _connection, _db_path

    with _lock:
        if _connection is not None:
            _connection.close()

        _db_path = IN_MEMORY
        _connection = _connect(IN_MEMORY)
