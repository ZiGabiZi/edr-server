"""
Construirea instantaneului de reputație. Rulează AFARĂ, nu pe server.
=====================================================================

Partea de SCRIERE. Citirea e în `app/services/reputation_store.py`, care
deschide fișierul produs aici și nu are voie să-l modifice.

De ce codul stă în `edr-server` deși rulează pe gazdă:
    Locul rulării nu decide proprietatea. Schema pe care serverul o citește nu
    poate fi definită într-un repo care nu e al serverului — prima schimbare de
    schemă ar călători separat de codul care o citește, iar divergența aia e
    exact ce previne disciplina contractelor. De aceea `SCHEMA` se importă din
    `reputation_store`, nu se duplică aici.

De ce construirea nu se face pe server:
    Două motive, unul practic și unul de fond.

    Practic: construirea a zeci de milioane de rânduri cu index cere sursa,
    baza în lucru și spațiu tranzitoriu pentru index și `VACUUM` — la 2,5–3×
    dimensiunea finală, simultan. Un instantaneu de 20 GB ar cere ~55 GB
    tranzitoriu din cei 66 liberi ai serverului, pe o mașină care rulează și
    serverul.

    De fond, și e cel care contează: într-un mediu izolat, o bază de reputație
    NU se construiește în rețeaua închisă. Se construiește afară și se livrează
    ca artefact. E aceeași mișcare ca la coborârea rulesetului din §L2.8 —
    cunoașterea coboară, ca datele să nu urce. Faptul că importul iese de pe
    server nu e o abatere de la poveste, e poveste.

De ce `VACUUM INTO` la sigilare, și nu o simplă copiere:
    Baza de lucru poate rula în WAL, care e mult mai rapid la import. Dar o bază
    lăsată în WAL nu se poate deschide read-only fără drept de scriere: cititorul
    are nevoie să creeze `-wal` și `-shm`. Un instantaneu livrat în WAL ar face
    ca `mode=ro` să eșueze la prima deschidere, adică „imutabil" ar fi o intenție
    contrazisă imediat.

    `VACUUM INTO` rezolvă amândouă problemele dintr-o mișcare: scrie o copie
    compactă (fără paginile libere lăsate de import) în modul jurnal implicit.
    Cere SQLite ≥ 3.27; serverul are 3.45.

De ce sigilarea produce un fișier NOU și nu editează pe loc:
    `reputation_store` deschide cu `immutable=1`, ceea ce e o promisiune că
    fișierul nu se schimbă sub cititor. Un import care ar rescrie fișierul viu ar
    face promisiunea falsă și rezultatele nedefinite. Schimbul se face prin
    înlocuire: instantaneul nou se construiește lângă cel vechi, iar cele două
    coexistă cât durează schimbul. Bugetul de disc din intrarea de decizie
    (pragul R1, 20 GB) e calculat exact pe coexistența asta, cu factor 2.

Ce NU face modulul acesta, deși ar părea locul lui:
    Nu descarcă nimic. Importul propriu-zis — RDS pe axa de noutate, inventarul
    MalwareBazaar pe axa de amenințare — e la P2.2.4 și P2.2.5. Aici se
    construiește dulapul: schema, identitatea, sigilarea. La finalul pasului
    P2.2.3 instantaneul e gol și corect, ceea ce e singura ordine în care schema
    nu devine justificarea pentru ce s-a importat deja.

Rulare:
    python -m app.services.reputation_build --iesire storage/reputation.db
"""

import argparse
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence

from app.services.reputation_store import (
    AXIS_SOFTWARE,
    AXIS_THREAT,
    META_BUILDER,
    META_BUILT_AT,
    META_SCHEMA_VERSION,
    SCHEMA,
    SCHEMA_VERSION,
    ReputationStoreError,
    content_fingerprint,
    fingerprint,
)


# Cine a produs fișierul. Intră în `snapshot_meta`, ca un instantaneu găsit
# peste un an să-și poată spune proveniența fără să depindă de numele lui.
BUILDER = "edr-server/app/services/reputation_build.py"


class SnapshotBuildError(RuntimeError):
    """Instantaneul nu a putut fi construit sau sigilat."""


def _now() -> str:
    """UTC, cu fus explicit. Serverul jurnalizează UTC, gazda e UTC+3."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def create_working_database(path: Path) -> sqlite3.Connection:
    """
    Baza de LUCRU: schema goală, WAL pornit, pregătită pentru import.

    Nu e artefactul livrabil. Devine unul abia prin `seal()`, care scrie altundeva.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(str(path))

    # SQLite ignoră cheile străine dacă nu i se cere altfel, iar tăcerea aia ar
    # face din REFERENCES sources(source_id) un comentariu: un rând ar putea
    # arăta spre o sursă inexistentă, deci o afirmație fără proveniență ar trece
    # exact prin gaura pe care CHECK-urile o astupă în rest.
    connection.execute("PRAGMA foreign_keys=ON")

    # WAL doar pentru import: aici se scriu zeci de milioane de rânduri, iar
    # jurnalul implicit face un fsync pe tranzacție. Modul ăsta NU ajunge în
    # fișierul livrat — `VACUUM INTO` scrie în cel implicit, tocmai ca
    # deschiderea read-only să fie posibilă.
    connection.execute("PRAGMA journal_mode=WAL")

    # Importul e reluabil prin idempotență, nu prin durabilitate per tranzacție:
    # dacă mașina cade la mijloc, se reia importul, nu se recuperează rândul.
    # Un fsync per lot ar tripla timpul fără să schimbe procedura de reluare.
    connection.execute("PRAGMA synchronous=NORMAL")

    for statement in SCHEMA:
        connection.execute(statement)

    connection.execute(
        "INSERT OR REPLACE INTO snapshot_meta (key, value) VALUES (?, ?)",
        (META_SCHEMA_VERSION, str(SCHEMA_VERSION)),
    )
    connection.execute(
        "INSERT OR REPLACE INTO snapshot_meta (key, value) VALUES (?, ?)",
        (META_BUILDER, BUILDER),
    )

    connection.commit()

    return connection


def record_source(
    connection: sqlite3.Connection,
    name: str,
    axis: str,
    version: str,
    row_count: int,
) -> int:
    """
    Consemnează o sursă consultată, cu versiunea ei. Întoarce identificatorul.

    Versiunea sursei e singura apărare împotriva unui adevăr neplăcut: amprenta
    acoperă fișierul livrat, nu procesul care l-a produs. Sursele externe se
    schimbă — versiuni de RDS se retrag, inventarul MalwareBazaar se rotește —
    deci reconstruirea bit-cu-bit nu e garantată. Versiunea consemnată transformă
    „nu se poate reproduce" în „se poate reproduce dacă mai există sursa asta",
    ceea ce e o afirmație onestă în loc de una tăcută.
    """
    if axis not in (AXIS_SOFTWARE, AXIS_THREAT):
        raise SnapshotBuildError(
            f"Unknown axis {axis!r}; expected {AXIS_SOFTWARE!r} or {AXIS_THREAT!r}."
        )

    # UPSERT, nu INSERT OR REPLACE: al doilea ar ȘTERGE rândul și l-ar rescrie
    # cu alt source_id, iar rândurile din `reputation` care trimit spre el ar
    # rămâne agățate de un identificator care nu mai există. Un import reluat
    # ar rupe tăcut proveniența a tot ce s-a scris înainte de întrerupere.
    connection.execute(
        """
        INSERT INTO sources (name, axis, version, imported_at, row_count)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT (name) DO UPDATE SET
            axis        = excluded.axis,
            version     = excluded.version,
            imported_at = excluded.imported_at,
            row_count   = excluded.row_count
        """,
        (name, axis, version, _now(), row_count),
    )
    connection.commit()

    (source_id,) = connection.execute(
        "SELECT source_id FROM sources WHERE name = ?", (name,)
    ).fetchone()

    return source_id


def seal(connection: sqlite3.Connection, destination: Path) -> str:
    """
    Sigilează baza de lucru într-un instantaneu livrabil. Întoarce amprenta.

    `VACUUM INTO` refuză o destinație existentă, iar refuzul e binevenit: un
    instantaneu suprascris ar avea aceeași cale și alt conținut, adică exact
    minciuna pe care amprenta există s-o prevină. Schimbul se face prin
    redenumire, în afara acestei funcții și după ce amprenta a fost citită.
    """
    destination = Path(destination)

    if destination.exists():
        raise SnapshotBuildError(
            f"{destination} already exists. A snapshot is never overwritten in "
            f"place: build next to it, then replace."
        )

    destination.parent.mkdir(parents=True, exist_ok=True)

    connection.execute(
        "INSERT OR REPLACE INTO snapshot_meta (key, value) VALUES (?, ?)",
        (META_BUILT_AT, _now()),
    )
    connection.commit()

    try:
        # Parametrul nu se poate lega: VACUUM INTO cere un literal.
        connection.execute("VACUUM INTO ?", (str(destination),))
    except sqlite3.Error as error:
        raise SnapshotBuildError(
            f"Could not seal the snapshot into {destination}: {error}"
        ) from error

    return fingerprint(str(destination))


def build_empty_snapshot(destination: Path, working: Optional[Path] = None) -> str:
    """
    Construiește un instantaneu gol, dar complet: schemă, identitate, sigiliu.

    E starea de la finalul lui P2.2.3. Un depozit gol răspunde la fel de corect
    ca unul plin — pe ambele axe, cu „necunoscut" — iar rularea rece din ablație
    e chiar el.
    """
    destination = Path(destination)
    working = Path(working) if working else destination.with_suffix(".build")

    if working.exists():
        working.unlink()

    connection = create_working_database(working)

    try:
        amprenta = seal(connection, destination)
    finally:
        connection.close()

        for rest in (working, Path(str(working) + "-wal"), Path(str(working) + "-shm")):
            if rest.exists():
                rest.unlink()

    return amprenta


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Construieste un instantaneu de reputatie (P2.2.3: gol).",
    )
    parser.add_argument(
        "--iesire",
        required=True,
        help="Calea fisierului livrat. Nu se suprascrie daca exista.",
    )
    parser.add_argument(
        "--lucru",
        default=None,
        help="Baza de lucru intermediara. Implicit, <iesire>.build.",
    )
    parser.add_argument(
        "--sigileaza-din",
        default=None,
        help="Sigileaza o baza de lucru deja importata, in loc sa construiasca una goala.",
    )

    argumente = parser.parse_args(argv)

    try:
        if argumente.sigileaza_din:
            lucru = Path(argumente.sigileaza_din)

            if not lucru.exists():
                raise SnapshotBuildError(f"There is no working database at {lucru}.")

            connection = sqlite3.connect(str(lucru))

            try:
                # Amprenta de continut se calculeaza INAINTE de sigilare, pe baza
                # de lucru: dupa VACUUM INTO ar fi aceeasi, dar drumul pana la ea
                # ar trece printr-o a doua deschidere a unui fisier de gigaocteti.
                continut = content_fingerprint(connection)
                randuri, surse = _inventar(connection)
                amprenta = seal(connection, Path(argumente.iesire))
            finally:
                connection.close()
        else:
            amprenta = build_empty_snapshot(Path(argumente.iesire), argumente.lucru)
            continut, randuri, surse = None, 0, []
    except (SnapshotBuildError, ReputationStoreError) as error:
        print(f"eroare: {error}", file=sys.stderr)
        return 1

    marime = Path(argumente.iesire).stat().st_size

    print(f"instantaneu: {argumente.iesire}")
    print(f"schema:      versiunea {SCHEMA_VERSION}")
    print(f"marime:      {marime / 1024 ** 3:.2f} GB")
    print(f"randuri:     {randuri}")
    print(f"amprenta:    {amprenta}")

    if continut:
        print(f"continut:    {continut}")

    for nume, axa, versiune, cate in surse:
        print(f"  sursa:     {nume} ({axa}, {versiune}) - {cate} randuri")

    print()

    if randuri:
        print("Amprenta si lista surselor se declara langa orice cifra (METRICS.md 8).")
    else:
        print("Depozitul e gol. Importul e la P2.2.4 si P2.2.5.")

    return 0


def _inventar(connection: sqlite3.Connection):
    """Cate randuri si ce surse, pentru raportul de la sfarsitul sigilarii."""
    (randuri,) = connection.execute("SELECT COUNT(*) FROM reputation").fetchone()

    surse = connection.execute(
        "SELECT name, axis, version, row_count FROM sources ORDER BY axis, name"
    ).fetchall()

    return randuri, surse


if __name__ == "__main__":
    raise SystemExit(main())
