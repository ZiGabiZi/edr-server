"""
Importul pe axa de NOUTATE: RDS-ul NIST, adus in depozitul de reputatie.
========================================================================

Pasul P2.2.4. Ruleaza pe gazda, in afara retelei inchise, ca tot ce tine de
constructie. Nu descarca nimic: primeste calea unei baze RDS deja dezarhivate
si o citeste.

Ce scrie, si ce NU scrie:
    Scrie EXCLUSIV pe axa de noutate: known_software = 1, cu sursa RDS. Nu
    atinge niciodata known_malicious, si nu poate, fiindca `CORPUS.md` 5.4
    interzice verdictul curat derivat din apartenenta la RDS. NIST avertizeaza
    explicit ca lista contine hash-uri ale unor aplicatii care pot fi
    considerate malitioase; RDS spune doar ca fisierul nu e nou.

    Consecinta practica, si e chiar celula interesanta din 2x2: un fisier deja
    marcat malitios dintr-o sursa de amenintari NU isi pierde eticheta cand
    apare si in RDS. Capata known_software = 1 pe langa ea. Precedenta se aplica
    la derivare, nu la import, tocmai ca faptul sa nu se distruga ireversibil.

De ce schema sursei se descopera, nu se presupune:
    RDSv3 si-a schimbat forma de mai multe ori, iar noi importam o editie care
    nu exista inca in momentul scrierii codului. Un nume de tabel scris de mana
    ar transforma prima schimbare de format a NIST intr-o eroare la mijlocul
    unui import de ore. Codul cauta tabelul care are o coloana sha256 si cele
    mai multe randuri, si spune ce a gasit inainte sa inceapa.

Idempotenta: de ce UPSERT si nu INSERT OR IGNORE:
    OR IGNORE ar sari peste un hash deja prezent pe axa de amenintare si nu i-ar
    mai pune niciodata known_software = 1. Suprapunerea dintre cele doua axe ar
    disparea tacut, adica exact cifra pe care 2x2-ul exista sa o poata numara,
    si ar disparea in functie de ORDINEA importurilor - cel mai greu fel de bug
    de observat, fiindca rezultatul e plauzibil in ambele ordini.

Reluare: de ce cursorul e un hash si nu un numar de rand:
    Un OFFSET si-ar schimba intelesul daca sursa se schimba intre incercari, iar
    un contor de randuri procesate presupune o ordine pe care SQLite n-o
    garanteaza fara ORDER BY. Cursorul e ultimul sha256 comis, iar reluarea cere
    randurile strict mai mari decat el. E stabil, verificabil si nu depinde de
    cate ori a fost intrerupt importul.

    Cursorul se scrie in aceeasi tranzactie cu lotul de randuri. Daca ar fi doua
    tranzactii, o cadere intre ele ar lasa depozitul si cursorul dezacordate, iar
    reluarea ar sari peste randuri sau le-ar rescrie - a doua e inofensiva, prima
    nu.

De ce contorul de randuri se numara la final, nu se incrementeaza:
    `sources.row_count` trebuie sa descrie depozitul, nu istoria importului. Un
    contor incrementat ar numara de doua ori randurile atinse de doua rulari
    reluate, iar cifra aia ajunge in `METRICS.md` 8, langa rezultate.

Rulare:
    python -m app.services.reputation_import_rds \\
        --sursa /cale/RDS_2026.03.1_modern_minimal.db \\
        --depozit storage/reputation.build \\
        --versiune 2026.03.1
"""

import argparse
import sqlite3
import sys
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from app.services.reputation_build import (
    SnapshotBuildError,
    create_working_database,
    record_source,
)
from app.services.reputation_store import AXIS_SOFTWARE


# Numele sub care RDS apare in `sources` si in orice raportare. Fix, fiindca
# ablatia rece/semiinzestrat selecteaza sursele pe nume.
SOURCE_NAME = "NSRL RDS"

# Cheia din `snapshot_meta` sub care traieste cursorul de reluare.
CURSOR_KEY = "import_cursor_rds"

# Cate randuri intr-o tranzactie. Prea mic inseamna un fsync la fiecare
# nimic; prea mare inseamna ca o intrerupere arunca mult lucru bun.
BATCH = 50_000


class RdsImportError(RuntimeError):
    """Sursa RDS nu a putut fi citita sau nu e ce pretinde ca e."""


def discover_file_table(source: sqlite3.Connection) -> Tuple[str, str]:
    """
    Gaseste tabelul si coloana care poarta sha256 in baza RDS.

    Intoarce (tabel, coloana). Daca sunt mai multi candidati, castiga cel cu mai
    multe randuri: in RDSv3, tabelul FILE e cu ordine de marime peste orice
    tabel auxiliar care ar putea avea si el o coloana de hash.
    """
    candidati: List[Tuple[str, str]] = []

    # DOAR tabele, niciodata vederi. RDSv3 publica o vedere DISTINCT_HASH,
    # definita ca SELECT DISTINCT sha256, ... FROM FILE. Ar parea sursa ideala —
    # exact hash-urile distincte — dar SQLite ar trebui sa materializeze un
    # DISTINCT peste 432 de milioane de randuri, o data ca sa o numere si o data
    # ca sa o citeasca. Tabelul FILE, citit in ordinea cheii primare, da acelasi
    # rezultat prin UPSERT si costa o singura parcurgere.
    tabele = [
        nume for (nume,) in source.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' "
            "AND name NOT LIKE 'sqlite_%'"
        )
    ]

    for tabel in tabele:
        try:
            coloane = source.execute('PRAGMA table_info("%s")' % tabel).fetchall()
        except sqlite3.Error:
            continue

        for coloana in coloane:
            if coloana[1].lower() == "sha256":
                candidati.append((tabel, coloana[1]))
                break

    if not candidati:
        raise RdsImportError(
            "No table with a sha256 column was found in the RDS source. "
            "Check that the file is an RDSv3 SQLite database, not the zip."
        )

    # Un singur candidat: nu se numara nimic. COUNT(*) peste 432 de milioane de
    # randuri e o parcurgere completa, adica minute bune platite doar ca sa
    # confirmam ce stim deja.
    if len(candidati) == 1:
        return candidati[0]

    def numara(pereche: Tuple[str, str]) -> int:
        try:
            (n,) = source.execute('SELECT COUNT(*) FROM "%s"' % pereche[0]).fetchone()
            return n
        except sqlite3.Error:
            return -1

    return max(candidati, key=numara)


def source_is_indexed(source: sqlite3.Connection, table: str, column: str) -> bool:
    """
    Are sursa un index care incepe cu coloana de hash?

    Intrebarea nu e de eleganta, e diferenta dintre ore si zile. Reluarea cere
    randurile in ordinea hash-ului, cu WHERE sha256 > cursor ORDER BY sha256.
    Cu index, fiecare lot e o cautare urmata de o citire secventiala. Fara index,
    fiecare lot sorteaza din nou tot tabelul - 432 de milioane de randuri, de
    peste 1400 de ori.

    Verificarea se face inainte de primul rand, fiindca altfel diferenta s-ar
    observa dupa cateva ore de import care pare doar lent.
    """
    for (nume_index,) in source.execute(
        "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = ?",
        (table,),
    ):
        coloane = source.execute('PRAGMA index_info("%s")' % nume_index).fetchall()

        if coloane and coloane[0][2] and coloane[0][2].lower() == column.lower():
            return True

    # O coloana INTEGER PRIMARY KEY sau o cheie primara pe hash conteaza la fel.
    for coloana in source.execute('PRAGMA table_info("%s")' % table):
        if coloana[1].lower() == column.lower() and coloana[5]:
            return True

    return False


def _as_bytes(valoare) -> Optional[bytes]:
    """
    Hash-ul sursei, ca 32 de octeti bruti.

    RDS il tine ca text hexazecimal, de obicei cu majuscule, dar formatul s-a
    mai schimbat. Un rand pe care nu-l putem citi se sare si se numara; oprirea
    intregului import pentru un rand stricat ar transforma o imperfectiune a
    sursei intr-o zi pierduta.
    """
    if isinstance(valoare, (bytes, bytearray)):
        return bytes(valoare) if len(valoare) == 32 else None

    if isinstance(valoare, str):
        text = valoare.strip()

        if len(text) != 64:
            return None

        try:
            return bytes.fromhex(text)
        except ValueError:
            return None

    return None


def _cursor(target: sqlite3.Connection) -> Optional[str]:
    rand = target.execute(
        "SELECT value FROM snapshot_meta WHERE key = ?", (CURSOR_KEY,)
    ).fetchone()

    return rand[0] if rand else None


def import_rds(
    source_path: Path,
    target: sqlite3.Connection,
    version: str,
    limit: Optional[int] = None,
    progress=None,
) -> int:
    """
    Importa axa de noutate din baza RDS de la `source_path`. Intoarce randurile
    din depozit dupa import.

    Reluabila: o a doua rulare peste acelasi depozit continua de unde a ramas si,
    daca nu mai are ce continua, nu schimba nimic.
    """
    source_path = Path(source_path)

    if not source_path.exists():
        raise RdsImportError(f"There is no RDS database at {source_path}.")

    source = sqlite3.connect(
        Path(source_path).resolve().as_uri() + "?mode=ro", uri=True
    )

    try:
        tabel, coloana = discover_file_table(source)

        if progress:
            progress(f"sursa: tabelul {tabel}, coloana {coloana}")

        if not source_is_indexed(source, tabel, coloana):
            raise RdsImportError(
                f"The RDS source has no index starting with {tabel}.{coloana}. "
                f"Resuming reads rows in hash order, so every batch would re-sort "
                f"the whole table - hours become days, and you would only notice "
                f"after the import already looks slow. Build the index once "
                f"(it is a local copy, not NIST's file):\n\n"
                f'    sqlite3 "{source_path}" '
                f'"CREATE INDEX IF NOT EXISTS idx_import_{coloana} '
                f'ON \\"{tabel}\\" (\\"{coloana}\\");"\n'
            )

        # Sursa se consemneaza INAINTE de primul rand: cheia straina din
        # `reputation` are nevoie de identificator, iar un import intrerupt
        # imediat trebuie sa lase in urma o sursa cu zero randuri, nu randuri
        # fara sursa.
        source_id = record_source(target, SOURCE_NAME, AXIS_SOFTWARE, version, 0)

        cursor = _cursor(target)
        sarite = 0
        adaugate = 0

        while True:
            interogare = 'SELECT "%s" FROM "%s"' % (coloana, tabel)
            parametri: Tuple = ()

            if cursor is not None:
                interogare += ' WHERE "%s" > ?' % coloana
                parametri = (cursor,)

            interogare += ' ORDER BY "%s" LIMIT ?' % coloana
            parametri = parametri + (BATCH,)

            lot = source.execute(interogare, parametri).fetchall()

            if not lot:
                break

            randuri = []
            for (valoare,) in lot:
                octeti = _as_bytes(valoare)

                if octeti is None:
                    sarite += 1
                    continue

                randuri.append((octeti, source_id))

            # Lotul si cursorul, in ACEEASI tranzactie. Separate, o cadere intre
            # ele ar lasa depozitul mai avansat decat cursorul, iar reluarea ar
            # rescrie randuri, sau invers, si ar sari peste ele.
            target.execute("BEGIN")
            target.executemany(
                """
                INSERT INTO reputation (sha256, known_software, software_source)
                VALUES (?, 1, ?)
                ON CONFLICT (sha256) DO UPDATE SET
                    known_software  = 1,
                    software_source = excluded.software_source
                """,
                randuri,
            )

            cursor = lot[-1][0]

            target.execute(
                "INSERT OR REPLACE INTO snapshot_meta (key, value) VALUES (?, ?)",
                (CURSOR_KEY, cursor),
            )
            target.commit()

            adaugate += len(randuri)

            if progress:
                progress(f"  {adaugate} randuri, ultimul {str(cursor)[:16]}")

            if limit is not None and adaugate >= limit:
                break

        # Contorul se NUMARA, nu se incrementeaza: trebuie sa descrie depozitul,
        # nu de cate ori a fost reluat importul.
        #
        # Numaratoarea e o scanare completa, fiindca nu exista index pe axe -
        # scos deliberat la P2.2.4, unde am masurat ca ar costa 39,5 octeti pe
        # rand ca sa economiseasca minute intr-o raportare rulata o data.
        # Factura se plateste aici, cateva minute, o singura data. Se anunta,
        # fiindca altfel ultimul pas al unui import de ore arata ca o blocare.
        if progress:
            progress("numar randurile pentru sources.row_count; "
                     "e o scanare completa, dureaza cateva minute...")

        (total,) = target.execute(
            "SELECT COUNT(*) FROM reputation WHERE known_software = 1"
        ).fetchone()

        record_source(target, SOURCE_NAME, AXIS_SOFTWARE, version, total)

        if sarite and progress:
            progress(f"randuri sarite, hash necitibil: {sarite}")

        return total
    finally:
        source.close()


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Importa axa de noutate din RDS (pasul P2.2.4).",
    )
    parser.add_argument("--sursa", required=True, help="Baza RDS dezarhivata (.db).")
    parser.add_argument("--depozit", required=True, help="Baza de lucru a instantaneului.")
    parser.add_argument("--versiune", required=True, help="Versiunea editiei RDS.")
    parser.add_argument(
        "--limita", type=int, default=None,
        help="Opreste-te dupa N randuri. Pentru o proba, nu pentru productie.",
    )

    argumente = parser.parse_args(argv)

    depozit = Path(argumente.depozit)
    target = create_working_database(depozit)

    try:
        total = import_rds(
            Path(argumente.sursa),
            target,
            argumente.versiune,
            limit=argumente.limita,
            progress=lambda linie: print(linie, flush=True),
        )
    except (RdsImportError, SnapshotBuildError) as error:
        print(f"eroare: {error}", file=sys.stderr)
        return 1
    finally:
        target.close()

    marime = depozit.stat().st_size

    print()
    print(f"randuri pe axa de noutate: {total}")
    print(f"baza de lucru:             {marime / 1024 ** 3:.2f} GB")

    if total:
        print(f"octeti pe rand:            {marime / total:.1f}")

    print()
    print("Baza de lucru NU e instantaneul. Sigilarea e cu reputation_build.seal().")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
