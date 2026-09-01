"""
Importul pe axa de AMENINTARE: inventarul MalwareBazaar.
========================================================

Pasul P2.2.5. Ruleaza pe gazda, ca tot ce tine de constructie. Nu descarca
nimic si nu atinge nicio mostra: citeste inventarul de metadate strans la P2.1.

ATENTIE, si e cel mai important lucru din modulul acesta:
    Selectia corpusului a fost facuta DIN acest inventar. Toate cele 330 de
    mostre malitioase ale corpusului sunt printre cele 14.251 de intrari de aici.
    Deci un instantaneu care contine axa asta inchide INTREGUL strat malitios la
    T0, iar raportul de divulgare iese spectaculos fara ca protocolul sa fi facut
    ceva.

    Asta NU e un bug si nu e un motiv sa nu importam. E chiar bratul
    SEMIINZESTRAT al ablatiei declarate in intrarea de decizie: se ruleaza
    experimentul si cu, si fara sursa asta, iar diferenta dintre cele doua
    masoara cat din economie vine din reputatie - arta anterioara - si cat din
    protocol. Fara ablatia aia, oricine poate sustine ca rezultatul masoara o
    lista de hash-uri.

    De aceea fiecare rand poarta sursa: selectia surselor consultate e parametru
    de rulare, nu proprietate a depozitului. Bratul RECE se obtine excluzand
    sursa la interogare, nu construind alt instantaneu.

    Consecinta practica, scrisa aici ca sa nu se piarda: o cifra de divulgare
    raportata fara sa spuna care brat a fost rulat nu inseamna nimic.

De ce inventarul si nu selectia:
    Inventarul are 14.251 de intrari, selectia 330. Daca axa de amenintare ar fi
    alimentata din exact ce s-a selectat pentru corpus, potrivirea ar fi
    garantata prin constructie si depozitul n-ar contine nicio informatie despre
    fisiere pe care nu le stim deja. Cu inventarul intreg, exista si intrari care
    NU sunt in corpus, deci depozitul are ce sa nu stie.

    Diferenta se declara, nu se presupune: raportul de acoperire de la P2.2.6
    numara cate din cele 14.251 ating corpusul.

    Modulul refuza un fisier de selectie, structural. Un mesaj de avertisment
    ar fi fost citit o data si sarit a doua oara.

De ce nu are cursor de reluare, spre deosebire de importul RDS:
    14.251 de randuri incap intr-o singura tranzactie. Asta e o garantie mai TARE
    decat reluarea: importul fie s-a intamplat intreg, fie deloc, deci nu exista
    stare partiala de reconciliat. Cursorul de la RDS exista fiindca 432 de
    milioane de randuri nu incap intr-o tranzactie, nu fiindca reluarea ar fi
    preferabila.

Rulare:
    python -m app.services.reputation_import_bazaar \\
        --sursa /mnt/c/Malware_Samples/inventar/inventar.json \\
        --depozit storage/reputation.build
"""

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Tuple

from app.services.reputation_build import (
    SnapshotBuildError,
    create_working_database,
    record_source,
)
from app.services.reputation_store import AXIS_THREAT


# Numele sub care inventarul apare in `sources`. Fix, fiindca ablatia
# rece/semiinzestrat selecteaza sursele pe nume.
SOURCE_NAME = "MalwareBazaar"


class BazaarImportError(RuntimeError):
    """Inventarul nu a putut fi citit, sau nu e un inventar."""


def load_inventory(path: Path) -> Tuple[Dict[str, dict], str]:
    """
    Intrarile inventarului si versiunea lui. Refuza un fisier de selectie.

    Versiunea e momentul in care inventarul a fost strans, nu una data de
    operator: e o proprietate a datelor, iar un numar tastat de mana ar putea
    descrie alt inventar decat cel citit.
    """
    try:
        continut = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise BazaarImportError(
            f"Could not read the inventory at {path}: {error}"
        ) from error

    # Garda structurala. Un fisier de selectie are `source_inventory` si tine
    # `samples` ca lista; inventarul le tine ca dictionar, indexat pe hash.
    if "source_inventory" in continut:
        raise BazaarImportError(
            f"{path} is a corpus SELECTION, not the inventory. Importing it would "
            f"make the threat axis contain exactly the corpus and nothing else, so "
            f"every match would be guaranteed by construction. Use the file named "
            f"in its source_inventory field instead."
        )

    intrari = continut.get("samples")

    if not isinstance(intrari, dict):
        raise BazaarImportError(
            f"{path} has no samples dictionary; it was not produced by "
            f"Malware_Bazar.py."
        )

    return intrari, continut.get("generated_at") or "necunoscut"


def _sha256(cheie: str, intrare: dict) -> Optional[bytes]:
    """
    Amprenta, din cheia dictionarului.

    Cheia e sursa de adevar, nu campul sha256 din interior: in inventarul strans
    la P2.1 campul acela e trunchiat la unele intrari, in timp ce cheia e
    intotdeauna hash-ul intreg. O nepotrivire ar fi trecut neobservata si ar fi
    produs randuri care nu se potrivesc niciodata cu nimic.
    """
    text = (cheie or "").strip()

    if len(text) != 64:
        return None

    try:
        return bytes.fromhex(text)
    except ValueError:
        return None


def import_bazaar(
    source_path: Path,
    target: sqlite3.Connection,
    version: Optional[str] = None,
    progress=None,
) -> Dict[str, Any]:
    """
    Importa axa de amenintare din inventar. Intoarce cifrele de raportat.

    Intr-o singura tranzactie: fie tot, fie nimic.
    """
    intrari, versiune_inventar = load_inventory(Path(source_path))
    versiune = version or versiune_inventar

    if progress:
        progress(f"inventar: {len(intrari)} intrari, versiunea {versiune}")

    source_id = record_source(target, SOURCE_NAME, AXIS_THREAT, versiune, 0)

    randuri = []
    sarite = 0

    for cheie, intrare in intrari.items():
        octeti = _sha256(cheie, intrare)

        if octeti is None:
            sarite += 1
            continue

        nume = intrare.get("file_name")

        randuri.append((
            octeti,
            source_id,
            intrare.get("signature") or None,
            intrare.get("first_seen") or None,
            nume or None,
            1 if nume else None,
        ))

    target.execute("BEGIN")
    target.executemany(
        """
        INSERT INTO reputation
            (sha256, known_malicious, threat_source, family, first_seen,
             representative_name, name_count)
        VALUES (?, 1, ?, ?, ?, ?, ?)
        ON CONFLICT (sha256) DO UPDATE SET
            known_malicious     = 1,
            threat_source       = excluded.threat_source,
            family              = COALESCE(excluded.family, family),
            first_seen          = COALESCE(excluded.first_seen, first_seen),
            representative_name = COALESCE(representative_name, excluded.representative_name),
            name_count          = COALESCE(name_count, excluded.name_count)
        """,
        randuri,
    )
    target.commit()

    (total,) = target.execute(
        "SELECT COUNT(*) FROM reputation WHERE known_malicious = 1"
    ).fetchone()

    (ambele,) = target.execute(
        "SELECT COUNT(*) FROM reputation "
        "WHERE known_malicious = 1 AND known_software = 1"
    ).fetchone()

    record_source(target, SOURCE_NAME, AXIS_THREAT, versiune, total)

    return {
        "intrari_in_inventar": len(intrari),
        "randuri_pe_axa": total,
        "suprapunere_cu_rds": ambele,
        "sarite": sarite,
        "versiune": versiune,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Importa axa de amenintare din inventarul MalwareBazaar (P2.2.5).",
    )
    parser.add_argument("--sursa", required=True, help="inventar.json, nu selectie.json.")
    parser.add_argument("--depozit", required=True, help="Baza de lucru a instantaneului.")
    parser.add_argument(
        "--versiune", default=None,
        help="Implicit, momentul strangerii inventarului, citit din fisier.",
    )

    argumente = parser.parse_args(argv)

    target = create_working_database(Path(argumente.depozit))

    try:
        cifre = import_bazaar(
            Path(argumente.sursa),
            target,
            argumente.versiune,
            progress=lambda linie: print(linie, flush=True),
        )
    except (BazaarImportError, SnapshotBuildError) as error:
        print(f"eroare: {error}", file=sys.stderr)
        return 1
    finally:
        target.close()

    print()
    print("intrari in inventar   : %d" % cifre["intrari_in_inventar"])
    print("randuri pe axa        : %d" % cifre["randuri_pe_axa"])
    print("suprapunere cu RDS    : %d" % cifre["suprapunere_cu_rds"])

    if cifre["sarite"]:
        print("sarite, hash necitibil: %d" % cifre["sarite"])

    print()
    print("ATENTIE: selectia corpusului a fost facuta DIN acest inventar, deci un")
    print("instantaneu care il contine inchide tot stratul malitios la T0. Asta e")
    print("bratul SEMIINZESTRAT al ablatiei. Orice cifra de divulgare raportata")
    print("trebuie sa spuna care brat a fost rulat.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
