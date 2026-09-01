"""
Raportul de acoperire: cat din corpus stie depozitul, inainte de orice masuratoare.
===================================================================================

Pasul P2.2.6. Ruleaza offline, fara retea, din manifestul corpusului si dintr-un
instantaneu identificat prin amprenta. Nu produce niciun verdict si nu atinge
protocolul: numara.

De ce cifra asta se datoreaza oricum:
    Fractiunea din corpus prezenta in depozit decide direct cat poate inchide
    T0. Fara ea, un raport de divulgare bun n-ar putea fi deosebit de un corpus
    care se intampla sa fie deja cunoscut. E numitorul moral al rezultatului.

Capcana de ordine, si e usor de calcat:
    Cifra se calculeaza si se raporteaza, dar regula de decizie se enunta INAINTE
    de a o vedea. Altfel se alege importul care maximizeaza acoperirea, adica
    pescuit. Regulile de mai jos sunt scrise inainte de prima rulare:

    ARTEFACTELE COMPILATE trebuie sa fie ABSENTE din RDS, toate.
        Sunt programe compilate local, cu minute inainte. Daca apar in lista
        NIST, ceva e profund gresit - fie manifestul, fie importul, fie
        presupunerea ca sunt necunoscute. CORPUS.md 3.1 le cere tocmai ca sa
        existe fisiere benigne SI necunoscute in acelasi timp; daca RDS le
        cunoaste, categoria aia nu exista si banda ar invata ca tot ce e
        necunoscut e malitios.

    BINARELE DE SISTEM trebuie sa fie PREZENTE in RDS, in majoritate covarsitoare.
        Vin dintr-o instalare curata de Windows, adica exact ce colectioneaza
        NSRL. Daca lipsesc, concluzia NU e ca ceva e stricat la corpus: e ca
        editia importata nu acopera versiunea de Windows folosita. Intrarea de
        decizie permite explicit UN reimport declarat in avans pentru cazul asta,
        cu ambele acoperiri raportate.

De ce raportul cere amprenta:
    Un raport care nu spune peste ce instantaneu a rulat descrie un sistem care
    nu se poate reconstitui. Cu `--amprenta`, raportul REFUZA sa ruleze daca
    fisierul nu e cel asteptat - altfel o cale gresita ar produce zerouri, adica
    cea mai flatanta cifra posibila despre un sistem de confidentialitate,
    obtinuta dintr-o greseala de tastare.

Rulare:
    python -m app.services.reputation_coverage \\
        --manifest /mnt/d/Corpus_Manifest/manifest.json \\
        --instantaneu storage/reputation.db
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from app.services.reputation_store import (
    ReputationStoreError,
    fingerprint,
    open_readonly,
)


class CoverageError(RuntimeError):
    """Raportul nu a putut fi produs, sau ar fi descris alt instantaneu."""


def load_manifest(path: Path) -> list:
    """Fisierele din manifest. Doar cele cu amprenta citibila intra in raport."""
    try:
        continut = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise CoverageError(f"Could not read the manifest at {path}: {error}") from error

    fisiere = continut.get("files")

    if not isinstance(fisiere, list):
        raise CoverageError(
            f"The manifest at {path} has no files list; it was not produced by "
            f"Manifest_Corpus.py."
        )

    return fisiere


def measure(fisiere: Sequence[dict], connection) -> Dict[str, Any]:
    """
    Numara, pe straturi si pe origini, ce stie depozitul despre fiecare fisier.

    Interogarea se face fisier cu fisier, nu printr-un JOIN peste un tabel
    temporar: 1494 de cautari intr-un index sunt milisecunde, iar varianta cu
    tabel temporar ar cere scriere intr-un instantaneu deschis read-only.
    """
    per_origine: Dict[str, Counter] = {}
    total = Counter()
    hash_uri_rele = 0

    for fisier in fisiere:
        text = (fisier.get("sha256") or "").strip()

        try:
            octeti = bytes.fromhex(text)
        except ValueError:
            octeti = b""

        if len(octeti) != 32:
            hash_uri_rele += 1
            continue

        rand = connection.execute(
            "SELECT known_software, known_malicious FROM reputation WHERE sha256 = ?",
            (octeti,),
        ).fetchone()

        software = bool(rand[0]) if rand else False
        amenintare = bool(rand[1]) if rand else False

        origine = fisier.get("origin") or "necunoscut"
        contor = per_origine.setdefault(
            origine,
            Counter(
                {
                    "fisiere": 0,
                    "in_rds": 0,
                    "amenintare": 0,
                    "ambele": 0,
                    "necunoscut": 0,
                }
            ),
        )

        for tinta in (contor, total):
            tinta["fisiere"] += 1
            tinta["in_rds"] += software
            tinta["amenintare"] += amenintare
            tinta["ambele"] += software and amenintare
            tinta["necunoscut"] += not (software or amenintare)

        contor["strat"] = fisier.get("stratum") or "?"
        contor["eticheta"] = fisier.get("label") or "?"

    return {
        "total": dict(total),
        "per_origine": {k: dict(v) for k, v in sorted(per_origine.items())},
        "hash_uri_necitibile": hash_uri_rele,
    }


def sanity_checks(masuratoare: Dict[str, Any]) -> list:
    """
    Cele doua verificari enuntate inainte de prima rulare. Fiecare intoarce
    (nume, trecut, explicatie).
    """
    rezultate = []
    per_origine = masuratoare["per_origine"]

    compilate = per_origine.get("compilat")

    if compilate:
        gasite = compilate["in_rds"]
        rezultate.append((
            "artefactele compilate lipsesc din RDS",
            gasite == 0,
            f"{gasite} din {compilate['fisiere']} apar in RDS; asteptat 0. "
            f"Sunt compilate local, deci prezenta lor ar insemna ca manifestul, "
            f"importul sau presupunerea ca sunt necunoscute e gresita.",
        ))

    sistem = per_origine.get("sistem")

    if sistem and sistem["fisiere"]:
        procent = 100.0 * sistem["in_rds"] / sistem["fisiere"]
        rezultate.append((
            "binarele de sistem apar in RDS",
            procent >= 50.0,
            f"{sistem['in_rds']} din {sistem['fisiere']} ({procent:.1f}%). "
            f"Sub 50% inseamna ca editia importata nu acopera versiunea de "
            f"Windows folosita - subset prost ales, nu corpus gresit.",
        ))

    return rezultate


def _procent(parte: int, intreg: int) -> str:
    return "%5.1f%%" % (100.0 * parte / intreg) if intreg else "    -"


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Raportul de acoperire peste manifest (pasul P2.2.6).",
    )
    parser.add_argument("--manifest", required=True, help="manifest.json al corpusului.")
    parser.add_argument("--instantaneu", required=True, help="Instantaneul de reputatie.")
    parser.add_argument(
        "--amprenta",
        default=None,
        help="Amprenta asteptata. Raportul refuza sa ruleze daca nu se potriveste.",
    )

    argumente = parser.parse_args(argv)

    try:
        amprenta = fingerprint(argumente.instantaneu)

        if argumente.amprenta and argumente.amprenta != amprenta:
            raise CoverageError(
                f"The snapshot at {argumente.instantaneu} has fingerprint "
                f"{amprenta}, not the expected {argumente.amprenta}. Refusing to "
                f"report on a different snapshot than the one you named."
            )

        fisiere = load_manifest(Path(argumente.manifest))
        connection = open_readonly(argumente.instantaneu)

        try:
            masuratoare = measure(fisiere, connection)
            surse = connection.execute(
                "SELECT name, axis, version, row_count FROM sources ORDER BY axis, name"
            ).fetchall()
        finally:
            connection.close()
    except (CoverageError, ReputationStoreError) as error:
        print(f"eroare: {error}", file=sys.stderr)
        return 1

    total = masuratoare["total"]

    print("Instantaneu : %s" % argumente.instantaneu)
    print("Amprenta    : %s" % amprenta)
    print("Surse       :")

    for nume, axa, versiune, randuri in surse:
        print("   %-16s %-9s %-12s %d randuri" % (nume, axa, versiune, randuri))

    print()
    print("%-12s %7s %9s %8s %11s %8s %11s" % (
        "origine", "fisiere", "in RDS", "%", "amenintare", "ambele", "necunoscut"))
    print("-" * 74)

    for origine, c in masuratoare["per_origine"].items():
        print("%-12s %7d %9d %8s %11d %8d %11d" % (
            origine, c["fisiere"], c["in_rds"], _procent(c["in_rds"], c["fisiere"]),
            c["amenintare"], c["ambele"], c["necunoscut"]))

    print("-" * 74)
    print("%-12s %7d %9d %8s %11d %8d %11d" % (
        "TOTAL", total["fisiere"], total["in_rds"],
        _procent(total["in_rds"], total["fisiere"]),
        total["amenintare"], total["ambele"], total["necunoscut"]))

    if masuratoare["hash_uri_necitibile"]:
        print()
        print("hash-uri necitibile in manifest: %d" % masuratoare["hash_uri_necitibile"])

    print()
    print("Verificari de sanatate, enuntate inainte de prima rulare:")

    esecuri = 0
    for nume, trecut, explicatie in sanity_checks(masuratoare):
        print("   [%s] %s" % ("ok" if trecut else "ESEC", nume))
        print("        %s" % explicatie)
        esecuri += not trecut

    print()
    print("Cifra care conteaza: %s din corpus se poate inchide la T0 prin reputatie."
          % _procent(total["in_rds"] + total["amenintare"] - total["ambele"],
                     total["fisiere"]).strip())

    return 1 if esecuri else 0


if __name__ == "__main__":
    raise SystemExit(main())
