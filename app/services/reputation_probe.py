"""
Ce ar răspunde serverul pentru un hash — interogat de mână, fără server pornit.
==============================================================================

La ce folosește:
    Verificarea pasului P2.3 pe date reale, și întrebarea operațională de zi cu
    zi — „ce știe depozitul despre amprenta asta". Consultă exact codul pe care
    îl folosește ingestia, deci ce afișează aici e ce ar pune serverul în
    răspuns.

De ce nu pornește un server:
    Un `uvicorn` cere port liber, credențiale de înrolare și o bază de
    evenimente; verificarea ar depinde de trei lucruri care n-au legătură cu ce
    se verifică. Iar în rețeaua închisă unde rulează măsurătoarea, unealta care
    răspunde cel mai repede la „de ce s-a închis fișierul ăsta la T0" e una care
    nu cere nimic pornit.

De ce NU scrie nimic:
    Trece prin `reputation_disposition.describe()`, nu prin `for_event()`, deci
    nu consemnează nicio rulare în baza de evenimente. O unealtă de diagnostic
    care lasă urme într-un experiment strică exact cifra pentru care a fost
    chemată.

Ce declară, obligatoriu (`METRICS.md` §8.1):
    Amprenta instantaneului, sursele cu versiunile lor și brațul ablației.
    Ultimul se derivă din surse: un instantaneu care conține o sursă pe axa de
    amenințare e cel semiînzestrat, fiindcă selecția corpusului a fost făcută
    chiar din inventarul acela. Fără declarația asta, „necunoscut" nu spune
    nimic — e chiar diferența dintre cele două brațe.

Exemple:

    python -m app.services.reputation_probe --exemple
    python -m app.services.reputation_probe --sha256 <64-hex> --sha256 <64-hex>
    python -m app.services.reputation_probe --exemple --instantaneu storage/reputation.db
"""

import argparse
import os
import sqlite3
import sys
from typing import List, Optional, Sequence, Tuple

from app.services import reputation_disposition, reputation_store


def exemple_din_instantaneu(cale: str) -> List[Tuple[str, str]]:
    """
    Câte un hash din fiecare celulă ocupată a 2×2-ului, plus unul absent.

    Deschide instantaneul separat, tot read-only: interogările astea sunt ale
    uneltei, nu ale serverului, iar `lookup()` nu are — și nu trebuie să aibă —
    un mod „dă-mi un rând oarecare".
    """
    uri = os.path.abspath(cale)
    connection = sqlite3.connect(f"file:{uri}?mode=ro&immutable=1", uri=True)

    interogari = [
        (
            "cunoscut ca amenintare, absent din software",
            "SELECT sha256 FROM reputation WHERE known_malicious = 1 "
            "AND known_software = 0 LIMIT 1",
        ),
        (
            "cunoscut ca software, absent din amenintari",
            "SELECT sha256 FROM reputation WHERE known_software = 1 "
            "AND known_malicious = 0 LIMIT 1",
        ),
        (
            "ambele axe (celula de suprapunere)",
            "SELECT sha256 FROM reputation WHERE known_software = 1 "
            "AND known_malicious = 1 LIMIT 1",
        ),
    ]

    alese: List[Tuple[str, str]] = []

    for eticheta, interogare in interogari:
        rand = connection.execute(interogare).fetchone()

        if rand is None:
            print(f"  (nicio potrivire pentru: {eticheta})")
            continue

        alese.append((eticheta, rand[0].hex()))

    connection.close()

    # Un hash care nu poate exista în niciun instantaneu real: ultimul octet îl
    # face improbabil, iar rostul lui e să arate că `unknown` e un răspuns, nu o
    # eroare.
    alese.append(("absent din ambele surse", "f" * 63 + "e"))

    return alese


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Ce ar raspunde serverul pentru un hash, consultand acelasi depozit "
            "ca ingestia. Nu porneste server si nu scrie nimic."
        )
    )
    parser.add_argument(
        "--sha256",
        action="append",
        default=[],
        metavar="HEX",
        help="Amprenta de verificat, 64 de caractere hexazecimale. Se poate repeta.",
    )
    parser.add_argument(
        "--exemple",
        action="store_true",
        help="Alege singur cate un hash din fiecare celula ocupata a instantaneului.",
    )
    parser.add_argument(
        "--instantaneu",
        default=None,
        metavar="CALE",
        help=(
            "Instantaneul de consultat. Implicit, cel din "
            f"{reputation_store.SNAPSHOT_PATH_ENV} sau cel implicit al serverului."
        ),
    )

    argumente = parser.parse_args(argv)

    if argumente.instantaneu:
        os.environ[reputation_store.SNAPSHOT_PATH_ENV] = argumente.instantaneu
        reputation_store.close()

    cale = reputation_store.configured_path()

    try:
        identitate = reputation_store.snapshot_identity()
    except reputation_store.ReputationStoreError as eroare:
        print(f"Instantaneul nu s-a putut deschide: {eroare}", file=sys.stderr)
        print(
            f"Serverul ar raspunde '{reputation_disposition.REPUTATION_UNAVAILABLE}' "
            f"la orice eveniment cu hash — stare declarata, nu defect.",
            file=sys.stderr,
        )
        return 2

    surse = identitate["sources"]

    print(f"Instantaneu: {cale}")
    print(f"  amprenta:  {identitate['fingerprint']}")
    print(f"  construit: {identitate['built_at']}")
    print(f"  brat:      {identitate['ablation_arm']}")

    for sursa in surse:
        print(
            f"  sursa:     {sursa['name']} ({sursa['axis']}, {sursa['version']}) "
            f"— {sursa['row_count']} randuri"
        )

    print()

    de_verificat: List[Tuple[str, str]] = [("cerut", h) for h in argumente.sha256]

    if argumente.exemple:
        de_verificat = exemple_din_instantaneu(cale) + de_verificat

    if not de_verificat:
        parser.error("da cel putin un --sha256, sau cere --exemple")

    for eticheta, hexa in de_verificat:
        try:
            cunoastere = reputation_store.lookup(bytes.fromhex(hexa))
        except (ValueError, reputation_store.ReputationStoreError) as eroare:
            print(f"{hexa}\n  EROARE: {eroare}")
            continue

        raspuns = reputation_disposition.describe(cunoastere)

        print(f"{hexa}")
        print(f"  {eticheta}")
        print(f"  disposition: {raspuns['disposition']}")
        print(f"  source:      {raspuns['source']}")

        if cunoastere.family:
            print(f"  family:      {cunoastere.family}")

        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
