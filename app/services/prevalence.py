"""
Memoria parcului: pe câte mașini se știe conținutul ăsta, și de când.
=====================================================================

De ce e a doua memorie, și de ce nu seamănă cu prima:
    Depozitul de reputație (`reputation_store`) e cunoaștere ÎMPRUMUTATĂ — vine
    din NSRL RDS și dintr-un inventar de amenințări, adică din artă anterioară.
    E un artefact sigilat: o rulare vede exact unul, iar amprenta lui răspunde
    definitiv la „ce a citit serverul când a produs cifra asta".

    Registrul de aici e prima cunoaștere care e A PARCULUI. Și e prima care se
    schimbă ÎN TIMPUL rulării: al cincilea endpoint care raportează un fișier
    primește alt răspuns decât primul, iar asta e chiar ce vrem să măsurăm.

De ce NU se amprentează:
    O amprentă peste ceva ce se schimbă în timpul rulării ar fi falsă înainte ca
    rularea să se termine. Ar arăta ca garanția pe care o dă amprenta
    instantaneului, fără să o poată ține — iar un mecanism de verificare care
    minte e mai rău decât absența lui. Ce se declară e POZIȚIA DE PLECARE, o
    dată pe rulare, în `run_prevalence`.

De ce numără mașini, nu evenimente:
    O singură mașină care rescrie un fișier de 500 de ori nu e un parc. Greșeala
    n-ar produce nicio eroare, doar o cifră mai mare în direcția care flatează
    afirmația. Registrul stochează perechi `(hash, mașină)`, iar prevalența e un
    `COUNT(*)` — corectă prin construcție, nu prin grija apelantului.

De ce ce pleacă pe fir e dovadă, nu scor:
    Momentul în care aici apare un prag — „peste trei mașini nu mai escaladez" —
    e momentul în care banda de incertitudine (§L2.7) rămâne fără obiect și
    sistemul are două mecanisme de decizie care se contrazic pe tăcute. E aceeași
    linie ca la depozit: se furnizează dovadă, agregarea e a benzii.

Ce NU măsoară:
    Prevalență OBSERVATĂ, nu reală. Numără mașinile care au *raportat* fișierul,
    nu pe cele care îl au. Un endpoint oprit, unul cu coada plină, sau unul care
    n-a atins încă directorul monitorizat lipsesc din număr. Limitare declarată,
    nu rezolvabilă la stratul ăsta.
"""

import logging
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Dict, Optional, Set

from app.services import event_store


logger = logging.getLogger(__name__)


# Rulările pentru care ACEST proces a consemnat deja poziția de plecare.
#
# Cache de proces, ca la identitatea instantaneului: rândul e unul singur pe
# rulare, iar `ON CONFLICT DO NOTHING` l-ar rescrie degeaba de zeci de mii de
# ori. Prima consemnare rămâne valabilă și după repornirea procesului, fiindcă o
# etichetă de rulare nu poate fi redeschisă.
_baseline_lock = Lock()
_baselines_recorded: Set[str] = set()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _record_baseline_once(run_id: str) -> None:
    """
    Consemnează starea memoriei la începutul rulării (decizia M5).

    Se cheamă ÎNAINTE de înregistrarea vederii, nu după: altfel „starea la
    început" ar include chiar evenimentul care a declanșat-o, iar prima rulare pe
    o bază goală ar raporta o poziție de plecare de un hash și un agent în loc de
    zero. Diferența e mică în cifre și totală în înțeles.
    """
    with _baseline_lock:
        if run_id in _baselines_recorded:
            return

        stare = event_store.prevalence_state()

        event_store.record_run_prevalence(
            run_id, _utc_now(), stare["distinct_hashes"], stare["agents"]
        )

        _baselines_recorded.add(run_id)


def for_event(
    sha256_hex: Optional[str], agent_id: str, run_id: str
) -> Optional[Dict[str, Any]]:
    """
    Înregistrează vederea și întoarce prevalența conținutului, pentru un eveniment.

    `None` când evenimentul n-are hash: fără conținut identificat nu există nimic
    de numărat, iar o prevalență pusă acolo ar fi o afirmație despre un fișier pe
    care nimeni nu l-a identificat. Evenimentele de ciclu de viață cad toate aici,
    ca la `disclosure` și la `reputation`.

    Numărul întors INCLUDE mașina care tocmai a raportat (M6). „Pe câte mașini se
    știe că există conținutul ăsta" — iar mașina care tocmai l-a raportat e una
    dintre ele. Primul endpoint primește `1`, niciodată `0`; un zero n-ar putea fi
    deosebit de „n-a fost numărat".

    `park_agents` călătorește lângă `agents` fiindcă un numărător fără numitor nu
    se poate citi: trei mașini înseamnă altceva într-un parc de cinci decât în
    unul de cinci sute.
    """
    if sha256_hex is None:
        return None

    # Poziția de plecare, înaintea oricărei scrieri a rulării.
    _record_baseline_once(run_id)

    # Decodarea, ca la reputație: forma hash-ului e garantată de validatorul din
    # `EventCreateRequest` (v7), deci o excepție aici ar însemna că un eveniment a
    # ajuns în serviciu fără să treacă prin schemă — presupunere ruptă, care
    # trebuie să se audă, nu să fie îmbrăcată într-o valoare plauzibilă.
    hash_brut = bytes.fromhex(sha256_hex)

    vazut = event_store.record_and_count_sighting(hash_brut, agent_id, _utc_now())

    return {
        "agents": vazut["agents"],
        "park_agents": event_store.park_agents(),
        "first_seen": vazut["first_seen"],
    }


def reset_for_tests() -> None:
    """Uită ce rulări au poziția de plecare consemnată, ca testul următor să fie curat."""
    with _baseline_lock:
        _baselines_recorded.clear()
