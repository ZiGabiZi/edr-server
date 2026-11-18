"""
Banda minimă la T0, publicată ca tabel — nu ca rată (`METRICS.md` §3.7).
=========================================================================

De ce celulele și nu doar deciziile:
    O rată de închidere descrie o singură politică. Tabelul dispoziție ×
    (văzut înainte, prevalența la sosire) descrie RULAREA: orice politică de
    forma „decizie = f(dispoziție, văzut înainte)" se citește din el fără altă
    rulare, iar `agents` brut păstrează și politicile pe prevalență, nedeclarate
    azi. Cele două politici pre-înregistrate (B10) se calculează amândouă aici,
    din aceleași celule.

De ce deciziile stocate se compară cu cele recalculate:
    Decizia declarată e scrisă la ingestie, în `event_band`. Recalculată din
    celule cu același tabel, trebuie să iasă identic. Dacă nu iese, tabelul din
    cod s-a schimbat sub o rulare deja făcută, iar cifra publicată ar descrie
    altă politică decât cea care a decis — `stored_matches_table` o spune.

Golurile, ca la §2.1:
    `hashed_events_without_band` — evenimente cu hash fără rând de bandă: scrise
    înainte de P2.6 sau cu o dispoziție pe care tabelul n-o cunoaște (numărate
    sub numele ei). `inherited_without_escalation` — `inherit` al cărui conținut
    n-are niciun `escalate` în toată baza: prima vedere a fost `hold`, a fost
    scrisă înainte de bandă, registrul e murdar, sau prima sosire a eșuat după
    ce își înregistrase vederea. Ultimul caz vine din ordinea din
    `event_service.create_event`: `prevalence.observe` face commit înainte de
    `insert_event`, deci retransmisia unei inserări picate își vede propria
    vedere și primește `inherit`. Moștenire fără de la cine.

Ce NU se poate citi de aici:
    Criteriile de infirmare 1 (fișiere ajunse la T2) și 5 (abținerea) au aici
    doar o margine superioară: ce escaladează la T0 e plafonul pentru ce ajunge
    la T2 și pentru ce se poate abține mai sus pe scară.
"""

from typing import Any, Dict, Iterable, Mapping, Optional, Set, Tuple

from app.services import uncertainty_band
from app.services.reputation_disposition import VALID_DISPOSITIONS


# Cheia evenimentelor cu hash care n-au deloc dispoziție — scrise înainte ca
# serverul să consulte depozitul (P2.3). Fără ea, `str(None)` ar da cheia
# "None", care se citește ca o valoare de vocabular. Numele repetă golul de la
# §3.5, `hashed_events_without_disposition`: același fapt, același nume.
NO_DISPOSITION = "without_disposition"

assert NO_DISPOSITION not in VALID_DISPOSITIONS


def compute_band_metrics(
    events: Iterable[Dict[str, Any]],
    band_rows: Mapping[int, Dict[str, Any]],
    escalated: Set[str],
) -> Dict[str, Any]:
    """
    Tabelul benzii peste evenimentele date. Pură: depozitul dă rândurile.

    `band_rows` e `event_id → {policy, decision, prior_sighting}`, iar
    `escalated` conținuturile (hex) cu cel puțin un `escalate` în toată baza.
    """
    events_with_hash = 0
    without_band: Dict[str, int] = {}
    cells: Dict[Tuple[str, bool, Optional[int]], int] = {}
    stored: Dict[str, Dict[str, int]] = {}
    inherited_without_escalation = 0

    for event in events:
        digest = event.get("sha256")

        if not digest:
            continue

        events_with_hash += 1
        raw = (event.get("reputation") or {}).get("disposition")
        disposition = NO_DISPOSITION if raw is None else str(raw)
        event_id = event.get("event_id")
        row = band_rows.get(event_id) if event_id is not None else None

        if row is None:
            without_band[disposition] = without_band.get(disposition, 0) + 1
            continue

        agents = (event.get("prevalence") or {}).get("agents")
        key = (disposition, bool(row["prior_sighting"]), agents)
        cells[key] = cells.get(key, 0) + 1

        by_decision = stored.setdefault(row["policy"], {})
        by_decision[row["decision"]] = by_decision.get(row["decision"], 0) + 1

        if (
            row["decision"] == uncertainty_band.INHERIT
            and digest.lower() not in escalated
        ):
            inherited_without_escalation += 1

    computed = {
        policy: _decisions_from_cells(cells, policy)
        for policy in uncertainty_band.POLICIES
    }

    declared = uncertainty_band.POLICY
    stored_declared = {
        decision: count
        for decision, count in stored.get(declared, {}).items()
        if count
    }

    return {
        "events_with_hash": events_with_hash,
        "events_with_band": sum(cells.values()),
        "declared_policy": declared,
        "policies": {
            policy: uncertainty_band.describe_policy(policy)
            for policy in uncertainty_band.POLICIES
        },
        "cells": [
            {
                "disposition": disposition,
                "prior_sighting": prior,
                "agents_at_arrival": agents,
                "events": count,
            }
            for (disposition, prior, agents), count in sorted(
                cells.items(), key=lambda item: (item[0][0], item[0][1], item[0][2] or 0)
            )
        ],
        "decisions": computed,
        "stored_decisions": stored,
        "stored_matches_table": stored_declared == {
            d: c for d, c in computed[declared].items() if c
        },
        "hashed_events_without_band": sum(without_band.values()),
        "without_band_by_disposition": dict(sorted(without_band.items())),
        "inherited_without_escalation": inherited_without_escalation,
        "note": (
            "Banda minima la T0 (P2.6): nicio escaladare reala, next_action ramane "
            "none, iar decizia sta in depozit, nu pe fir. Se publica TABELUL, nu o "
            "rata: cells numara evenimentele pe dispozitie x prior_sighting x "
            "agents_at_arrival, numitorul e events_with_hash, ca la reputation, deci "
            "orice politica de forma f(dispozitie, vazut inainte) se citeste fara "
            "alta rulare. decisions da ambele politici pre-inregistrate, calculate "
            "din celule; stored_decisions da ce s-a scris la ingestie. Nicio "
            "decizie nu spune ca fisierul e bun: close_known spune doar ca nu "
            "escaladeaza din motiv de noutate (CORPUS.md 5.4), iar inherit ca "
            "parcul a platit deja escaladarea continutului. Pentru criteriile 1 si "
            "5, escalate e doar o margine superioara. O rulare cu hold > 0 nu e "
            "comparabila cu una fara."
        ),
    }


def _decisions_from_cells(
    cells: Mapping[Tuple[str, bool, Optional[int]], int], policy: str
) -> Dict[str, int]:
    """Deciziile unei politici, numărate din celule. Toate cele cinci, și zero."""
    counts: Dict[str, int] = {decision: 0 for decision in uncertainty_band.DECISIONS}
    undecided = 0

    for (disposition, prior, _), count in cells.items():
        decision = uncertainty_band.decide(disposition, prior, policy)

        if decision is None:
            undecided += count
        else:
            counts[decision] += count

    if undecided:
        counts["undecided"] = undecided

    return counts
