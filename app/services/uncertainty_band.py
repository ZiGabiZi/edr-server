"""
Banda minimă de incertitudine la T0: închis sau escaladat, și de ce (P2.6).
==========================================================================

Ce face și ce NU face:
    Pentru fiecare eveniment cu hash, decide și consemnează ce s-ar întâmpla la
    T0: se închide sau urcă pe scară. Nu escaladează nimic în realitate — pe fir
    `next_action` rămâne "none" — iar decizia stă în depozit (`event_band`), nu
    în răspuns. Contractul rămâne v12.

De ce un tabel de decizie și nu un scor (B1):
    Un scor ponderat ar avea ponderi alese după date, iar cifra publicată ar
    descrie o singură politică. Un tabel de rânduri, în care primul rând care se
    potrivește câștigă, se citește cu ochiul și se poate înlocui cu altul fără
    altă rulare: tabelul publicat numără celulele, nu doar deciziile.

De ce prevalența nu închide benign nimic:
    `CORPUS.md` §5.4 interzice ca RDS să dea „curat", deci singura dovadă care
    ar putea închide benign la T0 ar fi prevalența — „răspândit înseamnă bun".
    Respins: într-un parc de cinci, „pe trei mașini ⇒ închis" transformă coada
    de 3% a malware-ului (`CORPUS.md` §6.4) în ratări construite prin proiectare,
    iar `METRICS.md` §4.3 fixează ratările la zero. Un vierme e chiar fișierul
    care câștigă prevalență repede.

    Prevalența e aici dovada că parcul A PLĂTIT DEJA escaladarea conținutului:
    `inherit`. Verdictul benign vine doar dintr-o escaladare (T1 și mai sus),
    pe care banda minimă n-o face. Singura ieșire de la T0 care se termină fără
    semnalare e `close_known`, care vine din §5.4 („nu necesită escaladare din
    motiv de noutate") și nu depinde de prevalență.

Un fișier malițios pe toate cele cinci mașini:
    - pe axa de amenințare: `close_threat` la fiecare sosire, fiindcă rândul de
      amenințare e PRIMUL și prevalența nu-l poate depăși (B2);
    - necunoscut: `escalate` o dată, `inherit` de patru ori — o escaladare, un
      verdict, comparat pe amprentă (`METRICS.md` §4.1);
    - doar în RDS: `close_known` pe toate, la fel ca pe una singură.

De ce vechimea nu intră:
    În laborator toate vârstele sunt de minute sau ore, deci niciun rând pe
    vechime n-ar fi exercitat de măsurătoare. `first_seen` rămâne stocat (M3) și
    intră odată cu T1.
"""

from typing import Any, Dict, FrozenSet, List, Optional, Tuple

from app.services.reputation_disposition import (
    BOTH_AXES,
    KNOWN_MALICIOUS,
    KNOWN_SOFTWARE,
    REPUTATION_UNAVAILABLE,
    UNKNOWN,
)


# Politica declarată, stocată pe fiecare rând din `event_band` (B7).
POLICY = "t0-min-1"

# Varianta strictă, pre-înregistrată odată cu cea declarată (B10): tratează
# `known_software` ca `unknown`. NU se stochează — se calculează din celulele
# publicate, ca niciuna dintre cele două să nu fie aleasă după ce se văd datele.
STRICT_POLICY = "t0-min-1-strict"

CLOSE_THREAT = "close_threat"
HOLD = "hold"
ESCALATE = "escalate"
INHERIT = "inherit"
CLOSE_KNOWN = "close_known"

DECISIONS: Tuple[str, ...] = (CLOSE_THREAT, HOLD, ESCALATE, INHERIT, CLOSE_KNOWN)


# Un rând: (dispozițiile, „văzut înainte" — None înseamnă oricum, decizia).
_Row = Tuple[FrozenSet[str], Optional[bool], str]

# Ordinea rândurilor e decizia de securitate (B2): amenințarea întâi, ca
# prevalența să n-o poată depăși; indisponibilitatea înaintea lui `unknown`, ca
# o pană a depozitului să nu arate ca un corpus nou (`METRICS.md` §3.5).
_TABLES: Dict[str, Tuple[_Row, ...]] = {
    POLICY: (
        (frozenset({KNOWN_MALICIOUS, BOTH_AXES}), None, CLOSE_THREAT),
        (frozenset({REPUTATION_UNAVAILABLE}), None, HOLD),
        (frozenset({UNKNOWN}), False, ESCALATE),
        (frozenset({UNKNOWN}), True, INHERIT),
        (frozenset({KNOWN_SOFTWARE}), None, CLOSE_KNOWN),
    ),
    STRICT_POLICY: (
        (frozenset({KNOWN_MALICIOUS, BOTH_AXES}), None, CLOSE_THREAT),
        (frozenset({REPUTATION_UNAVAILABLE}), None, HOLD),
        (frozenset({UNKNOWN, KNOWN_SOFTWARE}), False, ESCALATE),
        (frozenset({UNKNOWN, KNOWN_SOFTWARE}), True, INHERIT),
    ),
}

POLICIES: Tuple[str, ...] = tuple(_TABLES)


def decide(
    disposition: Optional[str], prior_sighting: bool, policy: str = POLICY
) -> Optional[str]:
    """
    Decizia benzii pentru o celulă. Pură: nicio citire, nicio scriere.

    `None` pentru o dispoziție pe care tabelul n-o cunoaște. Nu se ghicește o
    decizie: evenimentul rămâne fără rând și se numără ca gol, sub numele
    dispoziției lui — o valoare nouă absorbită într-o celulă veche ar schimba
    cifra fără nicio urmă.
    """
    for dispositions, prior, decision in _TABLES[policy]:
        if disposition in dispositions and (prior is None or prior == prior_sighting):
            return decision

    return None


def describe_policy(policy: str) -> List[Dict[str, Any]]:
    """Tabelul de decizie, rând cu rând, cum se publică lângă cifră (B7)."""
    return [
        {
            "row": index,
            "dispositions": sorted(dispositions),
            "prior_sighting": "any" if prior is None else prior,
            "decision": decision,
        }
        for index, (dispositions, prior, decision) in enumerate(_TABLES[policy], 1)
    ]


def for_event(
    reputation: Optional[Dict[str, Any]], prior_sighting: Optional[bool]
) -> Optional[Dict[str, Any]]:
    """
    Rândul de consemnat în `event_band` pentru un eveniment, sau `None`.

    `None` când evenimentul n-are hash — fără conținut identificat nu există ce
    decide — și când dispoziția nu e în vocabular (vezi `decide`).
    """
    if reputation is None or prior_sighting is None:
        return None

    decision = decide(reputation.get("disposition"), prior_sighting)

    if decision is None:
        return None

    return {"policy": POLICY, "decision": decision, "prior_sighting": prior_sighting}
