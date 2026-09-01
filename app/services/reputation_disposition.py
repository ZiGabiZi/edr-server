"""
Dispoziția de treaptă: ce se știe despre un fișier la T0, spus pe fir.
=====================================================================

Ce e și, mai ales, ce NU e:
    Un VERDICT e imuabil, legat de conținut, și poartă treapta de dovadă la care
    a fost obținut — cheia `(sha256, versiune_ruleset, treaptă_de_dovadă)` din
    Etapa 3. O DISPOZIȚIE de treaptă spune doar ce știe depozitul la adâncimea
    T0, adică înainte ca protocolul să fi divulgat orice în plus față de o
    amprentă. Confundate, un verdict ieftin ar fi spălat ca verdict scump — exact
    greșeala refuzată în depozit la decizia R1, mutată cu un nivel mai sus, pe
    protocol.

    De aceea câmpul se numește `disposition`, iar `verdict` e trecut ca INTERZIS
    în contractul de fir. Numele nu e liber pentru altceva.

De ce cinci valori și de ce nu e enumul respins la R1:
    Cele patru celule ale 2×2-ului plus indisponibilitatea. E o BIJECȚIE cu ce
    stochează depozitul, nu o proiecție: `both_axes` nu se prăbușește în
    `known_malicious`, deși acțiunea de mai târziu va fi probabil aceeași.
    Maparea „ambele axe se tratează ca amenințare" aparține benzii de
    incertitudine (§L2.7), care primește dispoziția întreagă și decide — nu
    vocabularului, care doar transportă.

    Enumul refuzat la R1 pierdea o celulă. Ăsta nu pierde niciuna, deci nu
    reintroduce aceeași greșeală pe altă ușă.

De ce niciun termen de benignitate:
    `CORPUS.md` §5.4 — RDS e o listă de software CUNOSCUT, nu de software BUN.
    Un hash prezent acolo primește `known_software`, care spune exact atât.
    `clean`, `benign` și `safe` sunt interzise în contract, ca nume de câmp, iar
    absența lor din valori se verifică pe formă în teste.

De ce `reputation_unavailable` e o stare separată de `unknown`:
    `unknown` înseamnă „depozitul a fost întrebat și nu știe" — un răspuns cu
    conținut, chiar cel care numește candidatul la T1 și justifică lucrarea.
    `reputation_unavailable` înseamnă „depozitul n-a putut fi întrebat".

    Contopite, o pană a instantaneului arată IDENTIC cu un corpus genuin nou —
    adică exact variabila de care depinde afirmația centrală. Un fișier lipsă ar
    imita perfect brațul rece al ablației, fără nicio eroare vizibilă nicăieri.

De ce evenimentul se acceptă oricum:
    Alternativa ar fi 5xx, adică disponibilitatea telemetriei cuplată de
    disponibilitatea reputației. Coada agentului e at-least-once (§1.3), deci ar
    reîncerca la nesfârșit un eveniment perfect valid, iar o pană de reputație
    s-ar transforma într-o pană de colectare. Evenimentul intră; dispoziția spune
    cinstit că depozitul n-a răspuns.
"""

import json
import logging
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Dict, Optional, Set

from app.services import event_store, reputation_store
from app.services.reputation_store import Knowledge, ReputationStoreError


logger = logging.getLogger(__name__)


# Vocabularul dispoziției. În engleză, ca tot ce circulă pe fir — `ok`,
# `unstable`, `too_large`, `skipped_capacity`, `software`, `threat`. Româna e
# limba jurnalului și a comentariilor; o valoare românească lângă
# `hash_status: "ok"` ar fi o graniță de limbă imposibil de mutat după ce agentul
# o consumă.
KNOWN_MALICIOUS = "known_malicious"
KNOWN_SOFTWARE = "known_software"

# Numele îl repetă pe cel al proprietății de pe `Knowledge`, deliberat: același
# fapt nu are voie să aibă două nume în două straturi. Aceeași disciplină ca la
# `skipped_capacity` față de `forced_reason` în agent.
BOTH_AXES = "both_axes"

UNKNOWN = "unknown"
REPUTATION_UNAVAILABLE = "reputation_unavailable"

VALID_DISPOSITIONS = frozenset(
    {KNOWN_MALICIOUS, KNOWN_SOFTWARE, BOTH_AXES, UNKNOWN, REPUTATION_UNAVAILABLE}
)


# Rulările pentru care instantaneul a fost deja consemnat de ACEST proces.
#
# Există ca să nu se scrie în baza de evenimente la fiecare eveniment: rândul e
# unul singur pe rulare, iar `INSERT ... ON CONFLICT DO NOTHING` l-ar rescrie
# degeaba de zeci de mii de ori. Prima consemnare rămâne cea validă și după
# repornirea procesului, fiindcă o etichetă de rulare nu poate fi redeschisă.
_recorded_lock = Lock()
_recorded_runs: Set[str] = set()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _disposition_of(knowledge: Knowledge) -> str:
    """Cele patru celule, în ordinea în care nu se pot ascunde una pe alta."""
    if knowledge.both_axes:
        return BOTH_AXES

    if knowledge.known_malicious:
        return KNOWN_MALICIOUS

    if knowledge.known_software:
        return KNOWN_SOFTWARE

    return UNKNOWN


def _record_snapshot_once(run_id: str) -> None:
    """
    Leagă rularea de instantaneul care i-a răspuns (`METRICS.md` §8).

    Se face la PRIMA consultare a rulării, nu la deschiderea ei: o rulare care
    n-a întrebat niciodată depozitul n-a folosit niciun instantaneu, iar un rând
    scris la deschidere ar pretinde altceva.
    """
    with _recorded_lock:
        if run_id in _recorded_runs:
            return

        identitate = reputation_store.snapshot_identity()

        event_store.record_run_snapshot(
            run_id,
            _utc_now(),
            identitate["fingerprint"],
            json.dumps(identitate, ensure_ascii=False),
        )

        _recorded_runs.add(run_id)


def for_event(sha256_hex: Optional[str], run_id: str) -> Optional[Dict[str, Any]]:
    """
    Consultă depozitul pentru hash-ul unui eveniment și întoarce dispoziția lui.

    `None` când evenimentul n-are hash: fără `sha256` nu există nimic de căutat,
    iar o dispoziție pusă acolo ar fi o afirmație despre un fișier pe care nimeni
    nu l-a identificat. Evenimentele de ciclu de viață (`agent_startup`,
    `agent_shutdown`, `agent_restart`) cad toate aici — la fel ca la blocul
    `disclosure`, care nu însoțește decât evenimentele de fișier.

    Proveniența călătorește DOAR pe axa de amenințare. `software_source` rămâne
    pe server: apartenența la RDS nu poate justifica nicio acțiune (§5.4), deci
    ar fi octeți plătiți ca să se spună „cunoscut, dar asta nu înseamnă nimic".
    """
    if sha256_hex is None:
        return None

    # Decodarea, o singură dată, la graniță. NU e într-un `try`: forma
    # hash-ului e garantată de validatorul din `EventCreateRequest` (v7), deci o
    # excepție aici ar însemna că un eveniment a ajuns până în serviciu fără să
    # treacă prin schemă. Aia e o presupunere ruptă, nu o reputație
    # indisponibilă, și trebuie să se audă ca atare — nu să fie îmbrăcată în
    # `reputation_unavailable`, unde ar contamina exact cifra pe care starea aia
    # există s-o protejeze.
    hash_brut = bytes.fromhex(sha256_hex)

    try:
        cunoastere = reputation_store.lookup(hash_brut)
    except ReputationStoreError as error:
        # O singură linie per eveniment ar inunda logul într-o pană lungă, dar
        # tăcerea ar ascunde exact cazul în care fiecare cifră a rulării se
        # schimbă. Rămâne WARNING, cu motivul, iar dispoziția persistată face
        # pana numărabilă după aceea.
        logger.warning(
            "Reputation lookup failed for an event of run %s; the event is "
            "accepted and marked %s: %s",
            run_id,
            REPUTATION_UNAVAILABLE,
            error,
        )
        return {"disposition": REPUTATION_UNAVAILABLE, "source": None}

    _record_snapshot_once(run_id)

    dispozitie = _disposition_of(cunoastere)

    return {
        "disposition": dispozitie,
        "source": cunoastere.threat_source if cunoastere.known_malicious else None,
    }


def reset_for_tests() -> None:
    """Uită ce rulări au fost consemnate, ca testul următor să pornească curat."""
    with _recorded_lock:
        _recorded_runs.clear()
