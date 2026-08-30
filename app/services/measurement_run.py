"""
Rularea de măsurătoare — eticheta care spune din ce experiment vine o cifră.
============================================================================

Problema pe care o rezolvă modulul, și de ce apare abia acum:
    Până azi `events_store` trăiește în memoria procesului și moare la fiecare
    repornire. Efectul secundar era o igienă gratuită: porneai serverul, făceai
    experimentul, citeai cifra — iar cifra descria exact experimentul acela,
    pentru că nu mai era nimic altceva înăuntru. Corpusul declarat de
    contracts/METRICS.md §8 era implicit corect.

    Persistența (1.4.2) desființează accidentul. Evenimentele rămân pe disc, se
    adună peste zile și peste experimente diferite, iar
    `GET /api/metrics/disclosure` ar amesteca o probă cu 444 de fișiere, o
    rulare de depanare cu trei și un test de parc cu douăzeci de agenți într-o
    singură medie care nu descrie niciunul dintre ele.

    Deci pasul spre disc nu e „adaugă SQLite": e persistență PLUS noțiunea de
    rulare. Fără a doua, primul face rău net — schimbă o cifră care descrie
    ceva într-o cifră care nu descrie nimic, păstrându-i aparența.

Ce e o rulare:
    O etichetă lipită pe fiecare eveniment la ingestie, care spune din ce
    experiment face parte. Serverul are exact o rulare curentă; evenimentele
    primite până la următoarea schimbare o poartă pe ea.

Cele două surse ale etichetei, și de ce amândouă:
    - GENERATĂ, la prima nevoie de o etichetă (deci practic la pornire). E plasa
      de siguranță: niciun eveniment nu rămâne neetichetat, chiar dacă
      operatorul uită complet de mecanism, iar comportamentul de azi — o
      repornire = un experiment nou — se păstrează fără nicio muncă în plus.

    - DATĂ DE OPERATOR, prin `POST /api/runs/{label}`. E instrumentul. Eticheta
      poate fi chiar numele intrării de tip `masuratoare` din edr-journal, iar
      atunci legătura dintre ce am promis că măsor și ce date am obținut devine
      VERIFICABILĂ, nu declarată: oricine ia numele din jurnal, îl dă serverului
      și primește exact cifrele acelui experiment. Fără ea, legătura e pe
      încredere.

    Generata singură ar fi însemnat că două experimente făcute fără repornire
    se amestecă, iar unul întrerupt de o repornire accidentală se rupe în două.
    Operatorul singur ar fi însemnat că o etichetă uitată lasă evenimente peste
    numele vechi. Împreună: implicit sigur, explicit când contează.

De ce o etichetă folosită o dată nu se mai poate refolosi:
    E singurul mod în care mecanismul poate să mintă. Cine reia o etichetă deja
    publicată amestecă date noi în cifre pe care le-a citat deja cineva, iar
    amestecul e invizibil în răspuns: eticheta e aceeași, numerele nu. E exact
    problema pentru care jurnalul are regula că un commit de montaj nu se
    modifică prin amend sau push --force. Aici echivalentul e un refuz, cu 409.

    LIMITARE DECLARATĂ, până la 1.4.2: registrul etichetelor folosite trăiește
    în memoria procesului, ca evenimentele. Refuzul e deci real doar în
    interiorul unei rulări a serverului. Nu e un gol: cât timp evenimentele mor
    la repornire, refolosirea unei etichete după restart nu poate amesteca
    nimic, fiindcă nu mai există nimic de amestecat. Odată ce evenimentele
    ajung pe disc, registrul trebuie să ajungă în ACEEAȘI bază cu ele — altfel
    s-ar goli exact la restartul care face refolosirea probabilă și periculoasă.

De ce prefixul generatelor e rezervat:
    Un `auto-` la începutul unei etichete de operator ar face imposibil de spus,
    peste șase luni, dacă rularea a fost numită de cineva sau inventată de
    server. Întrebarea aceea are un singur răspuns corect și e ieftin să rămână
    verificabil: prefixul aparține serverului, iar operatorul primește 400 dacă
    îl cere.
"""

import logging
import re
import secrets
from datetime import datetime, timezone
from threading import Lock
from typing import Dict, List, Optional


logger = logging.getLogger(__name__)


# Sursele posibile ale etichetei curente. Se raportează în răspuns, nu se
# deduce din formă: cine citește o cifră trebuie să poată spune dacă rularea a
# fost numită de un om sau inventată de server, fără să ghicească după prefix.
SOURCE_GENERATED = "generated"
SOURCE_OPERATOR = "operator"

# Prefixul rezervat etichetelor pe care le inventează serverul.
GENERATED_LABEL_PREFIX = "auto-"

# Cuvinte pe care ruta le folosește ca segment propriu de cale. Ca etichete ar
# fi ambigue la citire, chiar dacă metodele HTTP le despart fără conflict.
RESERVED_LABELS = frozenset({"current"})

RUN_LABEL_MAX_LENGTH = 64

# Deliberat îngust: litere, cifre, punct, minus, underscore, cu început
# alfanumeric. Eticheta călătorește într-un segment de cale, ajunge în jurnal,
# în numele fișierelor de export și în textul lucrării — orice caracter care ar
# cere codare undeva pe drumul ăsta e un caracter care va fi scris greșit
# într-un singur loc și va rupe tăcut legătura dintre jurnal și date.
_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class RunLabelError(ValueError):
    """
    Eticheta cerută nu poate fi folosită.

    `reason` există ca ruta să traducă în cod HTTP fără să citească textul
    mesajului: o formă greșită e vina cererii (400), o etichetă deja folosită e
    un conflict cu starea serverului (409). Distincția contează pentru
    operator — prima se repară rescriind, a doua nu se repară deloc.
    """

    REASON_MALFORMED = "malformed"
    REASON_RESERVED = "reserved"
    REASON_ALREADY_USED = "already_used"

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


_lock = Lock()
_runs: Dict[str, Dict[str, str]] = {}
_current_label: Optional[str] = None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def generate_label() -> str:
    """
    Inventează o etichetă pentru o rulare pe care nimeni n-a numit-o.

    Formatul e `auto-<marcaj temporal>-<sufix aleator>`. Marcajul dă ordonare și
    se poate citi cu ochiul — cine se uită peste o listă de rulări vede imediat
    care e din ce zi. Sufixul aleator există pentru registrul PERSISTENT de la
    1.4.2: în memorie două porniri nu se pot ciocni, fiindcă a doua nu-și
    amintește prima, dar pe disc două porniri din aceeași secundă s-ar ciocni,
    iar coliziunea ar fi refuzată ca refolosire — adică un server care nu mai
    pornește, din cauza unei metrici.
    """
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    return f"{GENERATED_LABEL_PREFIX}{stamp}-{secrets.token_hex(3)}"


def validate_operator_label(label: str) -> str:
    """Verifică o etichetă venită din afară. Întoarce eticheta, sau ridică RunLabelError."""
    if not label or len(label) > RUN_LABEL_MAX_LENGTH:
        raise RunLabelError(
            RunLabelError.REASON_MALFORMED,
            f"A run label must have between 1 and {RUN_LABEL_MAX_LENGTH} characters",
        )

    if not _LABEL_PATTERN.match(label):
        raise RunLabelError(
            RunLabelError.REASON_MALFORMED,
            "A run label may contain only letters, digits, dot, dash and "
            "underscore, and must start with a letter or a digit",
        )

    if label.startswith(GENERATED_LABEL_PREFIX):
        raise RunLabelError(
            RunLabelError.REASON_RESERVED,
            f"The prefix {GENERATED_LABEL_PREFIX} belongs to labels generated by "
            f"the server; an operator label must stay distinguishable from them",
        )

    if label in RESERVED_LABELS:
        raise RunLabelError(
            RunLabelError.REASON_RESERVED,
            f"The word {label} is reserved by the runs API and cannot name a run",
        )

    return label


def _open_locked(label: str, source: str) -> Dict[str, str]:
    """Înscrie eticheta în registru și o face curentă. Cere _lock deținut."""
    global _current_label

    record = {
        "run_id": label,
        "source": source,
        "opened_at": _utc_now(),
    }
    _runs[label] = record
    _current_label = label

    return record


def _ensure_current_locked() -> Dict[str, str]:
    """
    Garantează că există o rulare curentă. Cere _lock deținut.

    Deschiderea e leneșă, nu la importul modulului: un efect secundar la import
    ar face ca ordinea importurilor să decidă marcajul temporal al etichetei și
    ar deschide o rulare chiar și în procese care nu primesc niciun eveniment —
    de pildă la un import făcut de un instrument de documentare.
    """
    if _current_label is None:
        record = _open_locked(generate_label(), SOURCE_GENERATED)
        logger.info(
            "No measurement run was named; events will be labelled %s.",
            record["run_id"],
        )
        return record

    return _runs[_current_label]


def current_run() -> Dict[str, str]:
    """Descrierea rulării curente: eticheta, sursa ei și când a fost deschisă."""
    with _lock:
        return dict(_ensure_current_locked())


def current_run_id() -> str:
    """Eticheta rulării curente. E ce se lipește pe fiecare eveniment la ingestie."""
    with _lock:
        return _ensure_current_locked()["run_id"]


def start_run(label: str) -> Dict[str, str]:
    """
    Deschide o rulare numită de operator și o face curentă.

    Refuză o etichetă deja folosită, inclusiv pe cea curentă: o rulare care se
    redeschide ar însemna date noi turnate peste cifre deja citate, fără nicio
    urmă în răspuns că s-a întâmplat.
    """
    validate_operator_label(label)

    with _lock:
        # Rularea generată se înscrie în registru ÎNAINTE de a fi înlocuită.
        # Altfel, o pornire de server urmată imediat de o etichetă de operator
        # ar lăsa un interval fără nicio rulare consemnată, iar evenimentele
        # sosite în el ar purta o etichetă care nu apare nicăieri în listă.
        _ensure_current_locked()

        if label in _runs:
            raise RunLabelError(
                RunLabelError.REASON_ALREADY_USED,
                f"Run {label} has already been used and cannot be reopened",
            )

        record = _open_locked(label, SOURCE_OPERATOR)

    logger.info("Measurement run %s opened by the operator.", label)

    return dict(record)


def known_runs() -> List[Dict[str, str]]:
    """Rulările consemnate de procesul curent, în ordinea deschiderii."""
    with _lock:
        _ensure_current_locked()
        return [dict(record) for record in _runs.values()]


def reset_for_tests() -> None:
    """
    Golește registrul și uită rularea curentă.

    Fără el, prima etichetă folosită de un test ar rămâne consemnată pentru
    restul suitei, iar al doilea test care o cere ar primi 409 — adică teste
    care trec sau cad după ordinea în care rulează.
    """
    global _current_label

    with _lock:
        _runs.clear()
        _current_label = None
