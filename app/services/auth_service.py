"""
Autentificarea agenților — secretul de înrolare și depozitul de chei.
=====================================================================

Ce rezolvă modulul:
    Până acum, orice proces care putea deschide un socket către server putea
    scrie în numele oricărui agent. POST /api/events cerea doar ca agent_id-ul
    din corp să existe în store, iar lista de agenți e publică — deci și
    valorile acceptate erau publice. Registrul de agenți și detecția de
    repornire se sprijină amândouă pe presupunerea că un eveniment vine chiar
    de la mașina pe care o numește; nimic nu verifica presupunerea aia.

Modelul ales pentru Etapa 0 — cheie de API per agent:
    - fiecare agent primește propria cheie la înrolare, deci compromiterea unui
      endpoint nu dă acces în numele întregului parc, iar revocarea atinge o
      singură mașină;
    - cheia se prezintă în antetul X-Agent-Key la fiecare scriere;
    - serverul verifică separat că agent_id-ul din corp aparține cheii folosite
      (vezi app/security.py). Fără pasul ăsta, toți agenții ar fi autentificați
      și oricare ar putea scrie în numele oricui — adică exact nimic câștigat.

Premisa declarată explicit:
    Fără TLS, o cheie care călătorește la fiecare cerere e vizibilă pentru cine
    ascultă rețeaua. Mecanismul de față apără împotriva unui client care nu are
    secretul, NU împotriva unui ascultător pe traseu. TLS e un pas separat, iar
    până atunci limitarea se declară, nu se ascunde.

De ce cheile se țin hash-uite:
    Depozitul păstrează SHA-256 al cheii, niciodată cheia. O copie a lui
    agent_keys.json sau un dump de memorie nu produc o credențială utilizabilă.
    Verificarea nu are nevoie de valoarea originală: se calculează amprenta
    celei prezentate și se caută în dicționar — căutarea ÎNSĂȘI e comparația,
    deci nu există o buclă care compară secretul candidat cu fiecare cheie
    stocată și nu se scurge nimic prin durata ei.

De ce cheile se persistă pe disc, spre deosebire de agents_store:
    agents_store e volatil deliberat — un restart al serverului îl golește, iar
    agenții se re-înregistrează singuri prin directiva 'reregister'. Dacă
    cheile ar trăi în aceeași memorie, restartul le-ar șterge și pe ele:
    agentul și-a consumat deja secretul de înrolare (se șterge după prima
    folosire reușită), deci n-ar mai avea nici cheie, nici cu ce să ceară una.
    Tot parcul ar rămâne blocat afară, cu evenimentele adunându-se în spool,
    până la o reînrolare manuală pe fiecare mașină.

    Ținute separat și persistate, cheile supraviețuiesc restartului:
    heartbeat-ul se autentifică, serverul răspunde 'unregistered' + reregister,
    agentul se re-înregistrează cu cheia lui, iar coada se golește de la sine.
    Fluxul de recuperare care exista deja rămâne intact.

De ce NU stau pe înregistrarea agentului din agents_store:
    GET /api/agents e o rută publică în acest pas (gaură cunoscută, tratată
    separat — vezi AUTH.md). O cheie scrisă în dicționarul agentului ar fi
    ajuns direct în răspunsul acelei rute. Depozit separat înseamnă că gaura de
    citire rămâne o problemă de confidențialitate a inventarului, nu una de
    divulgare a credențialelor.
"""

import hashlib
import hmac
import json
import logging
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Dict, Optional


logger = logging.getLogger(__name__)


# Numele antetelor. Deliberat NU "Authorization: Bearer": schema Bearer poartă
# în practică semantică de token cu expirare și conținut verificabil prin
# semnătură. Aici e o cheie opacă, de lungă durată, căutată într-un depozit —
# un nume propriu spune adevărul despre mecanism.
AGENT_KEY_HEADER = "X-Agent-Key"
ENROLLMENT_SECRET_HEADER = "X-Enrollment-Secret"

ENROLLMENT_SECRET_ENV = "EDR_ENROLLMENT_SECRET"

_BASE_DIR = Path(__file__).resolve().parent.parent.parent

DEFAULT_ENROLLMENT_SECRET_PATH = _BASE_DIR / "enrollment_secret.txt"
DEFAULT_AGENT_KEYS_PATH = _BASE_DIR / "agent_keys.json"

# 32 de octeți aleatori, codați url-safe -> ~43 de caractere. secrets, nu
# random: generatorul implicit al lui Python e Mersenne Twister, previzibil
# complet din câteva ieșiri observate.
AGENT_KEY_BYTES = 32
ENROLLMENT_SECRET_BYTES = 32

_KEYS_FILE_VERSION = 1

_lock = Lock()
_agent_id_by_key_hash: Dict[str, str] = {}
_records_by_agent_id: Dict[str, Dict[str, Any]] = {}
_enrollment_secret: Optional[str] = None
_agent_keys_path: Optional[Path] = DEFAULT_AGENT_KEYS_PATH
_enrollment_secret_path: Optional[Path] = DEFAULT_ENROLLMENT_SECRET_PATH
_keys_loaded = False


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_secret(value: str) -> str:
    """Amprenta stocată a unui secret. Vezi antetul modulului pentru de ce."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _restrict_permissions(path: Path) -> None:
    """
    Restrânge un fișier de secrete la proprietar (0600), unde platforma permite.

    Pe Windows chmod nu face decât să comute atributul read-only, deci nu e o
    garanție — serverul rulează însă pe Linux (vezi .venv), unde e reală. Un
    eșec se loghează și nu oprește nimic: un secret cu permisiuni largi e mai
    bun decât un server care nu pornește.
    """
    try:
        os.chmod(path, 0o600)
    except OSError as error:
        logger.warning(
            "Could not restrict permissions on %s: %s. The file may be readable "
            "by other local accounts.",
            path,
            error,
        )


# ---------------------------------------------------------------------------
# Secretul de înrolare
# ---------------------------------------------------------------------------

def get_enrollment_secret() -> str:
    """
    Întoarce secretul de înrolare al serverului, în ordinea de precedență:

        1. variabila de mediu EDR_ENROLLMENT_SECRET — calea recomandată în
           producție, pentru că nu lasă secretul pe disc lângă cod;
        2. fișierul enrollment_secret.txt din rădăcina serverului;
        3. dacă nu există niciunul: se generează unul și se scrie în fișier.

    Nu există mod „fără secret". Un server care ar accepta înrolări
    neautentificate atunci când configurarea lipsește ar transforma o omisiune
    de operator într-o gaură tăcută — exact tiparul de eșec pe care restul
    proiectului îl refuză. Valoarea generată NU se loghează niciodată; se
    loghează doar calea de unde operatorul o poate citi.
    """
    global _enrollment_secret

    with _lock:
        if _enrollment_secret is not None:
            return _enrollment_secret

        from_env = os.environ.get(ENROLLMENT_SECRET_ENV, "").strip()
        if from_env:
            _enrollment_secret = from_env
            logger.info(
                "Enrollment secret loaded from environment variable %s.",
                ENROLLMENT_SECRET_ENV,
            )
            return _enrollment_secret

        path = _enrollment_secret_path

        if path is not None and path.exists():
            try:
                stored = path.read_text(encoding="utf-8").strip()
            except OSError as error:
                raise RuntimeError(
                    f"Could not read enrollment secret from {path}: {error}"
                ) from error

            if stored:
                _enrollment_secret = stored
                logger.info("Enrollment secret loaded from %s.", path)
                return _enrollment_secret

        generated = secrets.token_urlsafe(ENROLLMENT_SECRET_BYTES)
        _enrollment_secret = generated

        if path is not None:
            try:
                path.write_text(generated + "\n", encoding="utf-8")
                _restrict_permissions(path)
                logger.warning(
                    "No enrollment secret was configured; a new one was generated "
                    "and written to %s. Copy it to each endpoint that must enroll, "
                    "then keep it out of backups and version control.",
                    path,
                )
            except OSError as error:
                logger.error(
                    "Generated an enrollment secret but could not persist it to "
                    "%s: %s. It will change at the next server restart, and agents "
                    "enrolled with the current value will need re-enrollment.",
                    path,
                    error,
                )

        return _enrollment_secret


def set_enrollment_secret(secret: str) -> None:
    """Fixează secretul în memorie (operare directă / teste). Nu scrie pe disc."""
    global _enrollment_secret

    with _lock:
        _enrollment_secret = secret


def verify_enrollment_secret(presented: Optional[str]) -> bool:
    """
    Verifică secretul de înrolare prezentat de un agent.

    compare_digest, nu ==: comparația naivă de șiruri iese la primul octet
    diferit, iar diferența de durată e măsurabilă peste multe cereri. Aici
    contează, spre deosebire de cheile de agent: secretul e comparat direct cu
    o valoare cunoscută, nu căutat într-un dicționar după amprentă.
    """
    if not presented:
        return False

    return hmac.compare_digest(presented, get_enrollment_secret())


# ---------------------------------------------------------------------------
# Depozitul de chei de agent
# ---------------------------------------------------------------------------

def _load_keys_locked() -> None:
    """Încarcă depozitul de pe disc o singură dată, la prima folosire."""
    global _keys_loaded

    if _keys_loaded:
        return

    _keys_loaded = True
    path = _agent_keys_path

    if path is None or not path.exists():
        return

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        # Fail-closed pe conținut, nu pe pornire: pornim cu depozit gol, deci
        # nimeni nu e autentificat pe baza unui fișier pe care nu-l putem citi.
        # Agenții primesc 401 și își păstrează evenimentele în coadă până când
        # operatorul repară fișierul — nimic nu se pierde.
        logger.error(
            "Could not read the agent key store at %s: %s. Starting with an empty "
            "store; every agent will receive 401 until the file is repaired or the "
            "fleet is re-enrolled.",
            path,
            error,
        )
        return

    agents = raw.get("agents") if isinstance(raw, dict) else None
    if not isinstance(agents, dict):
        logger.error(
            "Agent key store at %s has an unexpected shape; ignoring it.", path
        )
        return

    for agent_id, record in agents.items():
        key_hash = (record or {}).get("key_hash")
        if not key_hash:
            continue

        _records_by_agent_id[agent_id] = {
            "key_hash": key_hash,
            "created_at": record.get("created_at"),
            "issued_count": record.get("issued_count", 1),
            "last_used_at": None,
        }
        _agent_id_by_key_hash[key_hash] = agent_id

    logger.info(
        "Agent key store loaded from %s (%d agent(s)).",
        path,
        len(_records_by_agent_id),
    )


def _save_keys_locked() -> None:
    """
    Scrie depozitul pe disc. Apelat doar la emitere/revocare, nu la fiecare
    cerere: last_used_at rămâne intenționat doar în memorie, altfel fiecare
    eveniment livrat ar produce o scriere pe disc.
    """
    path = _agent_keys_path

    if path is None:
        return

    payload = {
        "version": _KEYS_FILE_VERSION,
        "agents": {
            agent_id: {
                "key_hash": record["key_hash"],
                "created_at": record.get("created_at"),
                "issued_count": record.get("issued_count", 1),
            }
            for agent_id, record in _records_by_agent_id.items()
        },
    }

    temporary_path = path.with_name(path.name + ".tmp")

    try:
        # Scriere atomică: un server oprit la mijlocul unui write ar lăsa altfel
        # un JSON trunchiat, iar la repornire tot parcul ar fi respins.
        temporary_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        _restrict_permissions(temporary_path)
        os.replace(temporary_path, path)
    except OSError as error:
        logger.error(
            "Could not persist the agent key store to %s: %s. Keys issued in this "
            "run will be lost at restart and those agents will need re-enrollment.",
            path,
            error,
        )


def issue_agent_key(agent_id: str) -> str:
    """
    Emite (sau reemite) cheia unui agent și întoarce valoarea în clar.

    Valoarea în clar există exact o dată, în răspunsul la înregistrare. Serverul
    păstrează doar amprenta, deci o cheie pierdută pe endpoint nu poate fi
    recuperată — se emite alta, prin reînrolare.

    Reemiterea peste o cheie existentă e deliberat permisă, dar se loghează ca
    avertisment: e singura cale de recuperare după pierderea fișierului de pe
    endpoint. E și motivul pentru care secretul de înrolare se șterge de pe
    endpoint după prima folosire reușită — cât timp există acolo, e o
    capacitate permanentă de a cere o cheie nouă.
    """
    key = secrets.token_urlsafe(AGENT_KEY_BYTES)
    key_hash = _hash_secret(key)

    with _lock:
        _load_keys_locked()

        previous = _records_by_agent_id.get(agent_id)
        issued_count = 1

        if previous is not None:
            issued_count = previous.get("issued_count", 1) + 1
            _agent_id_by_key_hash.pop(previous["key_hash"], None)
            logger.warning(
                "Replacing the existing API key of agent '%s' (issue #%d). The "
                "previous key is now invalid.",
                agent_id,
                issued_count,
            )

        _records_by_agent_id[agent_id] = {
            "key_hash": key_hash,
            "created_at": _utc_now(),
            "issued_count": issued_count,
            "last_used_at": None,
        }
        _agent_id_by_key_hash[key_hash] = agent_id

        _save_keys_locked()

    logger.info("Issued an API key for agent '%s'.", agent_id)
    return key


def agent_id_for_key(presented: Optional[str]) -> Optional[str]:
    """
    Întoarce agentul căruia îi aparține cheia prezentată, sau None.

    None înseamnă „identitate nerecunoscută" -> 401. NU înseamnă „nu are voie"
    (403): distincția e a apelantului, iar în app/security.py e păstrată exact.
    """
    if not presented:
        return None

    key_hash = _hash_secret(presented)

    with _lock:
        _load_keys_locked()

        agent_id = _agent_id_by_key_hash.get(key_hash)

        if agent_id is not None:
            record = _records_by_agent_id.get(agent_id)
            if record is not None:
                record["last_used_at"] = _utc_now()

        return agent_id


def has_agent_key(agent_id: str) -> bool:
    with _lock:
        _load_keys_locked()
        return agent_id in _records_by_agent_id


def revoke_agent_key(agent_id: str) -> bool:
    """
    Invalidează cheia unui agent. Calea de rotație/revocare, operată direct pe
    server. Întoarce True dacă exista o cheie de invalidat.
    """
    with _lock:
        _load_keys_locked()

        record = _records_by_agent_id.pop(agent_id, None)
        if record is None:
            return False

        _agent_id_by_key_hash.pop(record["key_hash"], None)
        _save_keys_locked()

    logger.warning("Revoked the API key of agent '%s'.", agent_id)
    return True


def list_key_records() -> Dict[str, Dict[str, Any]]:
    """Vedere read-only pentru operare. NU conține chei, doar amprente."""
    with _lock:
        _load_keys_locked()
        return {
            agent_id: dict(record)
            for agent_id, record in _records_by_agent_id.items()
        }


def reset_for_tests(enrollment_secret: str = "test-enrollment-secret") -> None:
    """
    Golește depozitul, fixează un secret cunoscut și dezactivează persistența.

    Fără dezactivarea persistenței, suita ar scrie agent_keys.json în rădăcina
    repo-ului la fiecare rulare și ar contamina rularea următoare.
    """
    global _enrollment_secret, _agent_keys_path, _enrollment_secret_path, _keys_loaded

    with _lock:
        _agent_id_by_key_hash.clear()
        _records_by_agent_id.clear()
        _enrollment_secret = enrollment_secret
        _agent_keys_path = None
        _enrollment_secret_path = None
        _keys_loaded = True
