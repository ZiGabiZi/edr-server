import logging

from pydantic import BaseModel, field_validator
from typing import Optional

from app.schemas.wire import WireModel


logger = logging.getLogger(__name__)

class HeartbeatRequest(WireModel):
    agent_id: str
    agent_version: Optional[str] = None

    # Contor monoton per proces al agentului: pornește de la 1 la fiecare lansare
    # și crește cu fiecare *încercare* de heartbeat, inclusiv cu cele eșuate.
    # Serverul îl folosește pentru încercările care nu au ajuns (failed_attempts),
    # NU pentru durata unei pene: încercările sunt distanțate de backoff exponențial,
    # iar ferestrele ratate sunt derivate server-side din last_seen.
    # NU mai deduce reporniri din resetarea lui — comitul e993733 a mutat detecția
    # pe agent_instance_id, pentru că o secvență mai mică poate fi și un pachet reordonat.
    # Opțional pentru compatibilitate cu agenți vechi care nu îl trimit încă.

    sequence: Optional[int] = None

    # Viitor: agent poate raporta starea sa locală
    # yara_ruleset_version: Optional[str] = None
    # Incarnarea procesului agentului, generată la fiecare pornire. Sursa autoritară
    # pentru detecția de repornire. Opțional doar pentru compatibilitate cu build-uri
    # vechi: în absența ei, continuitatea nu poate fi garantată (vezi record_heartbeat).

    agent_instance_id: Optional[str] = None

    # Starea supravegherii, recalculată de agent la fiecare heartbeat (v10, v11).
    # Heartbeat-ul e singurul canal care merge și când spool-ul a căzut, deci
    # e singurul care poate spune „sunt viu, dar orb". Absența înseamnă
    # necunoscut (build vechi), nu oprit. Vezi normalize_monitoring.
    monitoring: Optional[str] = None

    @field_validator("monitoring")
    @classmethod
    def _normalize_monitoring(cls, value: Optional[str]) -> Optional[str]:
        return normalize_monitoring(value)


# Vocabularul închis al câmpului monitoring. Orice valoare în afară de
# "active" înseamnă că endpoint-ul NU e supravegheat complet. "partial" (v11):
# pipeline-ul merge, dar unele directoare configurate lipseau la pornire sau
# s-au pierdut în timpul rulării.
MONITORING_ACTIVE = "active"
MONITORING_STATES = frozenset(
    {
        MONITORING_ACTIVE,
        "partial",
        "spool_unavailable",
        "monitor_unavailable",
        "stopped",
    }
)
MONITORING_UNRECOGNIZED = "unrecognized"


def normalize_monitoring(value: Optional[str]) -> Optional[str]:
    """
    Valoare din afara vocabularului -> "unrecognized", nu 422.

    Un Literal ar fi respins-o cu 422, iar la heartbeat 422 înseamnă că agentul
    nu mai trimite niciun heartbeat până la repornire (app/schemas/wire.py).
    Un agent mai nou, cu o stare pe care serverul n-o cunoaște încă, ar apărea
    atunci mort în loc de orb. "unrecognized" păstrează heartbeat-ul și rămâne
    de partea sigură: nu e "active", deci endpoint-ul nu se socotește
    supravegheat. Valoarea brută nu se stochează, doar se loghează.
    """
    if value is None or value in MONITORING_STATES:
        return value

    logger.warning(
        "HeartbeatRequest a primit monitoring=%r, în afara vocabularului %s. "
        "Stocat ca %r.",
        value[:64],
        sorted(MONITORING_STATES),
        MONITORING_UNRECOGNIZED,
    )
    return MONITORING_UNRECOGNIZED


class HeartbeatDirective(BaseModel):
    """
    Directive pe care serverul le trimite agentului la fiecare heartbeat.
    Acesta e canalul natural pentru config push și ruleset updates — 
    agentul întreabă, serverul răspunde cu ce trebuie făcut.
    """
    action: str = "none"               # "none" | "update_ruleset" | "collect_file"
    ruleset_version: Optional[str] = None
    collect_file_path: Optional[str] = None  # viitor: progressive disclosure

class HeartbeatResponse(BaseModel):
    status: str                         # "ok" | "unregistered"
    agent_id: str
    directive: HeartbeatDirective
    next_heartbeat_seconds: int         # cadența dictată de server pentru următorul heartbeat
    restart_detected: bool = False      # serverul a observat o resetare a secvenței (restart de agent)
    missed_heartbeats: int = 0          # câte heartbeat-uri au lipsit în golul de secvență curent
    failed_attempts: int = 0            # câte heartbeat-uri au eșuat în ultima cadență (ex: timeout)
    silence_seconds: float = 0.0        # cât timp a trecut de la ultimul heartbeat reușit
    continuity_lost: bool = False       # serverul nu poate garanta continuitatea (agent fara incarnare)
