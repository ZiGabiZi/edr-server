from pydantic import BaseModel
from typing import Optional

from app.schemas.wire import WireModel

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
