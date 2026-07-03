from pydantic import BaseModel
from typing import Optional, List

class HeartbeatRequest(BaseModel):
    agent_id: str
    agent_version: Optional[str] = None
    # Contor monoton per proces al agentului: pornește de la 1 la fiecare lansare
    # și crește cu fiecare heartbeat. Permite serverului să detecteze heartbeat-uri
    # pierdute (goluri în secvență) și reporniri de agent (resetarea contorului).
    # Opțional pentru compatibilitate cu agenți vechi care nu îl trimit încă.
    sequence: Optional[int] = None
    # Viitor: agent poate raporta starea sa locală
    # yara_ruleset_version: Optional[str] = None

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
