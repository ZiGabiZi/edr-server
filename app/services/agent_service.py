from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from threading import Lock

from app.schemas.agent import AgentRegisterRequest

agents_store: Dict[str, Dict[str, Any]] = {}
agents_lock = Lock()

STALE_AFTER_S = 30
OFFLINE_AFTER_S = 90

HEARTBEAT_INTERVAL_SECONDS = 10

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _parse_timestamp(raw: Any) -> Optional[datetime]:
    """
    Convertește un timestamp ISO din store într-un datetime aware.

    Store-ul păstrează timpul ca șir ISO (vezi _utc_now), deci orice calcul de
    vârstă trece prin parsare. Valorile scrise de build-uri mai vechi pot fi
    naive; le interpretăm ca UTC, pentru că _utc_now a produs mereu UTC.
    """
    if not raw:
        return None

    try:
        parsed = datetime.fromisoformat(raw)
    except (ValueError, TypeError):
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed


def _missed_windows(silence_seconds: float) -> int:
    """
    Traduce tăcerea măsurată în număr de ferestre de heartbeat ratate.

    De ce nu se poate deriva din secvență:
        Contorul agentului crește o dată per *încercare*, iar încercările sunt
        distanțate de backoff exponențial (edr-agent/services/backoff.py: bază =
        interval, dublare, plafon 300s). În timpul unei pene lungi agentul rărește
        deliberat încercările, deci golul de secvență descrie retry-urile, nu
        durata. La 10s interval, o pană de 10 minute produce ~7 încercări față de
        ~86 ferestre reale — iar raportul crește cu durata, după plafonare.

    Intervalul așteptat e cunoscut aici fără să fie cerut agentului: serverul îl
    dictează el însuși (HEARTBEAT_INTERVAL_SECONDS, trimis ca next_heartbeat_seconds).
    Se scade fereastra curentă — heartbeat-ul care tocmai a sosit — ca o cadență
    normală să dea zero.
    """
    if HEARTBEAT_INTERVAL_SECONDS <= 0:
        return 0

    return max(0, round(silence_seconds / HEARTBEAT_INTERVAL_SECONDS) - 1)


def _model_to_dict(model: AgentRegisterRequest) -> Dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


@dataclass
class HeartbeatResult:
    """
    Rezultatul procesării unui heartbeat.

    Pe lângă snapshot-ul agentului (sau None dacă agentul nu e înregistrat),
    poartă verdictul de continuitate al heartbeat-ului:
        - restart_detected: incarnarea agentului (agent_instance_id) s-a schimbat
          => procesul a repornit. Verdict autoritar: serverul are dovada.
        - missed_heartbeats: câte *ferestre* de heartbeat au fost ratate, derivate
          din tăcerea măsurată pe ceasul serverului. Aceasta este mărimea care
          răspunde la întrebarea operatorului: cât timp a fost endpoint-ul
          neacoperit.
        - failed_attempts: câte *încercări* de heartbeat nu au ajuns, derivate din
          golul de secvență. NU este durata penei — agentul distanțează
          încercările prin backoff exponențial, deci cele două diverg cu un ordin
          de mărime la orice pană mai lungă decât câteva intervale.
        - silence_seconds: tăcerea efectivă dintre acest heartbeat și precedentul.
        - continuity_lost: contorul de secvență a regresat, dar agentul nu raportează
          incarnarea, deci cauza nu poate fi stabilită. NU este un verdict de
          repornire — este declarația explicită că serverul nu poate garanta
          continuitatea pentru acest agent. Cele două se exclud reciproc prin
          construcție: unde există incarnare există verdict, unde nu, nu.
    """
    agent: Optional[Dict[str, Any]]
    restart_detected: bool = False
    missed_heartbeats: int = 0
    failed_attempts: int = 0
    silence_seconds: float = 0.0
    sequence: Optional[int] = None
    instance_id: Optional[str] = None
    continuity_lost: bool = False


class AgentIdConflictError(Exception):
    """Același agent_id revendicat de o mașină cu machine_id diferit."""
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        super().__init__(f"agent_id '{agent_id}' is already registered to a different machine")

def record_heartbeat(
    agent_id: str,
    sequence: Optional[int] = None,
    instance_id: Optional[str] = None,
) -> HeartbeatResult:
    """
    Actualizează last_seen pentru agentul dat în mod atomic și evaluează continuitatea
    heartbeat-ului pe trei axe independente: incarnarea procesului (repornire),
    tăcerea măsurată (ferestre ratate) și contorul de secvență (încercări eșuate).

    Repornirea e detectată autoritar prin agent_instance_id (identificator generat la
    pornirea procesului agentului), nu prin regresia secvenței:
        - instance_id None          -> agent legacy, fără detecție de repornire.
        - prima incarnare observată -> stabilim baseline, fără verdict.
        - instance_id != last       -> proces nou => RESTART, indiferent de secvență.
          Baseline-ul de secvență se resetează la secvența noii incarnări.

    De ce durata se măsoară separat de secvență:
        Contorul agentului crește o dată per încercare, iar încercările sunt rărite
        de backoff exponențial exact cât timp serverul e jos. Golul de secvență
        răspunde deci la „câte încercări nu au ajuns", nu la „cât timp a lipsit
        agentul". Serverul are a doua mărime din surse proprii — last_seen și
        cadența pe care o dictează el însuși — deci nu are nevoie de niciun câmp nou
        pe fir și nici de încredere în ceasul endpoint-ului. Vezi _missed_windows.

    Regulă de domeniu pentru contorul de secvență:
        last_sequence este comparabil DOAR în interiorul unei incarnări cunoscute și
        neschimbate. Orice tranziție a incarnării — inclusiv None -> X, când un agent
        actualizat începe să se identifice — invalidează valoarea memorată, pentru că
        ea aparține unei rulări diferite.

    Semantica secvenței (contor monoton per proces al agentului):
        - sequence None             -> fără detecție de încercări pierdute.
        - prima secvență observată  -> stabilim baseline (n-avem cu ce compara).
        - sequence == last_sequence -> retransmisie exactă => ignorat, idempotent.
        - sequence  < last_sequence, cu incarnare cunoscută
                                    -> în aceeași rulare contorul nu poate scădea,
                                       deci e pachet întârziat/reordonat => ignorat.
        - sequence  < last_sequence, fără incarnare
                                    -> cauza nu poate fi stabilită; re-stabilim
                                       baseline-ul și raportăm continuity_lost.
        - sequence  > last+1        -> gol => (sequence - last - 1) încercări eșuate.
        - sequence == last+1        -> continuitate normală a încercărilor.

    Contoarele cumulative restart_count / missed_heartbeats_total /
    failed_attempts_total / continuity_losses_total sunt persistate pe înregistrarea
    agentului pentru observabilitate.
    """
    with agents_lock:
        agent = agents_store.get(agent_id)
        if agent is None:
            return HeartbeatResult(agent=None)

        # Tăcerea se măsoară ÎNAINTE de suprascrierea lui last_seen: valoarea veche
        # e singura urmă a momentului în care agentul a fost auzit ultima oară.
        previous_last_seen = _parse_timestamp(agent.get("last_seen"))
        now = datetime.now(timezone.utc)
        agent["last_seen"] = now.isoformat()

        silence_seconds = (
            0.0
            if previous_last_seen is None
            else max(0.0, (now - previous_last_seen).total_seconds())
        )
        missed_windows = _missed_windows(silence_seconds)

        # Acumulat aici, o singură dată per heartbeat primit, înaintea oricărei
        # ramuri de secvență: tăcerea a existat inclusiv înaintea unei retransmisii,
        # iar ramurile care ies devreme (duplicat, pachet reordonat, repornire) ar
        # pierde-o dacă acumularea ar sta mai jos.
        if missed_windows:
            agent["missed_heartbeats_total"] = (
                agent.get("missed_heartbeats_total", 0) + missed_windows
            )

        # 1) REPORNIRE — autoritar, prin schimbarea incarnării.
        if instance_id is not None:
            last_instance = agent.get("agent_instance_id")

            if last_instance is None:
                # Prima incarnare cunoscută pentru acest agent -> doar baseline.
                # Un last_sequence memorat aici provine dintr-o rulare care nu s-a
                # identificat (build legacy, dinaintea lui agent_instance_id) și nu
                # aparține acestei incarnări. Păstrat, ar bloca baseline-ul exact ca
                # în cazul tratat mai jos, la primul heartbeat al agentului nou.
                agent["agent_instance_id"] = instance_id
                agent.pop("last_sequence", None)
            elif instance_id != last_instance:
                # Proces repornit (crash, kill, tampering). Adoptăm noua incarnare
                # și resetăm baseline-ul de secvență la ea.
                agent["restart_count"] = agent.get("restart_count", 0) + 1
                agent["agent_instance_id"] = instance_id
                agent["last_sequence"] = sequence
                # failed_attempts rămâne 0: golul de secvență nu are sens peste
                # granița dintre două incarnări. missed_heartbeats rămâne însă
                # relevant — timpul cât endpoint-ul a fost neacoperit e real,
                # indiferent care proces l-a lăsat descoperit.
                return HeartbeatResult(
                    agent=agent.copy(),
                    restart_detected=True,
                    missed_heartbeats=missed_windows,
                    failed_attempts=0,
                    silence_seconds=silence_seconds,
                    sequence=sequence,
                    instance_id=instance_id,
                )

        failed_attempts = 0
        continuity_lost = False

        if sequence is not None:
            last_sequence = agent.get("last_sequence")

            if last_sequence is None:
                agent["last_sequence"] = sequence                    # baseline
            elif sequence == last_sequence:
                # Duplicat exact (retransmisie) -> idempotent pe axa secvenței.
                # Valabil indiferent de incarnare: o retransmisie e inofensivă.
                return HeartbeatResult(
                    agent=agent.copy(), restart_detected=False,
                    missed_heartbeats=missed_windows, failed_attempts=0,
                    silence_seconds=silence_seconds,
                    sequence=sequence, instance_id=instance_id,
                )
            elif sequence < last_sequence:
                if instance_id is not None:
                    # Aici incarnarea e obligatoriu cunoscută ȘI neschimbată: dacă
                    # ar fi fost nouă, blocul 1 a golit last_sequence și am fi ajuns
                    # pe ramura de baseline; dacă ar fi diferit, am fi ieșit deja cu
                    # verdict de repornire. În interiorul aceleiași rulări contorul
                    # nu poate scădea -> pachet întârziat/reordonat, ignorat.
                    return HeartbeatResult(
                        agent=agent.copy(), restart_detected=False,
                        missed_heartbeats=missed_windows, failed_attempts=0,
                        silence_seconds=silence_seconds,
                        sequence=sequence, instance_id=instance_id,
                    )

                # Fără incarnare, regresia are două explicații posibile — contor
                # resetat de o repornire, sau pachet reordonat — pe care serverul nu
                # le poate departaja. Alegerea de a ignora regresia costă enorm:
                # baseline-ul ar rămâne blocat pe valoarea rulării precedente, iar
                # fiecare heartbeat până la depășirea ei ar fi aruncat. Cum contorul
                # nou crește cu aceeași cadență cu care a crescut cel vechi, fereastra
                # oarbă ar dura exact cât a durat rularea precedentă — fără plafon.
                # Preferăm baseline-ul refăcut și lacuna declarată deschis.
                agent["last_sequence"] = sequence
                agent["continuity_losses_total"] = (
                    agent.get("continuity_losses_total", 0) + 1
                )
                continuity_lost = True
            else:
                if sequence > last_sequence + 1:
                    failed_attempts = sequence - last_sequence - 1
                    agent["failed_attempts_total"] = (
                        agent.get("failed_attempts_total", 0) + failed_attempts
                    )
                agent["last_sequence"] = sequence

        return HeartbeatResult(
            agent=agent.copy(),
            restart_detected=False,
            missed_heartbeats=missed_windows,
            failed_attempts=failed_attempts,
            silence_seconds=silence_seconds,
            sequence=sequence,
            instance_id=instance_id,
            continuity_lost=continuity_lost,
        )


def register_agent(agent_request: AgentRegisterRequest) -> Dict[str, Any]:
    agent_data = _model_to_dict(agent_request)
    now = _utc_now()

    agent_data["status"] = "registered"
    agent_id = agent_data["agent_id"]

    with agents_lock:
        existing_agent_by_id = agents_store.get(agent_id)

        if existing_agent_by_id:
            existing_hash = existing_agent_by_id.get("machine_id_hash")
            existing_type = existing_agent_by_id.get("machine_id_type")
            new_hash = agent_data.get("machine_id_hash")
            new_type = agent_data.get("machine_id_type")

            # Conflict doar dacă AMBELE părți au o identitate de mașină non-goală
            # și aceasta diferă (hash sau tip). Înregistrările legacy fără hash
            # rămân actualizabile, ca până acum.
            if (
                existing_hash and existing_hash.strip()
                and new_hash and new_hash.strip()
                and (existing_hash, existing_type) != (new_hash, new_type)
            ):
                raise AgentIdConflictError(agent_id)


            created_at = existing_agent_by_id.get("created_at", now)

            existing_agent_by_id.update(agent_data)
            existing_agent_by_id["created_at"] = created_at
            existing_agent_by_id["last_seen"] = now
            existing_agent_by_id["registration_status"] = "updated_by_agent_id"

            return existing_agent_by_id.copy()

        existing_agent_by_machine_id = None
        machine_id_hash = agent_data.get("machine_id_hash")
        machine_id_type = agent_data.get("machine_id_type")

        if machine_id_hash and machine_id_hash.strip():
            for agent in agents_store.values():
                if (
                    agent.get("machine_id_hash") == machine_id_hash
                    and agent.get("machine_id_type") == machine_id_type
                ):
                    existing_agent_by_machine_id = agent
                    break

        if existing_agent_by_machine_id:
            old_agent_id = existing_agent_by_machine_id["agent_id"]
            created_at = existing_agent_by_machine_id.get("created_at", now)

            updated_agent = existing_agent_by_machine_id.copy()
            updated_agent.update(agent_data)
            updated_agent["created_at"] = created_at
            updated_agent["last_seen"] = now
            updated_agent["registration_status"] = "updated_by_machine_id"

            if old_agent_id != agent_id:
                agents_store.pop(old_agent_id, None)

            agents_store[agent_id] = updated_agent
            return updated_agent.copy()

        agent_data["created_at"] = now
        agent_data["last_seen"] = now
        agent_data["registration_status"] = "created"

        agents_store[agent_id] = agent_data
        return agent_data.copy()


def _derive_status(agent: Dict[str, Any]) -> str:
    last_seen_raw = agent.get("last_seen")
    if not last_seen_raw:
        return "unknown"

    try:
        last_seen = datetime.fromisoformat(last_seen_raw)
        
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
            
        age_seconds = (datetime.now(timezone.utc) - last_seen).total_seconds()
        
    except (ValueError, TypeError):
        return "unknown"

    if age_seconds < STALE_AFTER_S:
        return "online"
    if age_seconds < OFFLINE_AFTER_S:
        return "degraded"
    return "offline"


def get_agents() -> List[Dict[str, Any]]:
    result = []
    with agents_lock:
        agents_snapshot = list(agents_store.values())
        

        for agent in agents_snapshot:
            agent_view = agent.copy()
            agent_view["status"] = _derive_status(agent_view)
            result.append(agent_view)
            
        return result


def agent_exists(agent_id: str) -> bool:
    with agents_lock:
        return agent_id in agents_store