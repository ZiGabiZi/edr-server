"""
Traducerea unui eveniment de pe fir în forma stocată.

Depozitul propriu-zis stă în app/services/event_store.py. Separarea e aceeași
ca între agent și coada lui persistentă: aici e forma evenimentului și regula
de vizibilitate, acolo sunt schema, constrângerile și conexiunea. Un modul care
ar face amândouă ar fi imposibil de citit fără să deschizi SQLite.
"""

from datetime import datetime, timezone
from typing import List, Dict, Optional

from app.schemas.event import EventCreateRequest
from app.services import event_store, measurement_run


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def find_event_by_client_id(client_event_id: str) -> Optional[dict]:
    return event_store.event_by_client_id(client_event_id)


def create_event(event: EventCreateRequest) -> dict:
    """
    Înregistrează un eveniment primit de la un agent.

    Eticheta rulării se citește AICI, la ingestie, nu la interogarea metricii.
    Un eveniment aparține experimentului în care a sosit; dacă eticheta s-ar
    aplica la citire, toate evenimentele din depozit ar migra spre rularea
    curentă la fiecare schimbare de etichetă, iar experimentele vechi s-ar goli
    pe măsură ce se fac altele noi.

    Un duplicat după `client_event_id` PĂSTREAZĂ rularea primei sosiri și nu
    primește eticheta curentă. Retransmisia e a aceluiași eveniment (§1.3, coada
    e at-least-once), deci o rulare deschisă între cele două plecări n-a
    observat nimic nou — a doua sosire n-are ce adăuga în ea. Garanția nu mai
    stă într-un dicționar de memorie, ci în constrângerea UNIQUE din depozit:
    vezi event_store.py pentru de ce diferența contează odată cu discul.

    `event_id` vine tot din depozit. Contorul de proces de dinainte repornea de
    la 1 la fiecare pornire a serverului, deci ar fi produs coliziuni cu
    rândurile deja scrise.
    """
    new_event = {
        "agent_id": event.agent_id,
        "agent_instance_id": event.agent_instance_id,
        "event_type": event.event_type,
        "client_event_id": event.client_event_id,
        "file_path": event.file_path,
        "sha256": event.sha256,
        "hash_status": event.hash_status,
        "file_size": event.file_size,
        "measurements": event.measurements.model_dump() if event.measurements else None,
        "disclosure": event.disclosure.model_dump() if event.disclosure else None,
        "description": event.description,
        "occurred_at": event.occurred_at,
        "received_at": utc_now(),
        "run_id": measurement_run.current_run_id(),
        "status": "received",
    }

    return event_store.insert_event(new_event)


def get_all_events(run_id: Optional[str] = None) -> List[dict]:
    """
    Evenimentele vizibile acum. Implicit, cele ale rulării CURENTE.

    De ce implicitul nu e tot depozitul:
        Înainte de persistență, depozitul conținea prin construcție doar
        evenimentele pornirii curente — cifrele descriau exact experimentul
        tocmai făcut. Persistența desființează accidentul, iar un implicit care
        ar întoarce tot ar schimba tăcut înțelesul fiecărui apelant existent:
        `GET /api/events` ar amesteca zile de depanare cu proba de măsurătoare,
        iar metrica de divulgare ar publica o medie care nu descrie niciun
        experiment.

        Implicitul de aici păstrează deci comportamentul de dinainte, octet cu
        octet. Interogarea altei rulări e o cerere explicită — vezi 1.4.3, unde
        parametrul urcă până în rută și răspunsul declară ce rulare descrie.

    `run_id=""` nu e un caz special: numai `None` înseamnă rularea curentă, iar
    o etichetă goală nu poate exista (alfabetul din measurement_run o refuză).
    """
    return event_store.all_events(
        run_id if run_id is not None else measurement_run.current_run_id()
    )


def get_events_of_all_runs() -> List[dict]:
    """
    Tot depozitul, peste toate rulările. Fără apelant în server azi.

    Există pentru că întrebarea e legitimă la analiză — câte evenimente s-au
    adunat de când există baza — și pentru că altfel cineva ar fi tentat să o
    răspundă cu `get_all_events()`, crezând că întoarce tot. Numele spune ce
    face, tocmai ca greșeala aceea să nu poată fi făcută din reflex.
    """
    return event_store.all_events()


def reset_for_tests() -> None:
    """Aruncă depozitul și repornește pe o bază din memorie. Vezi event_store."""
    event_store.reset_for_tests()
