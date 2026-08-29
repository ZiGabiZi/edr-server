from typing import Optional

from fastapi import APIRouter, Query

from app.services import wire_accounting
from app.services.disclosure_metrics import compute_disclosure_metrics
from app.services.event_service import get_all_events


router = APIRouter(
    prefix="/api/metrics",
    tags=["Metrics"],
)


@router.get("/disclosure")
def disclosure_metrics(agent_id: Optional[str] = Query(default=None)) -> dict:
    """
    Costul divulgării progresive față de alternativa always-upload.

    Ruta există pentru că `events_store` trăiește în memoria procesului server:
    un script separat nu are cum să îl vadă, iar metrica trebuie citită din
    datele unei rulări reale, nu dintr-o reconstrucție.

    GAURĂ CUNOSCUTĂ, ACEEAȘI CU CEA DE LA RUTELE DE CITIRE (edr-server#9):
        nu cere nicio credențială. NU o lărgește însă: agregatul de aici e
        strict mai puțin decât ce expune deja `GET /api/events`, care întoarce
        fluxul brut, cu tot cu căi de fișiere și amprente. Cine poate citi
        evenimentele poate calcula singur metrica.

        Când analistul primește un secret propriu, ruta asta se închide odată cu
        celelalte două, în aceeași schimbare.
    """
    metrics = compute_disclosure_metrics(get_all_events(), agent_id=agent_id)

    # Reconcilierea se compune AICI, nu înăuntrul lui compute_disclosure_metrics.
    #
    # Funcția aceea e pură: primește evenimente, întoarce cifre, și se poate
    # testa fără proces, fără server și fără stare globală. Contabilizarea de
    # fir e exact opusul — stare vie de proces, alimentată de middleware la
    # fiecare cerere, inclusiv de cererile care n-au produs niciun eveniment.
    # Împletite, o metrică peste evenimente stocate ar depinde de starea
    # transportului, iar testele ei ar avea nevoie de un server pornit.
    #
    # Ele răspund și la întrebări diferite: prima spune cât a costat observarea,
    # a doua spune dacă cifra aceea poate fi crezută. Al doilea răspuns nu are
    # sens topit în primul.
    metrics["reconciliation"] = wire_accounting.reconciliation(agent_id=agent_id)

    return metrics
