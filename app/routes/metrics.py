from typing import Optional

from fastapi import APIRouter, Query

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
    return compute_disclosure_metrics(get_all_events(), agent_id=agent_id)
