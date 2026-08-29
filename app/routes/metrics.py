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
    # Măsurătoarea pe canale, luată ÎNAINTE de calcul: numărătorul afirmației
    # centrale e canalul de evenimente și doar el. Controlul e prag separat
    # (METRICS.md §1.4), înrolarea e proporțională cu repornirile, iar `other`
    # e plasa pentru rute care n-au fost clasificate — niciunul n-are ce căuta
    # în cifra publicată ca divulgare.
    measured = wire_accounting.measured_by_channel(agent_id=agent_id)
    measured_events = measured[wire_accounting.CHANNEL_EVENTS]

    metrics = compute_disclosure_metrics(
        get_all_events(),
        agent_id=agent_id,
        measured_channel_bytes=measured_events["bytes"],
        measured_channel_messages=measured_events["messages"],
    )

    # Canalele întregi, alături de numărător. Podeaua din §1.4 nu se mai
    # estimează pe hârtie: e aici, măsurată, lângă cifra pe care o mărginește.
    metrics["measured"] = {
        "scope": agent_id or "toti agentii",
        "by_channel": measured,
        "note": (
            "Octetii de corp masurati de server, despartiti dupa calea cererii. "
            "Numai canalul events intra in numaratorul divulgarii; control e "
            "pragul din §1.4, enrollment creste cu repornirile, iar other "
            "aduna rutele neclasificate, ca o ruta noua sa nu creasca tacut "
            "cifra afirmatiei principale. Octetii neatribuibili nu sunt aici: "
            "vezi reconciliation.unattributable."
        ),
    }

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
