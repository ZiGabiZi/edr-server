"""
Stratul HTTP al contabilizării — cine cântărește pachetul, și când.
===================================================================

Separarea față de app/services/wire_accounting.py e aceeași ca la security.py:
acolo stau contoarele, care se pot testa fără să existe un server; aici stă
singurul loc care se uită la o cerere HTTP și decide în ce găleată intră.

De ce middleware și nu numărătoare în rute
------------------------------------------
    O rută vede doar cererile care ajung la ea. Dar o cerere cu cheie greșită e
    respinsă cu 401 de dependency-ul de autentificare și nu ajunge niciodată la
    ruta de evenimente — deși a plecat de pe endpoint, a traversat rețeaua și a
    fost primită de server. Cu numărătoare în rute, exact traficul care eșuează
    la autentificare ar dispărea din contabilitate.

    Iar acela e cel mai interesant: un agent cu cheia greșită care trimite ore
    în șir divulgă tot ce trimite, fără să scrie nimic nicăieri. Un raport care
    nu-l arată descrie un endpoint tăcut, ceea ce e fals.

    Middleware-ul vede fiecare cerere, indiferent dacă reușește sau e refuzată.

Ce plătim pentru asta
---------------------
    Portarul stă înainte de rutare, deci nu are încă o identitate: aceea se
    stabilește mai târziu, în dependency-ul de autentificare. Ca să atribuie
    octeții, middleware-ul trebuie să caute singur cheia în depozit — o legătură
    în plus între contabilitate și autentificare, două zone care până acum nu se
    atingeau. E o simplă căutare, fără efecte secundare, și nu decide nimic
    despre cerere: nu respinge, nu modifică, nu întârzie.

De ce nu citim corpul
---------------------
    Ar fi cifra exactă, dar un middleware care consumă fluxul de intrare îl ia
    de sub ruta care urmează. Folosim `Content-Length`, pe care agentul îl pune
    întotdeauna (trimite un corp de octeți, deja serializat). Când lipsește,
    mesajul se numără la `unsized` — dimensiunea e necunoscută, nu zero.

    Anteturile HTTP nu se numără deloc, conform METRICS.md §1.2: sunt cost de
    transport, identic sub ambele politici, deci s-ar aduna la fel în numărător
    și în numitor.
"""

import logging
from typing import Callable

from fastapi import FastAPI, Request, Response

from app.services import auth_service, wire_accounting


logger = logging.getLogger(__name__)


# Metodele care poartă un corp. Restul — GET /health, rutele de citire, metrica
# însăși — nu divulgă nimic dinspre endpoint și nu au ce contabiliza.
_METHODS_WITH_BODY = frozenset({"POST", "PUT", "PATCH"})

# Numele antetelor, identice cu cele din edr-agent/services/transport.py și
# documentate în contracts/METRICS.md §7.1. O literă greșită aici nu produce o
# eroare, ci contabilitate tăcut goală — de aceea sunt constante, nu literali
# împrăștiați, și de aceea există testul care le caută în contract.
WIRE_ATTEMPTED_HEADER = "X-Agent-Wire-Attempted-Bytes"
WIRE_DELIVERED_HEADER = "X-Agent-Wire-Delivered-Bytes"
WIRE_INSTANCE_HEADER = "X-Agent-Instance-Id"


def _content_length(request: Request) -> int | None:
    """Dimensiunea corpului declarată de client, sau None dacă nu o declară."""
    raw = request.headers.get("content-length")

    if raw is None:
        return None

    try:
        value = int(raw)
    except ValueError:
        return None

    return value if value >= 0 else None


def account_for_request(request: Request) -> None:
    """
    Pune octeții cererii curente într-o găleată, oricare ar fi ea.

    Ordinea întrebărilor nu e arbitrară — fiecare motiv de neatribuire trebuie
    să descrie starea reală, nu prima verificare care a picat:

        1. are corp? dacă nu, nu e nimic de contabilizat;
        2. își declară dimensiunea? dacă nu, `unsized` — știm că a fost, nu și
           cât;
        3. prezintă o cheie? dacă nu, `no_key`;
        4. e cheia cunoscută? dacă nu, `unknown_key` — traficul care nu ajunge
           niciodată la o rută;
        5. își declară încarnarea? dacă nu, `no_instance` — azi, tipic, cererea
           de înregistrare (edr-agent#19);
        6. altfel, atribuit.
    """
    if request.method not in _METHODS_WITH_BODY:
        return

    byte_count = _content_length(request)

    if byte_count is None:
        wire_accounting.record_unattributable(wire_accounting.UNATTRIBUTABLE_UNSIZED)
        return

    if byte_count == 0:
        # Un corp gol nu divulgă nimic. Nu e o anomalie de raportat, doar o
        # cerere fără conținut — contabilizarea ei ar adăuga mesaje fără octeți.
        return

    presented_key = request.headers.get(auth_service.AGENT_KEY_HEADER)

    if not presented_key:
        wire_accounting.record_unattributable(
            wire_accounting.UNATTRIBUTABLE_NO_KEY, byte_count
        )
        return

    agent_id = auth_service.agent_id_for_key(presented_key)

    if agent_id is None:
        wire_accounting.record_unattributable(
            wire_accounting.UNATTRIBUTABLE_UNKNOWN_KEY, byte_count
        )
        return

    instance_id = request.headers.get(WIRE_INSTANCE_HEADER)

    if not instance_id:
        wire_accounting.record_unattributable(
            wire_accounting.UNATTRIBUTABLE_NO_INSTANCE, byte_count
        )
        return

    raw_attempted = request.headers.get(WIRE_ATTEMPTED_HEADER)
    raw_delivered = request.headers.get(WIRE_DELIVERED_HEADER)

    wire_accounting.record_attributed(
        agent_id=agent_id,
        agent_instance_id=instance_id,
        byte_count=byte_count,
        reported_attempted=wire_accounting.parse_reported_bytes(raw_attempted),
        reported_delivered=wire_accounting.parse_reported_bytes(raw_delivered),
        report_present=raw_attempted is not None or raw_delivered is not None,
    )


def install_wire_accounting(app: FastAPI) -> None:
    """
    Montează portarul pe aplicație.

    Contabilizarea se face ÎNAINTE de `call_next`, nu după: dacă ruta de după
    aruncă, octeții tot au fost primiți, iar o numărătoare de după ar pierde
    exact cererile care au stricat ceva. Din același motiv, orice eroare a
    contabilizării e prinsă și logată, nu propagată — o metrică nu are voie să
    doboare o cerere de eveniment. Într-un EDR, tăcerea unui endpoint e un
    simptom mai grav decât o cifră lipsă.
    """

    @app.middleware("http")
    async def account_wire_bytes(request: Request, call_next: Callable) -> Response:
        try:
            account_for_request(request)
        except Exception:  # pragma: no cover - plasa de siguranță
            logger.exception(
                "Wire accounting failed for %s %s. The request continues.",
                request.method,
                request.url.path,
            )

        return await call_next(request)
