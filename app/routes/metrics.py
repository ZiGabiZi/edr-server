from typing import Optional

from fastapi import APIRouter, Query

from app.routes.scope import RunScope, RunScopeDependency
from app.services import event_service, wire_accounting
from app.services.disclosure_metrics import compute_disclosure_metrics


router = APIRouter(
    prefix="/api/metrics",
    tags=["Metrics"],
)


# De ce măsurătoarea de fir nu se poate atribui oricărei rulări.
# =============================================================
#
# `wire_accounting` numără octeți de la pornirea procesului încoace și nu știe
# nimic despre rulări: middleware-ul cântărește corpuri, nu experimente. Cifra
# lui descrie deci o singură rulare doar dacă procesul n-a primit evenimente în
# nicio alta.
#
# Cazul tipic al unei măsurători adevărate îndeplinește condiția fără efort:
# pornești serverul, numești rularea, apoi trimiți corpusul — rularea generată
# la pornire rămâne goală. Cazul în care NU o îndeplinește e la fel de tipic:
# ceri metrica unei rulări de acum trei zile, iar procesul curent n-a numărat
# niciun octet din ea.
#
# Publicată totuși ca `measured`, cifra ar purta autoritatea unei măsurători
# peste date cu care n-are nicio legătură. Aceeași familie cu regula deja
# scrisă la §7.5: zero măsurat nu e o măsurătoare. Aici e mai rău — nu e zero,
# e numărul altcuiva.
MEASUREMENT_APPLIES = "numaratorul masurat descrie chiar aceasta rulare"

MEASUREMENT_OTHER_RUNS = (
    "procesul a primit evenimente si in alte rulari, deci octetii masurati de "
    "el nu descriu doar rularea ceruta; numaratorul revine la estimare"
)

MEASUREMENT_PAST_RUN = (
    "octetii se numara de la pornirea procesului, iar rularea ceruta nu e "
    "printre cele observate de el; numaratorul revine la estimare"
)

MEASUREMENT_ALL_RUNS = (
    "agregatul acopera rulari dinainte de pornirea procesului, pe care "
    "contabilizarea de fir nu le-a vazut; numaratorul revine la estimare"
)


def _measurement_verdict(scope: RunScope) -> tuple:
    """
    Spune dacă octeții măsurați de proces pot fi numărătorul acestei cifre.

    Întoarce perechea (se aplică, motivul). Motivul se publică și când
    răspunsul e da, pentru că o afirmație despre proveniența unei cifre e la
    fel de importantă în ambele sensuri.
    """
    if scope.covers_all_runs:
        return False, MEASUREMENT_ALL_RUNS

    observed = event_service.runs_observed_this_process()

    if observed - {scope.run_id}:
        return False, MEASUREMENT_OTHER_RUNS

    if not scope.is_current and scope.run_id not in observed:
        return False, MEASUREMENT_PAST_RUN

    return True, MEASUREMENT_APPLIES


@router.get("/disclosure")
def disclosure_metrics(
    agent_id: Optional[str] = Query(default=None),
    scope: RunScope = RunScopeDependency,
) -> dict:
    """
    Costul divulgării progresive față de alternativa always-upload.

    Ce descrie cifra, și de unde se știe:
        Implicit, rularea de măsurătoare CURENTĂ. `run_id` cere alta,
        `all_runs=true` cere agregatul peste tot depozitul. Răspunsul poartă
        întotdeauna blocul `run`, cu eticheta, sursa ei și câte evenimente are —
        altfel METRICS.md §8, care cere ca orice cifră publicată să vină cu
        corpusul declarat, ar rămâne o obligație pe hârtie.

        Implicitul nu e o comoditate, e decizia D2. Tot istoricul e mai util
        operațional și mai periculos pentru teză: o medie peste experimente cu
        distribuții diferite de fișiere nu descrie niciunul dintre ele. Se poate
        cere, dar se cere.

    De ce ruta rămâne, deși evenimentele sunt acum pe disc:
        Motivul inițial a fost că `events_store` trăia în memoria procesului,
        deci un script separat n-avea cum să îl vadă. Din 1.4.2 motivul acela nu
        mai e adevărat — evenimentele se pot citi din SQLite din afara
        serverului. Rămân însă două care nu se pot muta:

        Contabilizarea de fir (`wire_accounting`) e stare de proces, alimentată
        de middleware la fiecare cerere. Numărătorul MĂSURAT al metricii vine de
        acolo, iar un script din afară nu are de unde să îl ia; ar putea calcula
        doar varianta estimată, adică exact cifra pe care METRICS.md §7 o
        declară insuficientă.

        Și, mai important, definițiile. Numitorul, atribuirea pe trepte, golurile
        declarate — toate stau într-un singur loc, aici. Un script care le-ar
        reimplementa ar putea da o cifră diferită pentru aceleași date, fără ca
        vreuna dintre ele să fie vizibil greșită.

    GAURĂ CUNOSCUTĂ, ACEEAȘI CU CEA DE LA RUTELE DE CITIRE (edr-server#9):
        nu cere nicio credențială. NU o lărgește însă: agregatul de aici e
        strict mai puțin decât ce expune deja `GET /api/events`, care întoarce
        fluxul brut, cu tot cu căi de fișiere și amprente. Cine poate citi
        evenimentele poate calcula singur metrica.

        Când analistul primește un secret propriu, ruta asta se închide odată cu
        celelalte două, în aceeași schimbare.
    """
    events = (
        event_service.get_events_of_all_runs()
        if scope.covers_all_runs
        else event_service.get_all_events(scope.run_id)
    )

    # Măsurătoarea pe canale, luată ÎNAINTE de calcul: numărătorul afirmației
    # centrale e canalul de evenimente și doar el. Controlul e prag separat
    # (METRICS.md §1.4), înrolarea e proporțională cu repornirile, iar `other`
    # e plasa pentru rute care n-au fost clasificate — niciunul n-are ce căuta
    # în cifra publicată ca divulgare.
    measured = wire_accounting.measured_by_channel(agent_id=agent_id)
    measured_events = measured[wire_accounting.CHANNEL_EVENTS]

    # ...dar numai dacă octeții aceia descriu chiar rularea cerută. Altfel se
    # raportează mai jos ca diagnostic al procesului, fără să intre în cifră.
    applies, verdict = _measurement_verdict(scope)

    metrics = compute_disclosure_metrics(
        events,
        agent_id=agent_id,
        measured_channel_bytes=measured_events["bytes"] if applies else None,
        measured_channel_messages=measured_events["messages"] if applies else None,
    )

    # Canalele întregi, alături de numărător. Podeaua din §1.4 nu se mai
    # estimează pe hârtie: e aici, măsurată, lângă cifra pe care o mărginește.
    metrics["measured"] = {
        "scope": agent_id or "toti agentii",
        "by_channel": measured,
        "applies_to_numerator": applies,
        "attribution": verdict,
        "note": (
            "Octetii de corp masurati de server, despartiti dupa calea cererii. "
            "Numai canalul events intra in numaratorul divulgarii, si numai cand "
            "applies_to_numerator e adevarat; control e pragul din §1.4, "
            "enrollment creste cu repornirile, iar other aduna rutele "
            "neclasificate, ca o ruta noua sa nu creasca tacut cifra afirmatiei "
            "principale. Cifrele de aici descriu PROCESUL de la pornire incoace, "
            "nu rularea: cand cele doua nu coincid, raman diagnostic. Octetii "
            "neatribuibili nu sunt aici: vezi reconciliation.unattributable."
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
    #
    # La fel ca `measured`, descrie procesul, nu rularea — și din același motiv:
    # o discrepanță agent-server e o proprietate a transportului dintre două
    # porniri, nu a experimentului care se întâmpla atunci.
    metrics["reconciliation"] = wire_accounting.reconciliation(agent_id=agent_id)

    # Declarația de corpus stă PRIMA în răspuns, nu ultima. Cine deschide
    # rezultatul trebuie să vadă despre ce experiment e înainte să vadă cifrele;
    # invers, ar citi numerele și abia apoi ar afla dacă îl privesc.
    return {"run": scope.declaration(), **metrics}
