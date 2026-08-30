"""
Rutele rulării de măsurătoare — cum se citește și cum se schimbă eticheta.

Vezi app/services/measurement_run.py pentru ce e o rulare și de ce există.
Aici stă doar traducerea în HTTP.
"""

from fastapi import APIRouter, Depends

from app.routes.scope import http_error_for
from app.security import require_operator_secret
from app.services import event_store, measurement_run
from app.services.measurement_run import RunLabelError


router = APIRouter(
    prefix="/api/runs",
    tags=["Measurement runs"],
)


@router.get("/current")
def read_current_run() -> dict:
    """
    Rularea în care aterizează evenimentele care sosesc acum.

    Ruta e de citit înainte de orice experiment: dacă întoarce o etichetă
    `auto-...`, evenimentele care urmează vor purta numele inventat de server,
    nu numele din intrarea de jurnal.
    """
    return {"run": measurement_run.current_run()}


@router.get("")
def list_runs() -> dict:
    """
    Rulările consemnate de procesul curent.

    E catalogul experimentelor: registrul e persistent, deci lista acoperă tot
    ce s-a deschis vreodată, nu doar pornirea curentă a serverului.

    Fiecare rulare vine cu numărul ei de evenimente, pentru că întrebarea care
    urmează imediat după oricare etichetă e chiar aceea. O rulare cu zero
    evenimente e un fapt util, nu o eroare: tipic, eticheta generată la pornire,
    peste care operatorul a pus imediat numele din jurnal.
    """
    events_by_run = {
        item["run_id"]: item["events"] for item in event_store.event_counts_by_run()
    }
    runs = [
        {**run, "events": events_by_run.get(run["run_id"], 0)}
        for run in measurement_run.known_runs()
    ]

    return {
        "count": len(runs),
        "current": measurement_run.current_run_id(),
        "runs": runs,
    }


@router.post("/{label}")
def open_run(
    label: str,
    _: None = Depends(require_operator_secret),
) -> dict:
    """
    Deschide o rulare numită și o face curentă. Refuză o etichetă deja folosită.

    De ce eticheta stă în CALE și cererea n-are corp:
        Middleware-ul de contabilizare cântărește corpul fiecărei cereri și îl
        pune într-o găleată. O cerere de operator, care nu poartă cheie de
        agent, ar ateriza la `unattributable.no_key` — găleata în care se
        raportează azi prima înrolare a unei mașini, adică octeți plecați de pe
        un endpoint monitorizat. Doi octeți de administrare amestecați acolo ar
        murdări exact diagnosticul folosit ca să se explice ce anume rămâne
        nemăsurat (METRICS.md §7.5). Fără corp, nu e nimic de cântărit.

        Eticheta e făcută pentru calea asta: alfabetul din serviciu exclude
        orice caracter care ar avea nevoie de codare într-un segment de URL.
    """
    try:
        run = measurement_run.start_run(label)
    except RunLabelError as error:
        raise http_error_for(error)

    return {
        "message": "Measurement run opened",
        "run": run,
    }
