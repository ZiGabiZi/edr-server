"""
Rutele rulării de măsurătoare — cum se citește și cum se schimbă eticheta.

Vezi app/services/measurement_run.py pentru ce e o rulare și de ce există.
Aici stă doar traducerea în HTTP.
"""

from fastapi import APIRouter, Depends, HTTPException, status

from app.security import require_operator_secret
from app.services import measurement_run
from app.services.measurement_run import RunLabelError


router = APIRouter(
    prefix="/api/runs",
    tags=["Measurement runs"],
)


# Traducerea motivului în cod HTTP. Tabel, nu lanț de if-uri, ca un motiv nou
# adăugat în serviciu fără corespondent aici să iasă zgomotos (KeyError la
# prima folosire), nu tăcut ca un 400 nimerit din reflex.
_STATUS_BY_REASON = {
    RunLabelError.REASON_MALFORMED: status.HTTP_400_BAD_REQUEST,
    RunLabelError.REASON_RESERVED: status.HTTP_400_BAD_REQUEST,
    RunLabelError.REASON_ALREADY_USED: status.HTTP_409_CONFLICT,
}


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

    Cât timp registrul e în memorie (vezi limitarea declarată în serviciu),
    lista descrie pornirea curentă a serverului, nu istoricul măsurătorilor.
    """
    runs = measurement_run.known_runs()

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
        raise HTTPException(
            status_code=_STATUS_BY_REASON[error.reason],
            detail=str(error),
        )

    return {
        "message": "Measurement run opened",
        "run": run,
    }
