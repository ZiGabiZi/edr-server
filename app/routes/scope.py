"""
Selecția rulării — cum aleg rutele de citire despre ce experiment vorbesc.

Modulul e comun rutelor de metrică și de evenimente pentru că întrebarea e
aceeași, iar două traduceri paralele ale ei ar începe să difere: una ar accepta
o etichetă necunoscută, cealaltă nu, și nimeni n-ar observa până când o cifră
publicată n-ar descrie altceva decât crede cititorul.

De ce o etichetă necunoscută primește 404, nu un rezultat gol:
    Un răspuns gol pentru `masuratoare-t0-corpus-444` scris greșit ar arăta
    exact ca un experiment care n-a divulgat nimic — cea mai flatantă cifră
    posibilă despre un sistem de confidențialitate, obținută dintr-o greșeală de
    tastare. Ruta refuză să răspundă despre o rulare care nu există.

    Un experiment care chiar n-a produs niciun eveniment se deosebește:
    eticheta lui E în registru, deci răspunsul vine cu zero evenimente și cu
    rularea declarată lângă ele.
"""

from dataclasses import dataclass
from typing import Optional

from fastapi import Depends, HTTPException, Query, status

from app.services import event_store, measurement_run
from app.services.measurement_run import RunLabelError


# Traducerea motivului în cod HTTP. Tabel, nu lanț de if-uri, ca un motiv nou
# adăugat în serviciu fără corespondent aici să iasă zgomotos (KeyError la prima
# folosire), nu tăcut ca un 400 nimerit din reflex.
STATUS_BY_REASON = {
    RunLabelError.REASON_MALFORMED: status.HTTP_400_BAD_REQUEST,
    RunLabelError.REASON_RESERVED: status.HTTP_400_BAD_REQUEST,
    RunLabelError.REASON_ALREADY_USED: status.HTTP_409_CONFLICT,
}


def http_error_for(error: RunLabelError) -> HTTPException:
    return HTTPException(
        status_code=STATUS_BY_REASON[error.reason],
        detail=str(error),
    )


@dataclass(frozen=True)
class RunScope:
    """
    Despre ce vorbește un răspuns de citire.

    `run_id is None` înseamnă tot istoricul, cerut explicit. Nu e o valoare
    lipsă: e chiar decizia D2 — implicit se descrie rularea curentă, iar
    agregatul peste toate rulările se cere, nu se nimerește.
    """

    run_id: Optional[str]
    source: Optional[str]
    opened_at: Optional[str]
    is_current: bool

    @property
    def covers_all_runs(self) -> bool:
        return self.run_id is None

    def declaration(self) -> dict:
        """
        Blocul pe care orice răspuns îl poartă, ca METRICS.md §8 să nu rămână o
        obligație pe hârtie: cifra spune singură ce corpus descrie.
        """
        if self.covers_all_runs:
            by_run = event_store.event_counts_by_run()

            return {
                "selection": "all_runs",
                "run_id": None,
                "events_in_scope": sum(item["events"] for item in by_run),
                "runs_covered": by_run,
                "note": (
                    "Agregat peste toate rularile din depozit, cerut explicit. "
                    "Cifrele NU descriu un singur experiment: corpusul e "
                    "reuniunea celor de mai jos, cu distributii de fisiere "
                    "diferite. Pentru o cifra citabila, cere o singura rulare."
                ),
            }

        return {
            "selection": "single_run",
            "run_id": self.run_id,
            "source": self.source,
            "opened_at": self.opened_at,
            "is_current": self.is_current,
            "events_in_scope": event_store.count_events(self.run_id),
            "note": (
                "Cifrele descriu doar evenimentele sosite in aceasta rulare. "
                "source=operator inseamna ca eticheta a fost data de un om si "
                "poate fi legata de intrarea de tip masuratoare din jurnal; "
                "source=generated inseamna ca a inventat-o serverul la pornire."
            ),
        }


def run_scope(
    run_id: Optional[str] = Query(
        default=None,
        description=(
            "Eticheta rularii de masuratoare. Implicit, rularea curenta."
        ),
    ),
    all_runs: bool = Query(
        default=False,
        description=(
            "Agrega peste toate rularile din depozit. Nu se combina cu run_id."
        ),
    ),
) -> RunScope:
    """
    Dependency FastAPI: traduce parametrii de selecție într-o rulare validată.

    `run_id` și `all_runs` împreună sunt o contradicție, nu o preferință cu
    câștigător: cine le trimite pe amândouă crede ceva despre răspuns, iar orice
    am alege în locul lui ar fi jumătate din ce a cerut. 400, cu motivul spus.
    """
    if all_runs and run_id is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "run_id and all_runs are mutually exclusive: ask for one run, "
                "or for the aggregate over every run, not both"
            ),
        )

    if all_runs:
        return RunScope(run_id=None, source=None, opened_at=None, is_current=False)

    if run_id is None:
        current = measurement_run.current_run()

        return RunScope(
            run_id=current["run_id"],
            source=current["source"],
            opened_at=current["opened_at"],
            is_current=True,
        )

    record = event_store.run_record(run_id)

    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"No measurement run named {run_id} has ever been opened. An "
                f"empty answer would look like an experiment that disclosed "
                f"nothing, so the request is refused instead"
            ),
        )

    return RunScope(
        run_id=record["run_id"],
        source=record["source"],
        opened_at=record["opened_at"],
        is_current=record["run_id"] == measurement_run.current_run_id(),
    )


RunScopeDependency = Depends(run_scope)
