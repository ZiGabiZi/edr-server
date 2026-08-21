from typing import Optional
from pydantic import model_validator, BaseModel

from app.schemas.wire import WireModel


# Valorile acceptate pentru hash_status. 'ok' e singura care poate insoti un
# sha256. Restul numesc motivul absentei lui, nu doar o absenta tacuta:
#   unstable          — plafonul de asteptare a stabilizarii a fost depasit
#   unreadable        — fisierul n-a putut fi citit (lock, permisiuni)
#   too_large         — fisierul depaseste max_hash_bytes, nu s-a incercat hashing
#   vanished          — fisierul a disparut intre detectie si hashing
#   skipped_capacity  — coada de hashing era plina (v4)
#   skipped_shutdown  — agentul se oprea, bugetul de hashing a expirat (v4)
#
# Ultimele doua descriu AGENTUL, nu fisierul. 'unstable' spune ca fisierul nu
# s-a linistit; 'skipped_*' spun ca observatorul era sub presiune sau se oprea,
# in timp ce fisierul putea fi perfect stabil. Confundate, registrul de
# divulgare de la Etapa 3 nu ar mai putea separa costul impus de obiectul
# observat de costul impus de observator. Numele oglindesc deliberat
# SettleTracker.PendingFile.forced_reason din agent ('capacity', 'shutdown').
VALID_HASH_STATUSES = frozenset(
    {
        "ok",
        "unstable",
        "unreadable",
        "too_large",
        "vanished",
        "skipped_capacity",
        "skipped_shutdown",
    }
)


class EventMeasurements(WireModel):
    """
    Costul observatiei, nu al obiectului observat.

    Separat structural de EventCreateRequest ca sa nu se amestece niciodata cu
    campurile care descriu fisierul (sha256, file_size): niciun camp de aici
    nu are voie sa intre intr-o decizie de verdict sau de escaladare — vezi
    contracts/wire-contract.json, models.event_measurements.
    """

    settle_wait_ms: Optional[int] = None
    hash_duration_ms: Optional[int] = None


class EventCreateRequest(WireModel):
    agent_id: str
    event_type: str
    client_event_id: Optional[str] = None
    file_path: Optional[str] = None
    sha256: Optional[str] = None
    hash_status: Optional[str] = None
    file_size: Optional[int] = None
    measurements: Optional[EventMeasurements] = None
    description: Optional[str] = None
    occurred_at: Optional[str] = None
    agent_instance_id: Optional[str] = None

    @model_validator(mode="after")
    def _validate_hash_invariants(self) -> "EventCreateRequest":
        """
        Impune DOAR invariantele care nu pot fi incalcate de traficul de azi.

        hash_status obligatoriu-cand-file_path-e-prezent NU e verificat aici,
        deliberat: agentul curent trimite file_path fara hash_status,
        iar o exceptie ridicata aici ar deveni 422 ->
        FatalTransportError -> EventDispatcher trateaza evenimentul ca poison
        message si il sterge din spool. Un camp lipsa e recuperabil; un
        eveniment sters, nu. Vezi app/schemas/wire.py pentru acelasi
        rationament aplicat cheilor nedeclarate. Invarianta e verificata in
        schimb la nivel de test, impotriva builder-ului agentului
        (test_event_contract.py::
        test_agent_builder_always_declares_hash_status_when_file_path_is_present),
        si va deveni validator aici cand agentul chiar calculeaza hash-uri.
        """
        if self.hash_status is not None and self.hash_status not in VALID_HASH_STATUSES:
            raise ValueError(
                f"hash_status invalid: {self.hash_status!r}. "
                f"Valori acceptate: {sorted(VALID_HASH_STATUSES)}."
            )

        has_hash = self.sha256 is not None
        is_ok = self.hash_status == "ok"

        if has_hash and not is_ok:
            raise ValueError(
                "sha256 este prezent dar hash_status nu este 'ok'. Invarianta "
                "contractului: sha256 prezent <=> hash_status == 'ok' (vezi "
                "contracts/wire-contract.json, models.event_create_request)."
            )

        if is_ok and not has_hash:
            raise ValueError(
                "hash_status este 'ok' dar sha256 lipseste. Invarianta "
                "contractului: sha256 prezent <=> hash_status == 'ok'."
            )

        if is_ok and self.file_size is None:
            raise ValueError(
                "hash_status este 'ok' dar file_size lipseste. file_size "
                "trebuie sa insoteasca intotdeauna un hash reusit — e "
                "numaratorul metricii de octeti divulgati vs. always-upload, "
                "si nu se poate reconstrui retroactiv daca fisierul se schimba."
            )

        return self


class EventResponse(BaseModel):
    event_id: int
    client_event_id: Optional[str] = None
    agent_id: str
    agent_instance_id: Optional[str] = None
    event_type: str
    file_path: Optional[str] = None
    sha256: Optional[str] = None
    hash_status: Optional[str] = None
    file_size: Optional[int] = None
    measurements: Optional[EventMeasurements] = None
    description: Optional[str] = None
    occurred_at: Optional[str] = None
    received_at: Optional[str] = None
    status: str