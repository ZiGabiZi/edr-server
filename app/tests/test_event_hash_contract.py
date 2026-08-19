"""
Invariantele noi din contract_version 3: hash-ul, dimensiunea si granita
'niciun continut pe canalul de evenimente'.
"""

import pytest
from pydantic import ValidationError

from app.schemas.event import EventCreateRequest


def _base(**overrides):
    payload = {"agent_id": "a1", "event_type": "file_created"}
    payload.update(overrides)
    return payload


def test_sha256_without_ok_status_is_rejected():
    with pytest.raises(ValidationError, match="sha256 este prezent"):
        EventCreateRequest(**_base(sha256="a" * 64, hash_status="unstable"))


def test_ok_status_without_sha256_is_rejected():
    with pytest.raises(ValidationError, match="hash_status este 'ok' dar sha256"):
        EventCreateRequest(**_base(hash_status="ok"))


def test_ok_status_without_file_size_is_rejected():
    with pytest.raises(ValidationError, match="file_size lipseste"):
        EventCreateRequest(**_base(hash_status="ok", sha256="a" * 64))


def test_ok_status_with_sha256_and_file_size_is_accepted():
    event = EventCreateRequest(
        **_base(hash_status="ok", sha256="a" * 64, file_size=1024)
    )
    assert event.hash_status == "ok"


def test_unknown_hash_status_is_rejected():
    with pytest.raises(ValidationError, match="hash_status invalid"):
        EventCreateRequest(**_base(hash_status="cine_stie"))


@pytest.mark.parametrize(
    "status", ["unstable", "unreadable", "too_large", "vanished"]
)
def test_failure_statuses_are_accepted_without_a_hash(status):
    """Esecul hash-ului e o stare legitima, nu o eroare de validare."""
    event = EventCreateRequest(**_base(file_path="C:\\x.exe", hash_status=status))
    assert event.sha256 is None


def test_event_model_never_carries_file_content():
    """
    Pattern pe nume, nu lista fixa (decizia 3): acopera si campuri viitoare
    neanticipate, nu doar 'file_content'/'file_bytes' ghicite azi.
    """
    forbidden_substrings = ("content", "bytes")
    offending = [
        name
        for name in EventCreateRequest.model_fields
        if any(s in name.lower() for s in forbidden_substrings)
    ]
    assert not offending, (
        f"EventCreateRequest declara campuri care sugereaza continut de "
        f"fisier: {offending}. Canalul de evenimente nu are voie sa poarte "
        f"continut — vezi contracts/wire-contract.json, "
        f"models.event_create_request.notes."
    )


def test_agent_builder_always_declares_hash_status_when_file_path_is_present():
    """
    Invarianta 'hash_status insoteste file_path' NU e validator (vezi
    docstring-ul din EventCreateRequest._validate_hash_invariants) — e
    verificata aici, impotriva builder-ului agentului insusi.

    Azi acest test e asteptat sa PICE, pentru ca build_file_event_payload nu
    trimite inca hash_status (Pas 0.2/0.3 nu exista). E marcat xfail explicit
    ca sa fie vizibil in raportul de teste, nu doar taciut.
    """
    pytest.xfail(
        "Se activeaza cand build_file_event_payload (Pas 0.2/0.3) incepe sa "
        "trimita hash_status. Pana atunci, importul builder-ului agentului "
        "necesita edr-agent langa edr-server (EDR_AGENT_PATH), simetric cu "
        "test_wire_contract.py::find_peer_repo."
    )