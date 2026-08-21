"""
Invariantele noi din contract_version 3: hash-ul, dimensiunea si granita
'niciun continut pe canalul de evenimente'.
"""

import importlib
import json
import logging
import os
import sys
import tempfile
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.schemas.event import VALID_HASH_STATUSES, EventCreateRequest
from app.tests.test_wire_contract import require_peer_repo


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
    "status",
    [
        "unstable",
        "unreadable",
        "too_large",
        "vanished",
        "skipped_capacity",
        "skipped_shutdown",
    ],
)
def test_failure_statuses_are_accepted_without_a_hash(status):
    """Esecul hash-ului e o stare legitima, nu o eroare de validare."""
    event = EventCreateRequest(**_base(file_path="C:\\x.exe", hash_status=status))
    assert event.sha256 is None


def test_the_contract_and_the_schema_agree_on_the_status_vocabulary():
    """
    Vocabularul traieste in doua locuri: frozenset-ul din schema si nota din
    contract. Un status adaugat intr-unul si uitat in celalalt nu produce
    niciun esec la rulare — produce doar o documentatie care minte, exact
    genul de divergenta pe care contractul de fir exista sa o previna.
    """
    contract_path = (
        Path(__file__).resolve().parents[2] / "contracts" / "wire-contract.json"
    )
    notes = json.loads(contract_path.read_text(encoding="utf-8"))["models"][
        "event_create_request"
    ]["notes"]

    undocumented = sorted(
        status for status in VALID_HASH_STATUSES if f"'{status}'" not in notes
    )

    assert not undocumented, (
        f"Statusuri acceptate de schema, dar nementionate in notele "
        f"contractului: {undocumented}."
    )


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
    verificata aici, impotriva agentului insusi.

    Marcajul xfail a cazut la v4: agentul calculeaza acum hash-uri. Testul nu
    se multumeste sa cheme builder-ul cu hash_status dat de mana — asta ar
    verifica doar ca parametrul exista. Ruleaza FileHasher pe un fisier real si
    verifica payload-ul pe care agentul l-ar trimite efectiv, apoi il valideaza
    cu schema serverului. Daca vreo cale din hasher ar uita hash_status,
    esecul apare aici.
    """
    peer_repo = require_peer_repo(
        "invarianta 'hash_status insoteste intotdeauna file_path', verificata "
        "pe payload-ul pe care agentul chiar il produce"
    )

    sys.path.insert(0, str(peer_repo))
    try:
        importlib.invalidate_caches()
        file_hasher = importlib.import_module("services.file_hasher")
        settle_tracker = importlib.import_module("services.settle_tracker")
    finally:
        sys.path.remove(str(peer_repo))

    captured = []

    hasher = file_hasher.FileHasher(
        tracker=settle_tracker.SettleTracker(),
        event_callback=captured.append,
        agent_id="a1",
        agent_instance_id="i1",
        logger=logging.getLogger("test"),
    )

    with tempfile.TemporaryDirectory() as directory:
        file_path = os.path.join(directory, "proba.exe")
        with open(file_path, "wb") as handle:
            handle.write(b"continut de proba")

        hasher.submit(
            settle_tracker.PendingFile(
                path=file_path,
                event_type="file_created",
                occurred_at="2026-01-01T00:00:00+00:00",
                first_seen=1.0,
                last_seen=2.0,
                released_at=3.0,
            )
        )
        assert hasher.process_once() == 1

    payload = captured[0]

    assert payload.get("file_path"), "Hasher-ul nu a produs file_path."
    assert payload.get("hash_status"), (
        "Agentul a produs un eveniment cu file_path, dar fara hash_status. "
        "Serverul nu poate distinge 'nu s-a incercat' de 'a esuat', iar metrica "
        "de octeti divulgati ramane fara numitor."
    )

    # Payload-ul trebuie sa treaca si validarea reala, nu doar sa aiba cheia.
    event = EventCreateRequest(**payload)
    assert event.hash_status in VALID_HASH_STATUSES
    assert event.sha256 is not None
    assert event.file_size is not None