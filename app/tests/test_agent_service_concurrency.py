import threading
import pytest

from app.schemas.agent import AgentRegisterRequest
from app.services import agent_service as svc

N_REGISTER_THREADS = 4
N_READER_THREADS = 6
REGISTRATIONS_PER_THREAD = 400
READS_PER_THREAD = 150


def setup_function():
    svc.agents_store.clear()


def _register_many(thread_index: int, errors: list):
    try:
        for i in range(REGISTRATIONS_PER_THREAD):
            request = AgentRegisterRequest(
                agent_id=f"agent-{thread_index}-{i}",
                hostname="HOST",
                operating_system="windows",
                architecture="x64",
                os_architecture="x64",
                machine_id_type="hash",
                machine_id_hash=f"hash-{thread_index}-{i}",
            )
            svc.register_agent(request)
    except Exception as exc:  # pragma: no cover - failure path under test
        errors.append(exc)


def _read_many(errors: list):
    try:
        for _ in range(READS_PER_THREAD):
            svc.get_agents()
    except Exception as exc:  # pragma: no cover - failure path under test
        errors.append(exc)


def test_concurrent_register_and_read_does_not_corrupt_store():
    """
    Regresie pentru: "dictionary changed size during iteration" +
    read-modify-write neatomic in register_agent/record_heartbeat.
    register_agent insereaza mereu chei noi (creste dictionarul), in timp
    ce alte thread-uri citesc via get_agents() -> pe codul vechi, neprotejat
    de lock, asta reproducea RuntimeError in cateva sutimi de secunda.
    """
    errors: list = []
    threads = [
        threading.Thread(target=_register_many, args=(n, errors))
        for n in range(N_REGISTER_THREADS)
    ] + [
        threading.Thread(target=_read_many, args=(errors,))
        for _ in range(N_READER_THREADS)
    ]

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert len(svc.agents_store) == N_REGISTER_THREADS * REGISTRATIONS_PER_THREAD


def test_concurrent_heartbeats_are_atomic():
    """
    Regresie pentru read-modify-write neatomic in record_heartbeat: fara lock,
    heartbeat-uri concurente pe acelasi agent_id pot interleui intre citirea
    si scrierea lui last_seen.
    """
    agent_id = "agent-shared"
    svc.register_agent(
        AgentRegisterRequest(
            agent_id=agent_id,
            hostname="HOST",
            operating_system="windows",
            architecture="x64",
            os_architecture="x64",
            machine_id_type="hash",
            machine_id_hash="hash-shared",
        )
    )

    errors: list = []

    def _heartbeat_many():
        try:
            for _ in range(READS_PER_THREAD):
                result = svc.record_heartbeat(agent_id)
                assert result is not None
        except Exception as exc:  # pragma: no cover - failure path under test
            errors.append(exc)

    threads = [threading.Thread(target=_heartbeat_many) for _ in range(N_READER_THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert svc.agent_exists(agent_id)
