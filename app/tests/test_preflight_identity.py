"""
Verificarea identitatii clonelor (deploy/preflight_identity.py).

Scriptul e ultima poarta inainte de o eticheta de rulare, care nu se mai
redeschide. Un verdict gresit aici nu produce erori, produce o rulare in care
doua clone au devenit una — deci testele intreaba explicit fiecare ramura care
trebuie sa blocheze si fiecare care doar avertizeaza.

Scriptul sta in deploy/, nu intr-un pachet, si se incarca dupa cale.
"""

import importlib.util
import io
import json
import urllib.error
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parents[2] / "deploy" / "preflight_identity.py"
_spec = importlib.util.spec_from_file_location("preflight_identity", _PATH)
preflight = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(preflight)

SERVER = "http://server.test:8000"


def _agent(n, status="online", machine_hash=None, registration="created"):
    return {
        "agent_id": f"endpoint0{n}-abc{n}",
        "hostname": f"ENDPOINT0{n}",
        "machine_id_hash": machine_hash or f"{n}" * 64,
        "registration_status": registration,
        "status": status,
    }


def _run(monkeypatch, agents, *extra):
    monkeypatch.setattr(preflight, "fetch_agents", lambda url, timeout: agents)
    return preflight.main(["--server", SERVER, *extra])


def test_five_distinct_agents_open_the_run(monkeypatch, capsys):
    agents = [_agent(n) for n in range(1, 6)]

    assert _run(monkeypatch, agents, "--expected", "5") == 0
    assert "OK: identitati distincte" in capsys.readouterr().out


def test_stopped_agents_only_warn(monkeypatch, capsys):
    # Turul se face pe rand: la final, doar ultimul agent e online.
    agents = [_agent(n, status="offline") for n in range(1, 5)] + [_agent(5)]

    assert _run(monkeypatch, agents, "--expected", "5") == 0
    out = capsys.readouterr().out
    assert out.count("AVERTISMENT  server: endpoint0") == 4
    assert "1 agent(i) activi in registru: endpoint05-abc5" in out


def test_identity_taken_over_by_machine_id_blocks(monkeypatch, capsys):
    agents = [_agent(n) for n in range(1, 5)] + [_agent(5, registration="updated_by_machine_id")]

    assert _run(monkeypatch, agents, "--expected", "5") == 1
    assert "updated_by_machine_id" in capsys.readouterr().out


def test_the_same_machine_guid_on_two_clones_blocks(monkeypatch, capsys):
    agents = [_agent(n) for n in range(1, 4)] + [
        _agent(4, machine_hash="f" * 64),
        _agent(5, machine_hash="f" * 64),
    ]

    assert _run(monkeypatch, agents, "--expected", "5") == 1
    out = capsys.readouterr().out
    assert "acelasi machine_id_hash (ffffffffffff...)" in out
    assert "ENDPOINT04, ENDPOINT05" in out


def test_merged_clones_show_as_fewer_agents_and_block(monkeypatch, capsys):
    # Un fisier agent_id copiat: doua clone devin un singur agent, tacut.
    agents = [_agent(n) for n in range(1, 5)]

    assert _run(monkeypatch, agents, "--expected", "5") == 1
    assert "4 agenti in registru, asteptati 5" in capsys.readouterr().out


def test_without_expected_the_count_is_not_checked(monkeypatch):
    assert _run(monkeypatch, [_agent(1)]) == 0


def test_the_server_is_required():
    with pytest.raises(SystemExit) as raised:
        preflight.main([])
    assert raised.value.code == 2


def test_the_reports_mode_is_gone():
    with pytest.raises(SystemExit) as raised:
        preflight.main(["--reports", "preflight", "--server", SERVER])
    assert raised.value.code == 2


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_an_unreachable_server_is_invalid_input(monkeypatch):
    def refuse(url, timeout):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(preflight.urllib.request, "urlopen", refuse)
    with pytest.raises(SystemExit) as raised:
        preflight.fetch_agents(SERVER, 1.0)
    assert raised.value.code == 2


@pytest.mark.parametrize("body", [b"[]", b'{"agents": {}}', b'{"agents": [1, 2]}', b"nu e json"])
def test_a_response_of_another_shape_is_invalid_input(monkeypatch, body):
    monkeypatch.setattr(preflight.urllib.request, "urlopen", lambda url, timeout: _Response(body))
    with pytest.raises(SystemExit) as raised:
        preflight.fetch_agents(SERVER, 1.0)
    assert raised.value.code == 2


def test_the_registry_is_read_from_api_agents(monkeypatch):
    seen = {}

    def answer(url, timeout):
        seen["url"] = url
        return _Response(json.dumps({"count": 1, "agents": [_agent(1)]}).encode("utf-8"))

    monkeypatch.setattr(preflight.urllib.request, "urlopen", answer)
    agents = preflight.fetch_agents(SERVER + "/", 1.0)

    assert seen["url"] == SERVER + "/api/agents"
    assert [a["agent_id"] for a in agents] == ["endpoint01-abc1"]
