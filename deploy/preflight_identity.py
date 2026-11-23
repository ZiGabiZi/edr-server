"""
Verificarea identitatii clonelor, inainte sa se deschida eticheta de rulare.

O eticheta de rulare nu se redeschide, deci o rulare pornita cu clone care se
contopesc pe server e pierduta. Scriptul raspunde, inainte de POST /api/runs,
la o singura intrebare: vede serverul exact N masini distincte?

Sursa e registrul serverului, GET /api/agents, citit dupa ce agentii au pornit
si s-au inregistrat (pe rand, daca gazda nu le tine pe toate deodata), dar
INAINTE de deschiderea rularii. Registrul tine minte si agentii opriti, pana la
repornirea serverului.

Exemplu:

    python deploy/preflight_identity.py --server http://192.168.16.10:8000 --expected 5

Cod de iesire: 0 = se poate deschide rularea, 1 = cel putin o problema
blocanta, 2 = intrare invalida. Avertismentele nu schimba codul.

Doar biblioteca standard: scriptul trebuie sa mearga pe VM fara .venv.

Ce ramura din register_agent prinde fiecare verificare:
    - acelasi machine_id_hash cu agent_id diferit -> ramura pe machine_id_hash:
      inregistrarile se scot una pe alta din registru (ping-pong, 404-uri,
      retransmisii in numarator); se vede ca registration_status =
      updated_by_machine_id sau ca hash dublat;
    - acelasi agent_id (fisier agent_id copiat) -> ramura pe agent_id:
      contopire tacuta, N masini devin un singur agent; se vede ca un numar
      de agenti mai mic decat --expected.

Inainte exista si un mod --reports, care compara rapoarte scrise pe fiecare
clona de o unealta din agent. Unealta n-a fost publicata, iar ambele tururi de
identitate ale masuratorii au folosit doar registrul, deci modul a fost scos.
"""

import argparse
import json
import sys
import urllib.error
import urllib.request
from collections import defaultdict

# Starile in care un agent trimite heartbeat-uri, deci probabil si evenimente
# (agent_service._derive_status: unknown, online, degraded, offline).
ACTIVE_STATUSES = frozenset({"online", "degraded"})


class Findings:
    def __init__(self):
        self.failures = []
        self.warnings = []

    def fail(self, message):
        self.failures.append(message)

    def warn(self, message):
        self.warnings.append(message)


def _duplicates(items, key):
    groups = defaultdict(list)
    for item in items:
        value = key(item)
        if value:
            groups[value].append(item)
    return {value: group for value, group in groups.items() if len(group) > 1}


def _names(group):
    return ", ".join(sorted(str(item.get("hostname")) for item in group))


def fetch_agents(server_url, timeout):
    url = server_url.rstrip("/") + "/api/agents"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError) as error:
        print(f"GET {url} a esuat: {error}", file=sys.stderr)
        raise SystemExit(2)
    agents = payload.get("agents") if isinstance(payload, dict) else None
    if not isinstance(agents, list) or not all(isinstance(a, dict) for a in agents):
        print(f"GET {url}: raspunsul nu are forma {{'agents': [ {{...}} ]}}", file=sys.stderr)
        raise SystemExit(2)
    return agents


def check_server(agents, expected, findings):
    for agent in agents:
        if agent.get("registration_status") == "updated_by_machine_id":
            findings.fail(
                f"server: {agent.get('agent_id')} a preluat identitatea altui agent_id "
                "(registration_status=updated_by_machine_id). Doua masini cu acelasi MachineGuid."
            )

    for hash_value, group in _duplicates(agents, lambda a: a.get("machine_id_hash")).items():
        findings.fail(f"server: acelasi machine_id_hash ({hash_value[:12]}...) pe: {_names(group)}")

    if expected is not None and len(agents) != expected:
        findings.fail(f"server: {len(agents)} agenti in registru, asteptati {expected}")

    for agent in agents:
        if agent.get("status") != "online":
            findings.warn(f"server: {agent.get('agent_id')} are status {agent.get('status')}")

    # Masuratoarea porneste clonele pe rand, deci cati agenti sunt activi
    # acum se declara, dar nu blocheaza.
    active = sorted(a.get("agent_id") for a in agents if a.get("status") in ACTIVE_STATUSES)
    findings.warn(
        f"server: {len(active)} agent(i) activi in registru"
        + (f": {', '.join(active)}" if active else "")
    )


def print_table(title, rows, columns):
    print(f"\n{title}")
    if not rows:
        print("  (nimic)")
        return
    widths = [max(len(c), *(len(str(r.get(c) or "-")) for r in rows)) for c in columns]
    print("  " + "  ".join(c.ljust(w) for c, w in zip(columns, widths)))
    for row in rows:
        print("  " + "  ".join(str(row.get(c) or "-").ljust(w) for c, w in zip(columns, widths)))


def main(argv=None):
    # __doc__ e None sub python -OO, iar Pylance il tipeaza str | None.
    description = __doc__.strip().splitlines()[0] if __doc__ else None
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--server", required=True, help="URL-ul serverului, ex. http://192.168.16.10:8000")
    parser.add_argument("--expected", type=int, help="numarul de clone asteptat")
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args(argv)

    findings = Findings()

    agents = fetch_agents(args.server, args.timeout)
    for agent in agents:
        agent["hash"] = (agent.get("machine_id_hash") or "")[:12]
    print_table(
        "Registrul serverului",
        agents,
        ["agent_id", "hostname", "hash", "registration_status", "status"],
    )
    check_server(agents, args.expected, findings)

    print()
    for message in findings.warnings:
        print(f"AVERTISMENT  {message}")
    for message in findings.failures:
        print(f"BLOCANT      {message}")

    if findings.failures:
        print(f"\nNU deschide rularea: {len(findings.failures)} problema(e) blocanta(e).")
        return 1

    print("\nOK: identitati distincte, rularea se poate deschide.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
