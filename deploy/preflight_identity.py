"""
Verificarea identitatii clonelor, inainte sa se deschida eticheta de rulare.

O eticheta de rulare nu se redeschide, deci o rulare pornita cu clone care se
contopesc pe server e pierduta. Scriptul raspunde, inainte de POST /api/runs,
la o singura intrebare: vede serverul exact N masini distincte?

Doua surse, oricare sau amandoua:

    --reports DIR   rapoartele identity-*.json scrise pe fiecare clona de
                    edr-agent/tools/identity_report.py (agentii opriti);
    --server URL    registrul serverului, GET /api/agents, dupa ce agentii au
                    pornit si s-au inregistrat, dar INAINTE de deschiderea rularii.

Exemple:

    python deploy/preflight_identity.py --reports preflight --expected 5
    python deploy/preflight_identity.py --server http://192.168.16.10:8000 --expected 5
    python deploy/preflight_identity.py --reports preflight --server http://192.168.16.10:8000 --expected 5

Cod de iesire: 0 = se poate deschide rularea, 1 = cel putin o problema
blocanta, 2 = intrare invalida. Avertismentele nu schimba codul.

Doar biblioteca standard: scriptul trebuie sa mearga pe VM fara .venv.

Ce ramura din register_agent prinde fiecare verificare:
    - acelasi machine_id_hash cu agent_id diferit -> ramura pe machine_id_hash:
      inregistrarile se scot una pe alta din registru (ping-pong, 404-uri,
      retransmisii in numarator);
    - acelasi agent_id (fisier agent_id copiat) -> ramura pe agent_id:
      contopire tacuta, N masini devin un singur agent;
    - aceeasi agent_key copiata -> cheia e legata de un singur agent_id,
      celelalte clone primesc 403 la inregistrare.
"""

import argparse
import json
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path

GUID_TYPE = "windows_machine_guid"

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


def load_reports(directory):
    reports = []
    for path in sorted(Path(directory).glob("identity-*.json")):
        try:
            report = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError) as error:
            print(f"Raport ilizibil {path}: {error}", file=sys.stderr)
            raise SystemExit(2)
        # JSON valid nu inseamna raport: o lista sau un numar ar cadea mai jos
        # cu TypeError si traceback, nu cu codul 2 al intrarii invalide.
        if not isinstance(report, dict):
            print(
                f"Raport invalid {path}: astept un obiect JSON, am primit "
                f"{type(report).__name__}",
                file=sys.stderr,
            )
            raise SystemExit(2)
        report["_file"] = path.name
        reports.append(report)
    return reports


def check_reports(reports, expected, findings):
    if expected is not None and len(reports) != expected:
        findings.fail(f"rapoarte: {len(reports)} gasite, asteptate {expected}")

    for (hash_value, _), group in _duplicates(
        reports, lambda r: (r.get("machine_id_hash"), r.get("machine_id_type"))
        if r.get("machine_id_hash") else None
    ).items():
        findings.fail(
            f"acelasi machine_id_hash ({hash_value[:12]}...) pe: {_names(group)}. "
            "Clonele au acelasi MachineGuid; serverul le va scoate una pe alta din registru."
        )

    for agent_id, group in _duplicates(reports, lambda r: r.get("agent_id_effective")).items():
        sources = ", ".join(sorted({str(r.get("agent_id_source")) for r in group}))
        findings.fail(
            f"acelasi agent_id '{agent_id}' (sursa: {sources}) pe: {_names(group)}. "
            "Serverul le va contopi tacut intr-un singur agent."
        )

    for fingerprint, group in _duplicates(reports, lambda r: r.get("agent_key_fingerprint")).items():
        findings.fail(
            f"aceeasi agent_key (amprenta {fingerprint}) pe: {_names(group)}. "
            "Cheia a fost copiata intre clone."
        )

    for hostname_part, group in _duplicates(reports, lambda r: r.get("hostname_part")).items():
        findings.fail(f"acelasi hostname '{hostname_part}' pe rapoartele: "
                      + ", ".join(r["_file"] for r in group))

    for report in reports:
        name = report.get("hostname")

        if report.get("machine_id_type") != GUID_TYPE:
            findings.warn(
                f"{name}: identitatea vine din {report.get('machine_id_type')}, nu din MachineGuid"
            )

        if report.get("agent_id_source") == "derived_random":
            findings.warn(f"{name}: niciun identificator stabil, agent_id va fi aleator")

        frozen = report.get("agent_id_frozen")
        expected_id = report.get("agent_id_expected_from_machine")
        if frozen and expected_id and frozen != expected_id:
            findings.warn(
                f"{name}: fisierul agent_id contine '{frozen}', masina ar deriva "
                f"'{expected_id}' (copiat de pe alta masina sau redenumita dupa inrolare)"
            )

        if report.get("agent_id_configured"):
            findings.warn(
                f"{name}: agent_id fixat in config.json ('{report['agent_id_configured']}'); "
                "config.json e fisierul copiat intre masini"
            )

        if report.get("spool_present"):
            findings.warn(
                f"{name}: event_spool.db exista ({report.get('spool_bytes')} octeti). "
                "Daca a venit odata cu imaginea, agentul retrimite evenimentele altei masini."
            )


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


def check_server(agents, reports, expected, findings):
    for agent in agents:
        if agent.get("registration_status") == "updated_by_machine_id":
            findings.fail(
                f"server: {agent.get('agent_id')} a preluat identitatea altui agent_id "
                "(registration_status=updated_by_machine_id). Doua masini cu acelasi MachineGuid."
            )

    for hash_value, group in _duplicates(agents, lambda a: a.get("machine_id_hash")).items():
        findings.fail(f"server: acelasi machine_id_hash ({hash_value[:12]}...) pe: {_names(group)}")

    by_id = {agent.get("agent_id"): agent for agent in agents}

    if reports:
        wanted = {r.get("agent_id_effective"): r for r in reports if r.get("agent_id_effective")}
        for agent_id, report in sorted(wanted.items()):
            agent = by_id.get(agent_id)
            if agent is None:
                findings.fail(f"server: {agent_id} ({report.get('hostname')}) nu e in registru")
                continue
            if agent.get("machine_id_hash") != report.get("machine_id_hash"):
                findings.fail(
                    f"server: {agent_id} e inregistrat cu alt machine_id_hash decat raportul clonei"
                )
            if agent.get("status") != "online":
                findings.warn(f"server: {agent_id} are status {agent.get('status')}")
        # Un agent din registru fara raport. Oprit, e o inregistrare veche, care
        # ramane in registru pana la repornirea serverului: avertisment. ACTIV
        # (online sau degraded), trimite evenimente pe care niciun raport nu le
        # garanteaza — de exemplu o clona readusa la instantaneul vechi — si
        # le-ar trimite in rularea cu nume: blocant.
        for agent_id in sorted(set(by_id) - set(wanted)):
            agent = by_id[agent_id]
            where = f"server: {agent_id} ({agent.get('hostname')}) e in registru, dar nu printre rapoarte"
            if agent.get("status") in ACTIVE_STATUSES:
                findings.fail(
                    f"{where}, si e {agent.get('status')}: ar trimite evenimente in rularea cu nume"
                )
            else:
                findings.warn(f"{where} (status {agent.get('status')})")

        # --expected s-a comparat cu rapoartele; registrul se declara separat.
        # Nu e blocant: masuratoarea porneste clonele pe rand, deci mai putini
        # agenti activi decat clone e starea normala.
        active = sorted(a for a, agent in by_id.items() if agent.get("status") in ACTIVE_STATUSES)
        findings.warn(
            f"server: {len(active)} agent(i) activi in registru"
            + (f", din {expected} clone asteptate" if expected is not None else "")
            + (f": {', '.join(active)}" if active else "")
        )
    else:
        if expected is not None and len(agents) != expected:
            findings.fail(f"server: {len(agents)} agenti in registru, asteptati {expected}")
        for agent in agents:
            if agent.get("status") != "online":
                findings.warn(f"server: {agent.get('agent_id')} are status {agent.get('status')}")


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
    parser.add_argument("--reports", type=Path, help="director cu identity-*.json")
    parser.add_argument("--server", help="URL-ul serverului, ex. http://192.168.16.10:8000")
    parser.add_argument("--expected", type=int, help="numarul de clone asteptat")
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args(argv)

    if not args.reports and not args.server:
        parser.print_usage(sys.stderr)
        print("Trebuie cel putin --reports sau --server.", file=sys.stderr)
        return 2
    if args.reports and not args.reports.is_dir():
        print(f"{args.reports} nu e un director.", file=sys.stderr)
        return 2

    findings = Findings()
    reports = []

    if args.reports:
        reports = load_reports(args.reports)
        for report in reports:
            report["hash"] = (report.get("machine_id_hash") or "")[:12]
            report["key"] = report.get("agent_key_fingerprint")
        print_table(
            "Rapoarte de pe clone",
            reports,
            ["hostname", "machine_id_type", "hash", "agent_id_effective", "agent_id_source", "key"],
        )
        check_reports(reports, args.expected, findings)

    if args.server:
        agents = fetch_agents(args.server, args.timeout)
        for agent in agents:
            agent["hash"] = (agent.get("machine_id_hash") or "")[:12]
        print_table(
            "Registrul serverului",
            agents,
            ["agent_id", "hostname", "hash", "registration_status", "status"],
        )
        check_server(agents, reports, args.expected, findings)

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
