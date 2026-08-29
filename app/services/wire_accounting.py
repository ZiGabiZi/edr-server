"""
Contabilizarea octeților primiți, pe încarnare, și reconcilierea cu ce declară agentul.
=======================================================================================

Ce măsoară:
    Câți octeți de corp a primit efectiv serverul de la fiecare încarnare a
    fiecărui agent, și cât declară agentul însuși că a pus pe fir. Cele două
    cifre nu vin din aceeași sursă și tocmai de aceea au valoare împreună:
    contractul (contracts/METRICS.md §7) cere ca numărătorul afirmației
    centrale să fie **măsurat**, iar reconcilierea să fie o proprietate
    verificabilă, nu o verificare internă.

De ce pe încarnare, nu pe agent:
    Contoarele agentului repornesc de la zero la fiecare pornire, prin
    construcție — registrul lui e per încarnare. Cu o cheie doar pe `agent_id`,
    fiecare restart ar arăta ca un total raportat prăbușit la zero lângă un
    total măsurat care crește: exact direcția gravă din §7.2, declanșată de o
    repornire perfect normală. Cheia `(agent_id, agent_instance_id)` face
    resetul așteptat și atribuibil, la fel ca detecția de repornire prin
    schimbarea încarnării de la heartbeat.

De ce nimic nu se pierde:
    Un octet primit și necontabilizat e mai rău decât unul contabilizat greșit,
    pentru că nu se vede. Orice cerere cu corp intră undeva:

        - atribuită unei încarnări, când cheia e cunoscută și antetul de
          încarnare e prezent;
        - în găleata de neatribuibil, cu MOTIVUL păstrat, altfel;
        - la mesaje fără dimensiune declarată, când nu există `Content-Length`.

    Motivul contează cel puțin cât cifra. `unknown_key` e traficul unui agent cu
    cheie greșită sau revocată — cel mai interesant din tot ce trece pe aici, și
    singurul care nu ajunge niciodată la o rută. Contopit cu `no_instance`, care
    e o consecință structurală cunoscută a payload-ului de înregistrare
    (edr-agent#19), n-ar mai spune nimic despre niciunul.
"""

from dataclasses import dataclass, field, replace
from threading import Lock
from typing import Any, Dict, Optional, Tuple


# Motivele pentru care octeții primiți nu pot fi puși pe seama unei încarnări.
#
# Sunt patru stări diferite ale lumii, nu patru fațete ale aceleiași:
UNATTRIBUTABLE_NO_KEY = "no_key"              # cerere fără antet de cheie
UNATTRIBUTABLE_UNKNOWN_KEY = "unknown_key"    # cheie prezentă, nerecunoscută
UNATTRIBUTABLE_NO_INSTANCE = "no_instance"    # agent cunoscut, încarnare nedeclarată
UNATTRIBUTABLE_UNSIZED = "unsized"            # corp fără Content-Length

UNATTRIBUTABLE_REASONS = (
    UNATTRIBUTABLE_NO_KEY,
    UNATTRIBUTABLE_UNKNOWN_KEY,
    UNATTRIBUTABLE_NO_INSTANCE,
    UNATTRIBUTABLE_UNSIZED,
)


@dataclass(frozen=True)
class IncarnationAccount:
    """
    Ce știe serverul despre o încarnare: ce a măsurat și ce i s-a declarat.

    `received_bytes_at_last_report` e câmpul care face reconcilierea posibilă și
    e ușor de omis. Anteturile agentului poartă totalul de dinaintea cererii
    curente (§7.1, ruperea circularității), deci raportul sosit odată cu mesajul
    N descrie mesajele 1..N-1. Comparat cu totalul măsurat DUPĂ ce s-a adunat
    mesajul N, ar ieși mereu o diferență egală cu mesajul curent — o discrepanță
    fabricată de propria noastră ordine de operații.

    Câmpul reține deci cât măsurase serverul exact în clipa în care raportul a
    sosit, adică perechea corectă de comparat.
    """

    received_bytes: int = 0
    received_messages: int = 0
    reported_attempted_bytes: Optional[int] = None
    reported_delivered_bytes: Optional[int] = None
    received_bytes_at_last_report: Optional[int] = None
    malformed_reports: int = 0


@dataclass(frozen=True)
class UnattributableCounters:
    messages: int = 0
    bytes: int = 0


@dataclass
class _Store:
    incarnations: Dict[Tuple[str, str], IncarnationAccount] = field(default_factory=dict)
    unattributable: Dict[str, UnattributableCounters] = field(default_factory=dict)


_store = _Store()
_lock = Lock()


def parse_reported_bytes(raw: Optional[str]) -> Optional[int]:
    """
    Traduce un antet de raportare în număr, sau None dacă nu e unul.

    Antetele vin de la un client, deci pot lipsi, pot fi goale sau pot conține
    orice. Un raport nedescifrabil NU face cererea neatribuibilă: octeții ei tot
    au fost primiți și tot aparțin încarnării. Se pierde doar raportul, iar
    faptul că s-a pierdut se numără separat (`malformed_reports`), ca un client
    stricat să se vadă ca atare, nu ca o discrepanță inexplicabilă.

    Negativele se refuză: un total raportat negativ n-are interpretare, iar
    acceptat ar putea trage discrepanța în direcția care flatează agentul.
    """
    if raw is None:
        return None

    try:
        value = int(raw.strip())
    except (ValueError, AttributeError):
        return None

    if value < 0:
        return None

    return value


def record_attributed(
    agent_id: str,
    agent_instance_id: str,
    byte_count: int,
    reported_attempted: Optional[int] = None,
    reported_delivered: Optional[int] = None,
    report_present: bool = False,
) -> None:
    """
    Contabilizează o cerere pusă pe seama unei încarnări.

    ORDINEA din interior e partea care contează: raportul se reține împreună cu
    totalul măsurat **de dinaintea** acestei cereri, iar abia apoi se adaugă
    octeții ei. Invers, fiecare comparație ar arăta o diferență egală cu mesajul
    curent (vezi IncarnationAccount).

    `report_present` spune că agentul a trimis anteturi de raportare, chiar dacă
    nu s-au putut citi. Fără el, un client care trimite gunoi n-ar fi deosebit de
    unul care nu raportează deloc — primul e un bug de reparat, al doilea e un
    agent vechi.
    """
    key = (agent_id, agent_instance_id)

    with _lock:
        account = _store.incarnations.get(key, IncarnationAccount())

        if reported_attempted is not None or reported_delivered is not None:
            account = replace(
                account,
                reported_attempted_bytes=(
                    reported_attempted
                    if reported_attempted is not None
                    else account.reported_attempted_bytes
                ),
                reported_delivered_bytes=(
                    reported_delivered
                    if reported_delivered is not None
                    else account.reported_delivered_bytes
                ),
                received_bytes_at_last_report=account.received_bytes,
            )
        elif report_present:
            account = replace(
                account, malformed_reports=account.malformed_reports + 1
            )

        _store.incarnations[key] = replace(
            account,
            received_bytes=account.received_bytes + byte_count,
            received_messages=account.received_messages + 1,
        )


def record_unattributable(reason: str, byte_count: int = 0) -> None:
    """
    Contabilizează octeți primiți care nu se pot pune pe seama nimănui.

    Un motiv necunoscut ridică ValueError în loc să deschidă tăcut o găleată
    nouă: motivele sunt alese din cod, dintr-o mulțime închisă, deci o valoare
    nouă e un bug, nu o stare de rulare. Aceeași regulă ca la canalele
    registrului de pe agent.

    La `unsized`, `byte_count` e zero pentru că dimensiunea nu e cunoscută — NU
    pentru că ar fi zero. De asta are motiv propriu: numărul de mesaje se vede,
    iar cine citește raportul știe că acolo lipsesc octeți, în loc să creadă că
    nu erau.
    """
    if reason not in UNATTRIBUTABLE_REASONS:
        raise ValueError(
            f"Motiv de neatribuire necunoscut: {reason!r}. "
            f"Motivele valide sunt {UNATTRIBUTABLE_REASONS}."
        )

    if byte_count < 0:
        raise ValueError(f"Numar de octeti negativ la neatribuit: {byte_count}.")

    with _lock:
        current = _store.unattributable.get(reason, UnattributableCounters())
        _store.unattributable[reason] = UnattributableCounters(
            messages=current.messages + 1,
            bytes=current.bytes + byte_count,
        )


def snapshot() -> Dict[str, Any]:
    """
    Fotografie coerentă a contabilității, luată sub lacăt.

    Toate motivele de neatribuire apar, inclusiv cele cu zero. Un zero afirmat e
    verificabil; o cheie lipsă nu se distinge de un motiv care n-a fost niciodată
    implementat.
    """
    with _lock:
        incarnations = dict(_store.incarnations)
        unattributable = dict(_store.unattributable)

    return {
        "incarnations": [
            {
                "agent_id": agent_id,
                "agent_instance_id": agent_instance_id,
                "received_bytes": account.received_bytes,
                "received_messages": account.received_messages,
                "reported_attempted_bytes": account.reported_attempted_bytes,
                "reported_delivered_bytes": account.reported_delivered_bytes,
                "received_bytes_at_last_report": account.received_bytes_at_last_report,
                "malformed_reports": account.malformed_reports,
            }
            for (agent_id, agent_instance_id), account in sorted(incarnations.items())
        ],
        "unattributable": {
            reason: {
                "messages": unattributable.get(reason, UnattributableCounters()).messages,
                "bytes": unattributable.get(reason, UnattributableCounters()).bytes,
            }
            for reason in UNATTRIBUTABLE_REASONS
        },
    }


def account_for(agent_id: str, agent_instance_id: str) -> Optional[IncarnationAccount]:
    """Contul unei încarnări, sau None dacă n-a trimis niciodată nimic."""
    with _lock:
        return _store.incarnations.get((agent_id, agent_instance_id))


def reset_for_tests() -> None:
    """
    Golește contabilitatea între teste.

    Contabilitatea e stare de proces, ca `agents_store` și `events_store`: fără
    golire, cifrele unei rulări de test s-ar aduna peste ale următoarei, iar
    testele ar trece sau ar cădea în funcție de ordinea în care rulează.
    """
    with _lock:
        _store.incarnations.clear()
        _store.unattributable.clear()
