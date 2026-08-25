"""
Metrica de divulgare: cât a costat observarea, față de a trimite tot.
=====================================================================

Ce măsoară:
    Protocolul de divulgare progresivă pornește de la premisa că un EDR nu are
    nevoie de conținutul fiecărui fișier atins ca să spună ceva despre el.
    Treapta T0 trimite doar o amprentă SHA-256 și metadate. Metrica de față
    compară costul acela cu alternativa naivă — un sistem care urcă fiecare
    fișier observat, ca să poată decide pe server.

    Numărătorul e ce a plecat efectiv de pe endpoint. Numitorul e ce ar fi
    plecat sub always-upload. Raportul lor e afirmația centrală, exprimată în
    octeți, nu în adjective.

De ce trăiește aici și nu se calculează retroactiv:
    contracts/wire-contract.json impune file_size obligatoriu când
    hash_status == 'ok', tocmai pentru că e numărătorul acestei metrici și „nu
    se poate reconstrui retroactiv dacă fișierul s-a schimbat". Invarianta a
    fost impusă din v3; funcția asta e primul loc care o și folosește.

Cele două costuri, ținute separat deliberat:
    - CONȚINUT divulgat: octeți de fișier care au părăsit endpoint-ul. La T0
      este zero prin construcție — niciun câmp al modelului de eveniment nu
      poate purta conținut, garda fiind pe forma numelui, nu pe o listă fixă
      (test_event_contract.py::test_event_model_never_carries_file_content).
    - METADATE: octeții evenimentelor înseși. Nu sunt gratuite și nu au voie să
      fie ascunse: canalul de evenimente circulă la FIECARE fișier atins, nu
      doar la cele escaladate. O metrică ce ar raporta doar „zero conținut" ar
      fi adevărată și înșelătoare în același timp.

Ce NU poate măsura, și de ce se raportează explicit:
    Un fișier fără hash reușit nu are file_size, deci nu poate intra în
    numitor. Sub always-upload ar fi fost totuși urcat, cu dimensiunea lui
    reală. Numitorul e prin urmare o SUBESTIMARE, iar mărimea golului se
    raportează pe statusuri, nu se rotunjește la zero.

    Distincția dintre statusuri contează aici mai mult decât oriunde:
    'unstable' spune că fișierul nu s-a liniștit, 'skipped_capacity' și
    'skipped_shutdown' spun că agentul era sub presiune sau se oprea. Primul e
    cost impus de obiectul observat, celelalte de observator. Contopite, nu s-ar
    mai putea spune care parte a golului e a metodei și care a implementării.
"""

import json
from typing import Any, Dict, Iterable, List, Optional


# Statusul în care amprenta a reușit, deci fișierul are dimensiune cunoscută.
_HASHED_OK = "ok"

# Câmpurile care descriu un fișier. Un eveniment fără niciunul (agent_startup,
# agent_shutdown, agent_restart) nu are ce căuta în metrică: nu corespunde
# niciunui fișier pe care un sistem always-upload l-ar fi urcat.
_FILE_MARKER = "file_path"


def _is_file_event(event: Dict[str, Any]) -> bool:
    return bool(event.get(_FILE_MARKER))


def _payload_bytes(event: Dict[str, Any]) -> int:
    """
    Costul de metadate al unui eveniment, aproximat prin serializarea lui JSON.

    Aproximare, și se spune: pe fir mai intervin anteturile HTTP și eventuala
    compresie, iar evenimentul stocat poartă câmpuri adăugate de server
    (event_id, received_at, status) care nu au traversat rețeaua. Ordinul de
    mărime e însă corect, iar el e tot ce cere comparația cu un numitor de
    ordinul megaocteților.
    """
    return len(json.dumps(event, ensure_ascii=False, default=str).encode("utf-8"))


def compute_disclosure_metrics(
    events: Iterable[Dict[str, Any]],
    agent_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Calculează metrica peste evenimentele date, opțional pentru un singur agent.

    Returnează un dicționar cu trei secțiuni:
        always_upload  — numitorul: ce ar fi plecat sub always-upload
        progressive    — numărătorul: ce a plecat efectiv
        unmeasured     — golul, pe statusuri, ca subestimarea să fie vizibilă
    """
    file_events: List[Dict[str, Any]] = []
    metadata_bytes = 0

    for event in events:
        if agent_id is not None and event.get("agent_id") != agent_id:
            continue

        # Metadatele se numără pentru TOATE evenimentele, nu doar pentru cele de
        # fișier: heartbeat-urile nu trec pe aici, dar agent_startup, _shutdown
        # și _restart da, iar ele au traversat aceeași rețea.
        metadata_bytes += _payload_bytes(event)

        if _is_file_event(event):
            file_events.append(event)

    hashed: List[Dict[str, Any]] = []
    unmeasured: Dict[str, int] = {}

    for event in file_events:
        if event.get("hash_status") == _HASHED_OK and event.get("file_size") is not None:
            hashed.append(event)
        else:
            status = event.get("hash_status") or "absent"
            unmeasured[status] = unmeasured.get(status, 0) + 1

    always_upload_bytes = sum(int(event["file_size"]) for event in hashed)
    distinct_hashes = {event.get("sha256") for event in hashed if event.get("sha256")}

    # Conținut divulgat la T0: zero, prin construcție. Nu e o constantă
    # optimistă — e o proprietate impusă de contract și verificată de test, iar
    # când canalul de escaladare (collect_file) va exista, aici va apărea suma
    # reală a fișierelor colectate.
    disclosed_content_bytes = 0

    total_sent = disclosed_content_bytes + metadata_bytes

    return {
        "scope": agent_id or "toti agentii",
        "always_upload": {
            "file_events_with_size": len(hashed),
            "bytes": always_upload_bytes,
            "distinct_hashes": len(distinct_hashes),
        },
        "progressive": {
            "content_bytes": disclosed_content_bytes,
            "metadata_bytes": metadata_bytes,
            "total_bytes": total_sent,
            "events_counted": len(file_events),
        },
        "ratio": {
            # Cât la sută din always-upload a costat divulgarea progresivă.
            # None, nu zero, când numitorul e gol: un raport fără numitor e o
            # afirmație fără suport, iar zero ar fi arătat ca un rezultat bun.
            "sent_over_always_upload": (
                round(total_sent / always_upload_bytes, 6)
                if always_upload_bytes
                else None
            ),
            "bytes_saved": always_upload_bytes - total_sent,
        },
        "unmeasured": {
            "file_events_without_size": sum(unmeasured.values()),
            "by_hash_status": dict(sorted(unmeasured.items())),
            "note": (
                "Fisierele fara hash reusit nu au file_size, deci nu intra in "
                "numitor. Sub always-upload ar fi fost totusi urcate: numitorul "
                "e o subestimare, iar raportul e prin urmare pesimist."
            ),
        },
    }
