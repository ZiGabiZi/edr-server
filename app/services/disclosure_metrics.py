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
    - CONȚINUT divulgat: octeți de fișier care au părăsit endpoint-ul, însumați
      din blocul `disclosure` al evenimentelor. La T0 și T1 suma e zero — dar
      prin invarianta de schemă (app/schemas/event.py::EventDisclosure) și prin
      verificarea geamănă de pe agent, nu prin presupunerea codului de aici.
      Garda pe forma numelui
      (test_event_hash_contract.py::test_event_model_never_carries_file_content)
      apără o graniță vecină, nu aceasta: ea interzice modelului de eveniment să
      DECLARE un câmp care ar transporta conținut — inclusiv în modelele
      imbricate, cu `disclosure.content_bytes` scutit explicit, pentru că e un
      contor de octeți, nu un transportor de octeți.
    - METADATE: octeții evenimentelor înseși. Nu sunt gratuite și nu au voie să
      fie ascunse: canalul de evenimente circulă la FIECARE fișier atins, nu
      doar la cele escaladate. O metrică ce ar raporta doar „zero conținut" ar
      fi adevărată și înșelătoare în același timp.

Numitorul include plicul (contracts/METRICS.md §2):
    Un sistem always-upload nu trimite fișiere goale: trimite fișierul PLUS
    aceleași metadate de identificare. Numitorul e deci `conținut + plic`, cu
    exact plicul evenimentelor care intră în el. Corecția merge aparent în
    defavoarea protocolului — raportul devine `plic / (plic + conținut)` în loc
    de `plic / conținut` — și tocmai de aceea apără afirmația: nimeni nu poate
    susține că numitorul a fost umflat.

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

    Al doilea gol, de altă natură, e cel de ATRIBUIRE: evenimente care au
    divulgat ceva fără să poată fi puse pe o treaptă. Octeții lor intră
    întotdeauna în numărător — un octet plecat a plecat — dar nu în tabelul pe
    trepte, iar diferența se raportează, nu se topește în el.
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


def _content_bytes(event: Dict[str, Any]) -> int:
    """Octeții de conținut declarați de blocul `disclosure`, zero dacă lipsește."""
    disclosure = event.get("disclosure") or {}

    return int(disclosure.get("content_bytes") or 0)


def _payload_bytes(event: Dict[str, Any]) -> int:
    """
    Costul de metadate al unui eveniment, aproximat prin serializarea lui JSON.

    Aproximare, și se spune: pe fir mai intervin anteturile HTTP și eventuala
    compresie, iar evenimentul stocat poartă câmpuri adăugate de server
    (event_id, received_at, status) care nu au traversat rețeaua. Ordinul de
    mărime e însă corect, iar el e tot ce cere comparația cu un numitor de
    ordinul megaocteților.

    Numărătorul MĂSURAT cerut de contracts/METRICS.md §7 — octeți raportați de
    agent și reconciliați aici, cu discrepanța agent↔server ca metrică proprie
    — nu există încă. E jumătatea 1.3b, rămasă deschisă după ce 1.3a a adus
    blocul `disclosure`; până atunci, orice cifră publicată de aici se declară
    ca estimare, nu ca măsurătoare.
    """
    return len(json.dumps(event, ensure_ascii=False, default=str).encode("utf-8"))


def compute_disclosure_metrics(
    events: Iterable[Dict[str, Any]],
    agent_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Calculează metrica peste evenimentele date, opțional pentru un singur agent.

    Returnează un dicționar cu următoarele secțiuni:
        scope          — agentul pentru care s-a calculat, sau toți
        always_upload  — numitorul: conținut + plic, ce ar fi plecat integral
        progressive    — numărătorul: ce a plecat efectiv
        ratio          — raportul lor, None când numitorul e gol
        by_tier        — atribuirea pe trepte (METRICS.md §3.4)
        unmeasured     — golul, ca subestimarea și neatribuirea să fie vizibile
    """
    file_events: List[Dict[str, Any]] = []
    file_event_envelope_bytes: List[int] = []
    metadata_bytes = 0

    # Atribuirea pe trepte (METRICS.md §3.4). Numitorul tabelului nu e mulțimea
    # tuturor evenimentelor, ci a celor care poartă o treaptă — evenimentele de
    # ciclu de viață nu sunt pe scară și nu au ce căuta acolo. Cele de fișier
    # fără treaptă sunt însă un gol declarat, nu o absență normală: ele au
    # divulgat metadate pe care tabelul nu le poate atribui.
    by_tier: Dict[str, Dict[str, int]] = {}
    disclosed_content_bytes = 0
    file_events_without_tier = 0
    disclosure_outside_file_events = 0

    for event in events:
        if agent_id is not None and event.get("agent_id") != agent_id:
            continue

        # Metadatele se numără pentru TOATE evenimentele, nu doar pentru cele de
        # fișier: heartbeat-urile nu trec pe aici, dar agent_startup, _shutdown
        # și _restart da, iar ele au traversat aceeași rețea.
        envelope_bytes = _payload_bytes(event)
        metadata_bytes += envelope_bytes

        # Conținutul se adună ÎNAINTE de orice ramificație pe treaptă. Un octet
        # care a părăsit endpoint-ul a plecat indiferent dacă știm cărei trepte
        # să-l atribuim; scos din numărător pentru că atribuirea lipsește, ar
        # face metrica să mintă exact în direcția care flatează afirmația.
        disclosed_content_bytes += _content_bytes(event)

        if not _is_file_event(event):
            # Bicondiționalitatea `disclosure <=> file_path` nu e validator (ar
            # șterge evenimente din spool ca poison messages), deci un bloc
            # apărut pe un eveniment care nu e de fișier ajunge până aici.
            # Octeții lui sunt deja în numărător; în tabelul pe trepte n-au voie
            # să intre, pentru că i-ar strica exact numitorul declarat la §3.4.
            if event.get("disclosure"):
                disclosure_outside_file_events += 1
            continue

        file_events.append(event)
        file_event_envelope_bytes.append(envelope_bytes)

        tier = (event.get("disclosure") or {}).get("tier")

        if not tier:
            file_events_without_tier += 1
            continue

        bucket = by_tier.setdefault(tier, {"events": 0, "content_bytes": 0})
        bucket["events"] += 1
        bucket["content_bytes"] += _content_bytes(event)

    hashed: List[Dict[str, Any]] = []
    always_upload_envelope_bytes = 0
    unmeasured: Dict[str, int] = {}

    for event, envelope_bytes in zip(file_events, file_event_envelope_bytes):
        if event.get("hash_status") == _HASHED_OK and event.get("file_size") is not None:
            hashed.append(event)
            # Plicul care intră în numitor e exact plicul evenimentului care
            # intră în el: un sistem always-upload ar fi trimis același mesaj de
            # identificare, plus fișierul.
            always_upload_envelope_bytes += envelope_bytes
        else:
            status = event.get("hash_status") or "absent"
            unmeasured[status] = unmeasured.get(status, 0) + 1

    always_upload_content_bytes = sum(int(event["file_size"]) for event in hashed)
    always_upload_bytes = always_upload_content_bytes + always_upload_envelope_bytes
    distinct_hashes = {event.get("sha256") for event in hashed if event.get("sha256")}

    # Diferența dintre conținutul divulgat și cel atribuit unei trepte. Derivată,
    # nu numărată separat: două acumulatoare pentru aceeași mărime se pot
    # despărți în timp, o scădere nu.
    tiered_content_bytes = sum(bucket["content_bytes"] for bucket in by_tier.values())
    content_bytes_without_tier = disclosed_content_bytes - tiered_content_bytes

    total_sent = disclosed_content_bytes + metadata_bytes

    return {
        "scope": agent_id or "toti agentii",
        "always_upload": {
            "file_events_with_size": len(hashed),
            "content_bytes": always_upload_content_bytes,
            "envelope_bytes": always_upload_envelope_bytes,
            "bytes": always_upload_bytes,
            "distinct_hashes": len(distinct_hashes),
            "note": (
                "Numitorul e continut + plic (METRICS.md §2): un sistem "
                "always-upload nu trimite fisiere goale, ci fisierul plus "
                "aceleasi metadate de identificare."
            ),
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
        "by_tier": {
            "events_with_tier": sum(b["events"] for b in by_tier.values()),
            "tiers": {
                tier: dict(by_tier[tier]) for tier in sorted(by_tier)
            },
            "note": (
                "Procentele pe trepte se raporteaza la events_with_tier, nu la "
                "totalul evenimentelor: evenimentele de ciclu de viata nu sunt "
                "pe scara de divulgare si nu au treapta prin proiectare."
            ),
        },
        "unmeasured": {
            "file_events_without_size": sum(unmeasured.values()),
            "by_hash_status": dict(sorted(unmeasured.items())),
            "file_events_without_tier": file_events_without_tier,
            "disclosure_outside_file_events": disclosure_outside_file_events,
            "content_bytes_without_tier": content_bytes_without_tier,
            "note": (
                "Fisierele fara hash reusit nu au file_size, deci nu intra in "
                "numitor. Sub always-upload ar fi fost totusi urcate: numitorul "
                "e o subestimare, iar raportul e prin urmare pesimist. "
                "file_events_without_tier numara separat evenimentele de fisier "
                "care au divulgat metadate fara sa poata fi atribuite unei "
                "trepte — gol de atribuire, nu de dimensiune. "
                "disclosure_outside_file_events numara blocurile aparute pe "
                "evenimente care nu sunt de fisier, adica incalcari ale "
                "bicondiționalitatii. content_bytes_without_tier sunt octetii "
                "de continut din ambele categorii: intra in numarator, dar nu "
                "in tabelul pe trepte."
            ),
        },
    }
