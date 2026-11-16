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
    exact plicul evenimentelor care intră în el. Corecția mută raportul în
    FAVOAREA protocolului — `plic / (plic + conținut)` e mai mic decât
    `plic / conținut` — deci plicul din numitor nu are voie să fie nici cu un
    octet mai mare decât cel de la numărător.

    De aici regula riglei (edr-server#14): numărător măsurat ⟹ plicul din
    numitor e corpul de pe fir al fiecărui eveniment, consemnat de server la
    primire; numărător estimat ⟹ reserializarea. Până la #14 numitorul
    reserializa și sub numărătorul măsurat, iar evenimentul stocat e mai lung
    decât corpul trimis de agent — numitorul ieșea umflat, mai ales sub 2 KB.

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
from typing import Any, Dict, Iterable, List, Mapping, Optional


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


def _is_valid_size(value: Any) -> bool:
    """
    Dacă o dimensiune STOCATĂ poate intra în numitor: întreg nenegativ.

    Schema respinge de la v12 orice altceva (app/schemas/event.py), dar
    depozitul păstrează evenimente primite înainte de v12, când `-5000000`,
    `true` și `4096.0` primeau 200. `bool` se exclude explicit pentru că în
    Python e subclasă de `int`: `True` ar trece testul de tip și ar intra în
    numitor ca un octet.
    """
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _payload_bytes(event: Dict[str, Any]) -> int:
    """
    Costul de metadate al unui eveniment, aproximat prin serializarea lui JSON.

    Aproximare, și se spune: pe fir mai intervin anteturile HTTP și eventuala
    compresie, iar evenimentul stocat poartă câmpuri adăugate de server
    (event_id, received_at, run_id, status, reputation, prevalence) care nu au
    traversat rețeaua. Ordinul de mărime e corect, dar asta ajunge doar lângă
    un numitor de ordinul megaocteților: la fișiere sub 2 KB, câteva sute de
    octeți de plic în plus mută raportul vizibil.

    E numărătorul doar când măsurătoarea pe fir lipsește (`numerator_source:
    estimated`), și plicul din numitor doar în același caz: sub numărătorul
    măsurat, plicul vine din corpul consemnat la primire, nu de aici
    (edr-server#14). Altfel cele două părți ale raportului ar folosi rigle
    diferite, iar a numitorului ar fi mai lungă.
    """
    return len(json.dumps(event, ensure_ascii=False, default=str).encode("utf-8"))


def compute_disclosure_metrics(
    events: Iterable[Dict[str, Any]],
    agent_id: Optional[str] = None,
    measured_channel_bytes: Optional[int] = None,
    measured_channel_messages: Optional[int] = None,
    measured_envelope_bytes: Optional[Mapping[int, int]] = None,
) -> Dict[str, Any]:
    """
    Calculează metrica peste evenimentele date, opțional pentru un singur agent.

    `measured_envelope_bytes` e plicul de pe fir per eveniment, `event_id →
    octeți de corp`, consemnat de server la primire. Se folosește NUMAI când
    numărătorul e măsurat: rigla numitorului urmează numărătorul, nu datele
    care se întâmplă să fie la îndemână (edr-server#14).

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
    # Câte evenimente au contribuit la metadata_bytes. NU e len(file_events):
    # estimatorul numără și evenimentele de ciclu de viață, care au traversat
    # aceeași rețea. Cifra e numitorul confundătorului de la `calibration`.
    events_metered = 0
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
        events_metered += 1

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

    # Rigla se alege o singură dată, înaintea numitorului, din același test ca
    # numărătorul de mai jos. Două decizii separate s-ar putea despărți — exact
    # cum s-au despărțit numărătorul și numitorul între 0465c4b și c3f6c6d.
    numerator_is_measured = bool(measured_channel_bytes)
    wire_envelopes = measured_envelope_bytes or {}

    hashed: List[Dict[str, Any]] = []
    # Contribuția fiecărui eveniment la numitor, conținut plus plic, cu rigla
    # aleasă mai sus. Paralelă cu `hashed`, ca să se poată spune la final cât
    # din numitor vine de la un singur eveniment și de la fiecare agent.
    contributions: List[int] = []
    always_upload_envelope_bytes = 0
    unmeasured: Dict[str, int] = {}
    envelope_unmeasured = 0
    file_size_invalid = 0

    for event, envelope_bytes in zip(file_events, file_event_envelope_bytes):
        if event.get("hash_status") == _HASHED_OK and event.get("file_size") is not None:
            if not _is_valid_size(event["file_size"]):
                # Un eveniment stocat înainte de v12 cu o dimensiune pe care
                # schema de azi o respinge. Iese din numitor cu totul, ca un
                # plic nemăsurat, și se numără: lăsat înăuntru, un negativ
                # micșorează numitorul, iar un `true` îl crește cu un octet
                # inventat.
                file_size_invalid += 1
                continue

            if numerator_is_measured:
                # Numărătorul e corpul de pe fir, deci plicul din numitor e tot
                # corpul de pe fir. Un eveniment care nu-l are iese din numitor
                # cu totul, conținut și plic: completat cu reserializarea, ar
                # aduce înapoi exact octeții adăugați de server, iar raportul
                # ar flata din nou protocolul. Scos, numitorul scade și
                # raportul crește — subestimare a economiei, declarată.
                # Fără event_id nu există plic consemnat de căutat: același caz
                # ca un plic lipsă, nu o excepție.
                event_id = event.get("event_id")
                wire_envelope = (
                    wire_envelopes.get(event_id) if event_id is not None else None
                )

                if wire_envelope is None:
                    envelope_unmeasured += 1
                    continue

                envelope_bytes = wire_envelope

            hashed.append(event)
            contributions.append(event["file_size"] + envelope_bytes)
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
    concentration = _denominator_concentration(hashed, contributions, always_upload_bytes)

    # Diferența dintre conținutul divulgat și cel atribuit unei trepte. Derivată,
    # nu numărată separat: două acumulatoare pentru aceeași mărime se pot
    # despărți în timp, o scădere nu.
    tiered_content_bytes = sum(bucket["content_bytes"] for bucket in by_tier.values())
    content_bytes_without_tier = disclosed_content_bytes - tiered_content_bytes

    estimated_sent = disclosed_content_bytes + metadata_bytes

    # Numărătorul publicat: măsurat când există măsurătoare, estimat altfel.
    #
    # De ce NU se adună conținutul peste cifra măsurată:
    #     Estimatul e `plic + conținut` pentru că plicul e reserializarea
    #     evenimentului stocat, iar conținutul divulgat e declarat separat, în
    #     blocul `disclosure`. Măsurătoarea e altceva: e corpul întreg al
    #     cererii, așa cum a trecut prin socket. Când T2/T3 vor începe să
    #     trimită conținut, acesta va călători ÎN corp, deci e deja înăuntru.
    #     Adunat pe deasupra, ar fi numărat de două ori — iar cifra ar crește
    #     exact în direcția care face protocolul să pară mai scump decât e.
    #
    #     `content_bytes` rămâne raportat, dar ca defalcare a numărătorului
    #     măsurat, nu ca termen al lui.
    #
    # De ce zero măsurat NU e o măsurătoare:
    #     Contabilizarea trăiește în memoria procesului. Un agent care nu-și
    #     declară încarnarea, sau un server repornit, dau zero octeți măsurați
    #     lângă evenimente reale în store. Publicat ca numărător, zero ar
    #     însemna „acest endpoint n-a divulgat nimic" — cea mai flatantă
    #     minciună posibilă despre un sistem de confidențialitate. Zero se
    #     tratează deci ca absență de măsurătoare, iar cifra publicată revine la
    #     estimare, declarată ca atare.
    if numerator_is_measured:
        total_sent = measured_channel_bytes
        numerator_source = "measured"
    else:
        total_sent = estimated_sent
        numerator_source = "estimated"

    return {
        "scope": agent_id or "toti agentii",
        "always_upload": {
            "file_events_with_size": len(hashed),
            "content_bytes": always_upload_content_bytes,
            "envelope_bytes": always_upload_envelope_bytes,
            # Rigla plicului, declarată lângă el: aceeași cu a numărătorului,
            # prin construcție. Cine compară două cifre vede dacă au fost
            # măsurate la fel.
            "envelope_source": numerator_source,
            "bytes": always_upload_bytes,
            "distinct_hashes": len(distinct_hashes),
            "concentration": concentration,
            "note": (
                "Numitorul e continut + plic (METRICS.md §2): un sistem "
                "always-upload nu trimite fisiere goale, ci fisierul plus "
                "aceleasi metadate de identificare. Plicul e masurat cu rigla "
                "numaratorului: corpul de pe fir cand numaratorul e masurat, "
                "reserializarea cand e estimat."
            ),
        },
        "progressive": {
            # Ce anume e cifra de mai jos. METRICS.md §8 cere ca orice cifră
            # publicată să spună dacă e măsurată sau estimată; aici o spune ea
            # însăși, în același obiect, ca nimeni s-o citească greșit.
            "numerator_source": numerator_source,
            "total_bytes": total_sent,
            "content_bytes": disclosed_content_bytes,
            "metadata_bytes": metadata_bytes,
            "measured_bytes": measured_channel_bytes,
            "estimated_bytes": estimated_sent,
            "events_counted": len(file_events),
        },
        "calibration": {
            "estimated_bytes": estimated_sent,
            "measured_bytes": measured_channel_bytes,
            # Cât greșește estimatorul, ca factor. Peste 1 înseamnă că pe fir a
            # plecat mai mult decât reconstruiește reserializarea.
            "factor": (
                round(measured_channel_bytes / estimated_sent, 6)
                if measured_channel_bytes and estimated_sent
                else None
            ),
            "messages_measured": measured_channel_messages,
            "events_metered": events_metered,
            # Confundătorul, raportat lângă factor, nu ascuns în el: factorul NU
            # e doar eroarea estimatorului. Măsurătoarea numără fiecare plecare
            # (§1.3: coada e at-least-once, deci un eveniment poate pleca de mai
            # multe ori) și numără și cererile respinse, în timp ce estimatorul
            # reserializează evenimentele STOCATE, adică o dată fiecare.
            #
            # Cât timp raportul de mai jos e ~1, factorul descrie estimatorul.
            # Când crește, o parte din el descrie retransmisiile — iar cine
            # publică o cifră calibrată trebuie să vadă amândouă.
            "messages_per_metered_event": (
                round(measured_channel_messages / events_metered, 6)
                if measured_channel_messages and events_metered
                else None
            ),
            "note": (
                "Factorul calibreaza cifrele per fisier de la §3.2, care raman "
                "estimate: totalul agregat e masurat, dar registrul nu tine "
                "octeti per eveniment, iar a-i pune in mesaj ar fi circular. "
                "messages_per_metered_event separa eroarea estimatorului de "
                "retransmisii; cat timp e ~1, factorul descrie estimatorul."
            ),
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
            "envelope_unmeasured": envelope_unmeasured,
            "file_size_invalid": file_size_invalid,
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
                "in tabelul pe trepte. envelope_unmeasured numara fisierele "
                "hash-uite scoase din numitorul masurat pentru ca serverul nu "
                "le-a consemnat plicul de pe fir (evenimente mai vechi decat "
                "consemnarea, sau cereri fara Content-Length); e zero cand "
                "numaratorul e estimat. file_size_invalid numara fisierele "
                "hash-uite scoase din numitor pentru ca dimensiunea stocata nu e "
                "un intreg nenegativ (evenimente primite inainte de contract v12)."
            ),
        },
    }


def _denominator_concentration(
    hashed: List[Dict[str, Any]],
    contributions: List[int],
    always_upload_bytes: int,
) -> Dict[str, Any]:
    """
    Cât din numitor vine de la un singur eveniment și de la fiecare agent.

    De ce există:
        Numitorul nu e măsurat, e DECLARAT de mașina observată: `file_size`
        vine din stat()-ul agentului. Schema respinge de la v12 dimensiunile
        negative, dar nu are cum să știe una prea mare: plafonul real e
        `hash_max_file_size_bytes` din configul agentului, pe care serverul nu-l
        vede. Un singur eveniment cu `file_size = 10**15` lângă zece fișiere de
        1 MB a dus raportul de la 0,000336 la 0,0 — iar cifra n-a lăsat nicio
        urmă că un eveniment din unsprezece o produsese.

        Răspunsul nu e un prag, ci o declarație lângă cifră, ca restul
        golurilor: un raport dominat de un eveniment sau de un agent se vede ca
        atare. Același lucru prinde și un agent care minte în limite
        plauzibile, de exemplu 200 MiB la fiecare fișier, pe care niciun prag
        nu l-ar fi prins.

    Ce NU face:
        Nu recalculează raportul fără evenimentul cel mai mare. Scos din
        numitor, evenimentul ar trebui scos și din numărător, iar sub
        numărătorul măsurat serverul nu are octeți per eveniment (§3.2), doar
        totalul de pe fir: cele două părți ar ajunge pe rigle diferite, exact
        greșeala închisă la edr-server#14.

    Contribuția e `file_size + plic`, cu plicul măsurat cu aceeași riglă ca
    restul numitorului, deci cotele se adună la 1 peste agenți.
    """
    note = (
        "Cat din numitor vine de la evenimentul cel mai mare si de la fiecare "
        "agent, continut plus plic, cu rigla numitorului. file_size e "
        "declarat de agent, nu masurat, iar serverul nu-i cunoaste plafonul: "
        "un share apropiat de 1 la largest_event inseamna ca raportul "
        "descrie un singur fisier, nu rularea."
    )

    # Forma rămâne aceeași și fără numitor: un cititor care caută cheia o
    # găsește, cu None în loc de un eveniment inventat.
    if not hashed or not always_upload_bytes:
        return {"largest_event": None, "by_agent": {}, "note": note}

    def share(part: int) -> float:
        return round(part / always_upload_bytes, 6)

    # max() întoarce primul maxim, deci la egalitate câștigă primul eveniment
    # în ordinea depozitului: cifra rămâne aceeași la fiecare apel.
    top = max(range(len(hashed)), key=lambda i: contributions[i])
    by_agent: Dict[str, Dict[str, int]] = {}

    for event, contribution in zip(hashed, contributions):
        bucket = by_agent.setdefault(
            str(event.get("agent_id")), {"events": 0, "bytes": 0}
        )
        bucket["events"] += 1
        bucket["bytes"] += contribution

    return {
        "largest_event": {
            "event_id": hashed[top].get("event_id"),
            "agent_id": hashed[top].get("agent_id"),
            "bytes": contributions[top],
            "share": share(contributions[top]),
        },
        "by_agent": {
            agent: {**by_agent[agent], "share": share(by_agent[agent]["bytes"])}
            for agent in sorted(by_agent)
        },
        "note": note,
    }
