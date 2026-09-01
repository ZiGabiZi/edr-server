"""
Ce a știut depozitul, pe o rulare — distribuția dispozițiilor de la T0.
======================================================================

De ce e o cifră SEPARATĂ de metrica de divulgare, și nu încă o secțiune în ea:
    Cele două tabele au numitori diferiți și răspund la întrebări diferite.

    `by_tier` din `disclosure_metrics` are numitorul `events_with_tier` — ce
    declară AGENTUL în blocul `disclosure`, adică ce a divulgat. Tabelul de aici
    are numitorul `events_with_hash` — evenimentele pentru care serverul chiar
    avea ce căuta, adică ce a conchis SERVERUL.

    Cele două pot diverge legitim: un eveniment care poartă treapta T0 și
    primește `unknown` a divulgat la T0 fără să se închidă acolo. Publicate ca un
    singur tabel, procentele s-ar aduna peste mulțimi diferite, iar rezultatul
    n-ar descrie niciuna. `METRICS.md` §3.4 vorbește deja despre „procentul de
    verdicte închise acolo" — până la P2.3 fraza n-avea referent, de acum are
    doi, și trebuie ținuți separați.

De ce NU se publică aici un procent de „închis la T0":
    Ar cere o mapare dispoziție → închis/escaladat, iar maparea aia e chiar
    decizia benzii de incertitudine (§L2.7), care nu există încă. Scrisă aici, ar
    fi al doilea mecanism de decizie din sistem, contrazicându-l tăcut pe primul
    — exact motivul pentru care depozitul nu are prag propriu.

    Concret, întrebarea deschisă e `known_software`: un fișier prezent în RDS e
    cunoscut, dar `CORPUS.md` §5.4 interzice să fie declarat curat, deci axa de
    amenințare îi rămâne nedecisă. Dacă „închis" l-ar include, cifra ar spăla
    apartenența la RDS ca verdict de benignitate — pe ușa din dos a unei metrici,
    după ce structura depozitului a închis-o pe cea din față.

    Se publică deci cele cinci contoare și numitorul lor. Cine vrea o rată de
    închidere o compune explicit, declarând ce a numărat ca închis.

Ce se declară lângă cifră (`METRICS.md` §8):
    Instantaneul care a răspuns, cu amprentă și surse. Fără el, „38,5% necunoscut"
    nu spune nimic: e chiar diferența dintre brațul rece și cel semiînzestrat al
    ablației, iar fără identitatea depozitului cifra ar putea fi oricare dintre
    ele.
"""

from typing import Any, Dict, Iterable, List, Sequence

from app.services.reputation_disposition import VALID_DISPOSITIONS


def compute_reputation_metrics(
    events: Iterable[Dict[str, Any]],
    snapshots: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Distribuția dispozițiilor peste evenimentele date, cu instantaneele declarate.

    `snapshots` vine din depozitul de evenimente, nu se citește aici: funcția
    rămâne pură — primește evenimente, întoarce cifre — și se poate testa fără
    server, fără proces și fără stare globală. Aceeași separare ca la
    reconcilierea de fir, care se compune tot în rută.
    """
    dispositions: Dict[str, int] = {value: 0 for value in sorted(VALID_DISPOSITIONS)}

    events_with_hash = 0
    without_disposition = 0
    unrecognised: Dict[str, int] = {}

    for event in events:
        if not event.get("sha256"):
            continue

        events_with_hash += 1
        reputation = event.get("reputation")

        if not reputation:
            # Evenimente scrise ÎNAINTE de v8: aveau hash, dar nimeni nu-l
            # consulta. Nu sunt zero-uri în tabel, sunt un gol de atribuire — la
            # fel ca `file_events_without_tier` de la §2.1. Contopite cu
            # `unknown`, o rulare veche ar arăta ca un corpus complet nou.
            without_disposition += 1
            continue

        disposition = reputation.get("disposition")

        if disposition in dispositions:
            dispositions[disposition] += 1
        else:
            # O valoare pe care vocabularul n-o cunoaște nu se aruncă și nu se
            # împinge în `unknown`: se numără sub numele ei. Ar însemna că o
            # versiune a scris ce alta nu poate citi, iar cifra trebuie să spună
            # asta, nu să o absoarbă.
            unrecognised[str(disposition)] = unrecognised.get(str(disposition), 0) + 1

    return {
        "events_with_hash": events_with_hash,
        "dispositions": dispositions,
        "hashed_events_without_disposition": without_disposition,
        "unrecognised_dispositions": dict(sorted(unrecognised.items())),
        "snapshots": list(snapshots),
        "note": (
            "Numitorul e events_with_hash — evenimentele pentru care serverul "
            "avea ce cauta — NU events_with_tier de la by_tier, care numara ce "
            "declara agentul ca a divulgat. Cele doua pot diverge legitim: un "
            "eveniment cu treapta T0 si dispozitia unknown a divulgat la T0 fara "
            "sa se inchida acolo. Nu se publica aici o rata de inchidere: "
            "maparea dispozitie -> inchis apartine benzii de incertitudine "
            "(§L2.7), iar known_software nu poate fi numarat ca inchis fara sa "
            "incalce CORPUS.md §5.4. reputation_unavailable NU e unknown: primul "
            "spune ca depozitul n-a putut fi intrebat, al doilea ca a fost "
            "intrebat si nu stie. snapshots declara instantaneul care a raspuns "
            "(METRICS.md §8); gol inseamna ca niciun eveniment din perimetru "
            "n-a ajuns sa consulte depozitul."
        ),
    }
