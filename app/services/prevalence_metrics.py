"""
Cât de răspândit e ce a văzut parcul — histograma prevalenței, pe o rulare.
===========================================================================

De ce e o cifră separată, a treia:
    `by_tier` numără ce a declarat AGENTUL că a divulgat. `reputation` numără ce
    a conchis serverul din memoria împrumutată. Tabelul de aici descrie memoria
    PROPRIE a parcului — și, spre deosebire de celelalte două, numitorul lui nu e
    o mulțime de evenimente, ci una de **conținuturi distincte**.

    Diferența nu e cosmetică. Un fișier care apare pe cinci mașini produce cinci
    evenimente și un singur rând în histogramă. Numărate la un loc, cele două ar
    da un procent peste o mulțime care nu există.

De ce histograma descrie starea de ACUM, nu ce s-a răspuns atunci:
    Prevalența se schimbă în timpul rulării, deci același fișier a primit `1` la
    primul endpoint și `5` la ultimul. O distribuție peste valorile răspunsurilor
    ar descrie în bună parte ORDINEA sosirii, nu parcul.

    Histograma peste starea finală e cea comparabilă cu proiectarea corpusului —
    1046 de fișiere pe cinci mașini, 448 pe una până la trei — deci e cea care
    poate fi infirmată de o măsurătoare.

    Ce s-a răspuns atunci nu se pierde: se raportează separat, ca număr de
    evenimente sosite la un conținut pe care parcul îl vedea prima oară față de
    unul pe care îl știa deja.

De ce NU se publică nicio economie:
    „Câte escaladări a evitat parcul" cere să se știe care evenimente ar fi
    escaladat, iar decizia aia e a benzii de incertitudine (§L2.7), care nu
    există. Se publică numărătoarea; interpretarea ei rămâne a pasului care are
    dreptul s-o facă.
"""

from typing import Any, Dict, Iterable, List, Mapping, Sequence


def compute_prevalence_metrics(
    events: Iterable[Dict[str, Any]],
    counts: Mapping[str, int],
    baselines: Sequence[Dict[str, Any]],
    park_agents: int,
) -> Dict[str, Any]:
    """
    Histograma prevalenței peste conținuturile văzute în evenimentele date.

    `counts` și `baselines` vin din depozit, nu se citesc aici: funcția rămâne
    pură — primește evenimente și stare, întoarce cifre — și se poate testa fără
    server, ca `compute_disclosure_metrics`.
    """
    hashes: set = set()
    first_sighting = 0
    prior_sighting = 0
    without_prevalence = 0

    for event in events:
        digest = event.get("sha256")

        if not digest:
            continue

        hashes.add(digest.lower())
        prevalence = event.get("prevalence")

        if not prevalence:
            # Evenimente scrise înainte ca registrul să existe: au conținut
            # identificat, dar nimeni nu-l număra. Gol de atribuire, ca la §2.1 —
            # contopite cu „prima vedere", o rulare veche ar arăta ca un parc în
            # care nimic nu se repetă niciodată.
            without_prevalence += 1
            continue

        if prevalence.get("agents") == 1:
            first_sighting += 1
        else:
            prior_sighting += 1

    histogram: Dict[str, int] = {}

    for digest in hashes:
        agents = counts.get(digest)

        if agents:
            histogram[str(agents)] = histogram.get(str(agents), 0) + 1

    machines = [int(k) * v for k, v in histogram.items()]
    placements = sum(machines)
    distinct = sum(histogram.values())

    return {
        "distinct_hashes": distinct,
        "park_agents": park_agents,
        "placements": placements,
        "machines_per_hash": round(placements / distinct, 4) if distinct else None,
        "histogram": {k: histogram[k] for k in sorted(histogram, key=int)},
        "events_at_first_sighting": first_sighting,
        "events_with_prior_sighting": prior_sighting,
        "hashed_events_without_prevalence": without_prevalence,
        "baselines": list(baselines),
        "note": (
            "Numitorul histogramei e distinct_hashes — CONTINUTURI distincte, nu "
            "evenimente: un fisier vazut pe cinci masini produce cinci evenimente "
            "si un singur rand. Nu se aduna cu by_tier sau cu reputation, care "
            "numara evenimente. Histograma descrie starea de ACUM a registrului, "
            "nu valorile raspunse atunci: prevalenta se schimba in timpul rularii, "
            "deci o distributie peste raspunsuri ar descrie ordinea sosirii. Ce "
            "s-a raspuns atunci apare separat, ca events_at_first_sighting fata de "
            "events_with_prior_sighting. Nu se publica nicio economie: „cate "
            "escaladari a evitat parcul\" cere sa se stie care evenimente ar fi "
            "escaladat, iar decizia apartine benzii de incertitudine (L2.7). "
            "baselines declara pozitia de plecare a memoriei pentru fiecare rulare "
            "din perimetru — registrul e global si NU se amprenteaza, fiindca se "
            "schimba in timpul rularii."
        ),
    }
