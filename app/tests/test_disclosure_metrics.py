"""
Metrica de divulgare: ce numără, ce refuză să numere, și ce nu ascunde.
=======================================================================

Contractul de fir impune `file_size` obligatoriu când `hash_status == 'ok'`
încă de la v3, cu motivul scris acolo: e numărătorul acestei metrici și „nu se
poate reconstrui retroactiv dacă fișierul s-a schimbat". Testele de aici sunt
primul loc care verifică faptul că invarianta chiar livrează ce a promis.

Ordinea urmează felul în care o metrică poate minți:

  1. NUMITORUL — ce ar fi costat always-upload. Greșit aici, tot restul e fals.
  2. SEPARAREA COSTURILOR — conținut zero nu înseamnă cost zero. Metadatele
     circulă la fiecare fișier atins, nu doar la cele escaladate.
  3. GOLUL — fișierele fără hash n-au dimensiune. Rotunjite la zero, ar face
     rezultatul să pară mai bun decât e.
"""

import pytest

from app.services.disclosure_metrics import compute_disclosure_metrics


def _file_event(
    name: str,
    size=None,
    hash_status: str = "ok",
    sha256: str = "a" * 64,
    agent_id: str = "agent-1",
) -> dict:
    return {
        "agent_id": agent_id,
        "event_type": "file_created",
        "file_path": f"C:\\EDR_Test\\{name}",
        "sha256": sha256 if hash_status == "ok" else None,
        "hash_status": hash_status,
        "file_size": size,
        "occurred_at": "2026-01-01T00:00:00+00:00",
    }


def _lifecycle_event(event_type: str = "agent_startup", agent_id: str = "agent-1") -> dict:
    return {
        "agent_id": agent_id,
        "event_type": event_type,
        "file_path": None,
        "occurred_at": "2026-01-01T00:00:00+00:00",
    }


# ---------------------------------------------------------------------------
# 1. Numitorul
# ---------------------------------------------------------------------------

def test_the_denominator_is_the_sum_of_hashed_file_sizes():
    metrics = compute_disclosure_metrics(
        [_file_event("a.bin", 1000), _file_event("b.bin", 2500)]
    )

    assert metrics["always_upload"]["bytes"] == 3500
    assert metrics["always_upload"]["file_events_with_size"] == 2


def test_lifecycle_events_are_not_files_and_stay_out_of_the_denominator():
    """
    agent_startup nu corespunde niciunui fișier pe care always-upload l-ar fi
    urcat. Numărat ca fișier de dimensiune zero, ar dilua raportul cu intrări
    care nu descriu nimic observat.
    """
    metrics = compute_disclosure_metrics(
        [_file_event("a.bin", 1000), _lifecycle_event(), _lifecycle_event("agent_shutdown")]
    )

    assert metrics["always_upload"]["file_events_with_size"] == 1
    assert metrics["progressive"]["events_counted"] == 1


def test_distinct_hashes_are_counted_separately_from_events():
    """
    Același fișier atins de zece ori produce zece evenimente, dar o singură
    amprentă. Distincția pregătește treapta următoare: prevalența se calculează
    pe amprente, nu pe evenimente.
    """
    metrics = compute_disclosure_metrics(
        [
            _file_event("a.bin", 100, sha256="a" * 64),
            _file_event("a.bin", 100, sha256="a" * 64),
            _file_event("b.bin", 100, sha256="b" * 64),
        ]
    )

    assert metrics["always_upload"]["file_events_with_size"] == 3
    assert metrics["always_upload"]["distinct_hashes"] == 2


def test_the_scope_can_be_narrowed_to_one_agent():
    metrics = compute_disclosure_metrics(
        [
            _file_event("a.bin", 1000, agent_id="agent-1"),
            _file_event("b.bin", 9999, agent_id="agent-2"),
        ],
        agent_id="agent-1",
    )

    assert metrics["always_upload"]["bytes"] == 1000
    assert metrics["scope"] == "agent-1"


# ---------------------------------------------------------------------------
# 2. Separarea costurilor
# ---------------------------------------------------------------------------

def test_no_content_leaves_the_endpoint_at_this_tier():
    metrics = compute_disclosure_metrics([_file_event("a.bin", 5_000_000)])

    assert metrics["progressive"]["content_bytes"] == 0


def test_metadata_is_counted_even_though_content_is_zero():
    """
    Zero conținut nu înseamnă cost zero. Canalul de evenimente circulă la
    FIECARE fișier atins, nu doar la cele escaladate. O metrică ce ar raporta
    doar conținutul ar fi adevărată și înșelătoare în același timp.
    """
    metrics = compute_disclosure_metrics([_file_event("a.bin", 5_000_000)])

    assert metrics["progressive"]["metadata_bytes"] > 0
    assert metrics["progressive"]["total_bytes"] == metrics["progressive"]["metadata_bytes"]


def test_lifecycle_events_cost_metadata_even_without_a_file():
    """Au traversat aceeași rețea, deci intră în numărător, nu în numitor."""
    with_lifecycle = compute_disclosure_metrics(
        [_file_event("a.bin", 1000), _lifecycle_event()]
    )
    without = compute_disclosure_metrics([_file_event("a.bin", 1000)])

    assert (
        with_lifecycle["progressive"]["metadata_bytes"]
        > without["progressive"]["metadata_bytes"]
    )
    assert with_lifecycle["always_upload"]["bytes"] == without["always_upload"]["bytes"]


def test_the_ratio_is_sent_over_always_upload():
    metrics = compute_disclosure_metrics([_file_event("a.bin", 1_000_000)])

    sent = metrics["progressive"]["total_bytes"]
    assert metrics["ratio"]["sent_over_always_upload"] == pytest.approx(
        sent / 1_000_000, rel=1e-9
    )
    assert metrics["ratio"]["bytes_saved"] == 1_000_000 - sent


def test_an_empty_denominator_yields_no_ratio_rather_than_zero():
    """
    Un raport fără numitor e o afirmație fără suport. Zero ar fi arătat exact ca
    un rezultat foarte bun, ceea ce e cel mai prost mod de a greși într-o
    metrică menită să susțină o teză.
    """
    metrics = compute_disclosure_metrics([_lifecycle_event()])

    assert metrics["ratio"]["sent_over_always_upload"] is None


# ---------------------------------------------------------------------------
# 3. Golul
# ---------------------------------------------------------------------------

def test_files_without_a_successful_hash_are_reported_not_dropped():
    """
    Fără dimensiune, nu pot intra în numitor. Dar sub always-upload ar fi fost
    urcate, deci numitorul e o subestimare — iar subestimarea trebuie să fie
    vizibilă, nu rotunjită la zero.
    """
    metrics = compute_disclosure_metrics(
        [
            _file_event("bun.bin", 1000),
            _file_event("instabil.bin", None, hash_status="unstable"),
            _file_event("mare.bin", None, hash_status="too_large"),
        ]
    )

    assert metrics["always_upload"]["file_events_with_size"] == 1
    assert metrics["unmeasured"]["file_events_without_size"] == 2
    assert metrics["unmeasured"]["by_hash_status"] == {"too_large": 1, "unstable": 1}


def test_the_gap_keeps_the_statuses_apart():
    """
    'unstable' e cost impus de obiectul observat; 'skipped_capacity' și
    'skipped_shutdown' sunt cost impus de observator. Contopite, nu s-ar mai
    putea spune care parte a golului aparține metodei și care implementării —
    exact distincția pentru care contractul de fir a introdus statusurile v4.
    """
    metrics = compute_disclosure_metrics(
        [
            _file_event("a.bin", None, hash_status="unstable"),
            _file_event("b.bin", None, hash_status="skipped_capacity"),
            _file_event("c.bin", None, hash_status="skipped_shutdown"),
        ]
    )

    assert metrics["unmeasured"]["by_hash_status"] == {
        "skipped_capacity": 1,
        "skipped_shutdown": 1,
        "unstable": 1,
    }


def test_a_file_event_with_ok_status_but_no_size_counts_as_a_gap():
    """
    Contractul impune file_size la hash_status ok, dar metrica nu se sprijină pe
    validator: un agent mai vechi sau un build din altă ramură poate trimite
    perechea invalidă, iar un numitor construit din None ar arunca la calcul.
    """
    metrics = compute_disclosure_metrics([_file_event("a.bin", None, hash_status="ok")])

    assert metrics["always_upload"]["bytes"] == 0
    assert metrics["unmeasured"]["file_events_without_size"] == 1


# ---------------------------------------------------------------------------
# Ruta
# ---------------------------------------------------------------------------

def test_the_route_reports_the_metric_for_the_stored_events(client, registered_agent_id):
    client.post(
        "/api/events",
        json={
            "agent_id": registered_agent_id,
            "event_type": "file_created",
            "file_path": "C:\\EDR_Test\\a.bin",
            "sha256": "a" * 64,
            "hash_status": "ok",
            "file_size": 4096,
        },
    )

    body = client.get("/api/metrics/disclosure").json()

    assert body["always_upload"]["bytes"] == 4096
    assert body["progressive"]["content_bytes"] == 0
    assert body["ratio"]["sent_over_always_upload"] is not None
