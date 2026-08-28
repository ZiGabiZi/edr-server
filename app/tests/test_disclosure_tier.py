"""
Teste pentru atribuirea pe trepte (contract v5).
=================================================

Blocul `disclosure` raspunde la o intrebare pe care metrica de divulgare nu o
putea pune inainte: nu doar CAT a plecat, ci de la CE TREAPTA. Fara el, raportul
agregat descrie deopotriva protocolul progresiv si un sistem care raporteaza
doar amprente — vezi contracts/METRICS.md §3.4.

Doua lucruri se apara aici. Invarianta de treapta: T0 si T1 nu divulga continut
prin definitie, iar un octet aparut acolo e ori un bug de atribuire, ori un canal
necontabilizat — in ambele cazuri, ceva ce nu are voie sa fie contabilizat tacit.
Si numitorul tabelului pe trepte: procentele se raporteaza la evenimentele care
POARTA o treapta, nu la totalul lor, iar cele de fisier fara treapta intra intr-un
gol declarat, nu dispar.
"""

import pytest
from pydantic import ValidationError

from app.schemas.event import (
    VALID_DISCLOSURE_TIERS,
    _CONTENTLESS_TIERS,
    EventCreateRequest,
    EventDisclosure,
)
from app.services.disclosure_metrics import compute_disclosure_metrics
from app.tests.test_wire_contract import CONTRACT


def _event(**overrides):
    """Un eveniment stocat, in forma pe care o vede metrica."""
    event = {
        "agent_id": "agent-1",
        "event_type": "file_created",
        "file_path": "C:\\tmp\\proba.exe",
        "sha256": "a" * 64,
        "hash_status": "ok",
        "file_size": 1_000_000,
        "disclosure": {"tier": "T0", "content_bytes": 0},
    }
    event.update(overrides)
    return event


# ---------------------------------------------------------------------------
# 1. Vocabularul treptelor
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("tier", sorted(VALID_DISCLOSURE_TIERS))
def test_every_declared_tier_is_accepted(tier):
    """
    Toate cele patru trepte sunt acceptate desi doar T0 exista. Un server care
    ar refuza o valoare viitoare ar bloca agentul exact in momentul in care
    treapta noua devine functionala — iar blocajul ar aparea la deploy, nu la
    dezvoltare.
    """
    disclosure = EventDisclosure(tier=tier)
    assert disclosure.tier == tier


def test_an_unknown_tier_is_rejected():
    with pytest.raises(ValidationError) as raised:
        EventDisclosure(tier="T4")

    assert "tier invalid" in str(raised.value)


def test_negative_content_bytes_is_rejected():
    with pytest.raises(ValidationError):
        EventDisclosure(tier="T3", content_bytes=-1)


@pytest.mark.parametrize("tier", ["T0", "T1"])
def test_a_contentless_tier_refuses_to_carry_content(tier):
    """
    Nu e o conventie de raportare, e definitia treptelor: daca T0 ar putea
    purta octeti de continut, distinctia dintre trepte s-ar dizolva si metrica
    ar masura o scara fara semnificatie.
    """
    with pytest.raises(ValidationError) as raised:
        EventDisclosure(tier=tier, content_bytes=4096)

    assert "content_bytes" in str(raised.value)


@pytest.mark.parametrize("tier", ["T2", "T3"])
def test_an_escalated_tier_may_carry_content(tier):
    disclosure = EventDisclosure(tier=tier, content_bytes=4096)
    assert disclosure.content_bytes == 4096


def test_a_block_without_a_tier_is_rejected():
    """
    Blocul e optional, treapta din el nu.

    Cele doua reguli nu se bat cap in cap. Absenta blocului ramane acceptata ca
    un agent de dinainte de v5 sa nu primeasca 422 si sa-si piarda evenimentul
    din spool. Dar un bloc PREZENT fara treapta ar readuce, cu un nivel mai jos,
    exact ambiguitatea pe care bicondiționalitatea a fost introdusa s-o elimine:
    nu s-ar mai putea spune daca evenimentul nu e pe scara, daca emitatorul e
    partial, sau daca builder-ul a uitat campul.
    """
    with pytest.raises(ValidationError):
        EventDisclosure(content_bytes=0)


def _disclosure_notes() -> str:
    return CONTRACT["models"]["event_disclosure"]["notes"]


def test_the_contract_and_the_schema_agree_on_the_tier_vocabulary():
    """
    Vocabularul traieste in trei locuri: frozenset-ul din schema, cel din
    builder-ul agentului, si nota din contract. O treapta adaugata intr-unul si
    uitata in celelalte nu produce niciun esec la rulare — produce doua repo-uri
    care valideaza scale diferite. Aceeasi garda ca la hash_status.
    """
    notes = _disclosure_notes()
    undocumented = sorted(
        tier for tier in VALID_DISCLOSURE_TIERS if f"'{tier}'" not in notes
    )

    assert not undocumented, (
        f"Trepte acceptate de schema, dar nementionate in notele "
        f"contractului: {undocumented}."
    )


def test_the_contentless_tiers_are_written_in_the_contract():
    """
    Nu doar CARE trepte exista, ci si care dintre ele nu au voie sa poarte
    continut: invarianta e verificata in trei locuri si trebuie sa aiba o
    singura sursa scrisa.
    """
    notes = _disclosure_notes()

    assert "FARA CONTINUT" in notes, (
        "Contractul nu mai numeste treptele fara continut; invarianta "
        "verificata de schema si de builder a ramas fara sursa scrisa."
    )

    for tier in sorted(_CONTENTLESS_TIERS):
        assert f"'{tier}'" in notes


def test_the_contract_marks_the_tier_mandatory_inside_the_block():
    """
    Garda pentru garda: `tier: str` in schema si `required: ["tier"]` in
    contract spun acelasi lucru, si testul generic de obligativitate le tine
    egale. Aici verificam doar ca partea de contract n-a fost relaxata inapoi.
    """
    spec = CONTRACT["models"]["event_disclosure"]

    assert spec["required"] == ["tier"], (
        f"Contractul nu mai cere tier in interiorul blocului: "
        f"required={spec['required']}. Un bloc fara treapta redevine ambiguu."
    )


def test_the_block_travels_through_the_full_request_model():
    event = EventCreateRequest(
        agent_id="a1",
        event_type="file_created",
        file_path="C:\\x.exe",
        sha256="b" * 64,
        hash_status="ok",
        file_size=2048,
        disclosure={"tier": "T0", "content_bytes": 0},
    )

    assert event.disclosure is not None
    assert event.disclosure.tier == "T0"
    assert event.disclosure.content_bytes == 0


def test_an_event_without_disclosure_is_still_accepted():
    """
    Bicondiționalitatea 'disclosure <=> file_path' NU e validator, deliberat:
    un agent care inca nu emite blocul ar primi 422 -> FatalTransportError ->
    stergere din spool. Un camp lipsa e recuperabil; un eveniment sters, nu.
    Acelasi rationament ca la hash_status intre v3 si v4.
    """
    event = EventCreateRequest(
        agent_id="a1",
        event_type="file_created",
        file_path="C:\\x.exe",
    )

    assert event.disclosure is None


# ---------------------------------------------------------------------------
# 2. Atribuirea pe trepte, in metrica
# ---------------------------------------------------------------------------

def test_events_are_counted_under_their_tier():
    metrics = compute_disclosure_metrics([_event(), _event(), _event()])

    assert metrics["by_tier"]["events_with_tier"] == 3
    assert metrics["by_tier"]["tiers"]["T0"]["events"] == 3
    assert metrics["by_tier"]["tiers"]["T0"]["content_bytes"] == 0


def test_lifecycle_events_are_absent_from_the_tier_table():
    """
    Numitorul tabelului nu e multimea tuturor evenimentelor. Un eveniment de
    pornire divulga metadate — deci intra in numarator — dar nu e pe scara si
    n-ar avea ce cauta printre procentele pe trepte.
    """
    events = [
        _event(),
        {"agent_id": "agent-1", "event_type": "agent_startup"},
    ]

    metrics = compute_disclosure_metrics(events)

    assert metrics["by_tier"]["events_with_tier"] == 1
    assert metrics["progressive"]["events_counted"] == 1
    # Metadatele evenimentului de pornire au plecat totusi pe aceeasi retea.
    assert metrics["progressive"]["metadata_bytes"] > 0


def test_a_file_event_without_a_tier_falls_into_a_declared_gap():
    """
    Golul de atribuire se numara separat de cel de dimensiune: un fisier
    hash-uit cu succes dar fara treapta nu e acelasi lucru cu unul pe care
    hashing-ul l-a ratat, iar contopite ar ascunde care dintre cele doua
    mecanisme a esuat.
    """
    metrics = compute_disclosure_metrics([_event(), _event(disclosure=None)])

    assert metrics["by_tier"]["events_with_tier"] == 1
    assert metrics["unmeasured"]["file_events_without_tier"] == 1
    assert metrics["unmeasured"]["file_events_without_size"] == 0


def test_disclosed_content_comes_from_the_tier_table_not_from_a_constant():
    """
    Inainte de v5, continutul divulgat era zero prin constanta. Acum e o suma
    peste trepte: cand T2 si T3 vor exista, ea se completeaza singura, iar
    metrica nu mai are nevoie de o promisiune in comentariu.
    """
    events = [
        _event(),
        _event(disclosure={"tier": "T3", "content_bytes": 143_000}),
    ]

    metrics = compute_disclosure_metrics(events)

    assert metrics["progressive"]["content_bytes"] == 143_000
    assert metrics["by_tier"]["tiers"]["T3"]["content_bytes"] == 143_000
    assert metrics["by_tier"]["tiers"]["T0"]["content_bytes"] == 0


def test_content_without_a_tier_still_reaches_the_numerator():
    """
    Un octet care a parasit endpoint-ul a plecat, indiferent daca stim carei
    trepte sa-l atribuim.

    Scos din numarator pentru ca atribuirea lipseste, ar deplasa cifra exact in
    directia care flateaza afirmatia centrala — genul de greseala care nu se
    vede in raport, pentru ca raportul arata mai bine.
    """
    metrics = compute_disclosure_metrics(
        [_event(disclosure={"content_bytes": 143_000})]
    )

    assert metrics["progressive"]["content_bytes"] == 143_000
    assert metrics["unmeasured"]["file_events_without_tier"] == 1
    assert metrics["unmeasured"]["content_bytes_without_tier"] == 143_000
    # Neatribuit inseamna in afara tabelului, nu in afara numaratorului.
    assert metrics["by_tier"]["events_with_tier"] == 0


def test_a_disclosure_block_outside_a_file_event_is_counted_and_flagged():
    """
    Bicondiționalitatea nu e validator, deci blocul poate aparea si acolo unde
    n-are ce cauta. Octetii lui intra in numarator; in tabelul pe trepte nu,
    pentru ca i-ar strica numitorul declarat la §3.4. Iar incalcarea se numara,
    ca sa nu ramana o presupunere.
    """
    events = [
        _event(),
        {
            "agent_id": "agent-1",
            "event_type": "agent_startup",
            "disclosure": {"tier": "T3", "content_bytes": 5_000},
        },
    ]

    metrics = compute_disclosure_metrics(events)

    assert metrics["progressive"]["content_bytes"] == 5_000
    assert metrics["unmeasured"]["disclosure_outside_file_events"] == 1
    assert metrics["by_tier"]["events_with_tier"] == 1
    assert "T3" not in metrics["by_tier"]["tiers"]


def test_the_ratio_reflects_escalated_content():
    """
    Cu o singura treapta, raportul descria mai ales dimensiunea fisierelor din
    corpus. Escaladarea il misca — si abia asta face din el o proprietate a
    protocolului, nu a directorului monitorizat.
    """
    doar_t0 = compute_disclosure_metrics([_event()])
    cu_escaladare = compute_disclosure_metrics(
        [_event(disclosure={"tier": "T3", "content_bytes": 900_000})]
    )

    assert (
        cu_escaladare["ratio"]["sent_over_always_upload"]
        > doar_t0["ratio"]["sent_over_always_upload"]
    )