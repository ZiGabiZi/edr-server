"""
Raportul de acoperire — cifra pe care o datorăm oricum, și cele două verificări.

Testele folosesc un manifest mic, construit aici. Manifestul real are 1494 de
fișiere și e produs de alt repo; un test legat de el ar depinde de o rulare de
corpus, iar ce se verifică aici e aritmetica raportului, nu conținutul corpusului.

Verificările de sănătate sunt enunțate în cod înainte de prima rulare pe date
reale, tocmai ca să nu poată fi ajustate după ce se vede rezultatul. Testele
fixează ambele direcții: și trecerea, și eșecul.
"""

import json

import pytest

import app.services.reputation_build as reputation_build
import app.services.reputation_coverage as coverage
import app.services.reputation_store as reputation_store


SISTEM = [bytes([i]) * 32 for i in range(1, 11)]
COMPILAT = [bytes([i]) * 32 for i in range(11, 16)]
MALWARE = [bytes([i]) * 32 for i in range(16, 21)]


def _manifest(tmp_path, intrari):
    cale = tmp_path / "manifest.json"
    cale.write_text(
        json.dumps({"count": len(intrari), "files": intrari}), encoding="utf-8"
    )

    return cale


def _fisier(h, origine, eticheta="benign", strat="realist"):
    return {
        "sha256": h.hex(),
        "label": eticheta,
        "origin": origine,
        "stratum": strat,
    }


@pytest.fixture
def intrari():
    return (
        [_fisier(h, "sistem") for h in SISTEM]
        + [_fisier(h, "compilat") for h in COMPILAT]
        + [_fisier(h, "malware", "malicious", "stres") for h in MALWARE]
    )


@pytest.fixture
def depozit(tmp_path):
    """
    Un depozit in care binarele de sistem sunt in RDS, artefactele compilate nu,
    iar malware-ul e pe axa de amenintare. Adica exact ce ar trebui sa iasa.
    """
    connection = reputation_build.create_working_database(tmp_path / "lucru.db")

    rds = reputation_build.record_source(
        connection, "NSRL RDS", "software", "2026.03.1", len(SISTEM)
    )
    bazaar = reputation_build.record_source(
        connection, "MalwareBazaar", "threat", "inventar-test", len(MALWARE)
    )

    connection.executemany(
        "INSERT INTO reputation (sha256, known_software, software_source) "
        "VALUES (?, 1, ?)",
        [(h, rds) for h in SISTEM],
    )
    connection.executemany(
        "INSERT INTO reputation (sha256, known_malicious, threat_source) "
        "VALUES (?, 1, ?)",
        [(h, bazaar) for h in MALWARE],
    )
    connection.commit()

    yield connection

    connection.close()


# ── Aritmetica ──────────────────────────────────────────────────────────────

def test_the_report_counts_each_origin_separately(intrari, depozit):
    m = coverage.measure(intrari, depozit)

    assert m["per_origine"]["sistem"]["in_rds"] == len(SISTEM)
    assert m["per_origine"]["compilat"]["in_rds"] == 0
    assert m["per_origine"]["compilat"]["necunoscut"] == len(COMPILAT)
    assert m["per_origine"]["malware"]["amenintare"] == len(MALWARE)


def test_the_overlap_is_counted_on_its_own(intrari, depozit):
    """
    Celula din 2x2 pe care un enum de trei valori ar fi facut-o imposibil de
    reconstruit. Aici se vede ca e o interogare, nu o instrumentare separata.
    """
    rds = reputation_build.record_source(
        depozit, "NSRL RDS", "software", "2026.03.1", 0
    )
    depozit.execute(
        "UPDATE reputation SET known_software = 1, software_source = ? "
        "WHERE sha256 = ?",
        (rds, MALWARE[0]),
    )
    depozit.commit()

    m = coverage.measure(intrari, depozit)

    assert m["per_origine"]["malware"]["ambele"] == 1
    assert m["total"]["ambele"] == 1


def test_an_unreadable_hash_is_counted_not_ignored(depozit, tmp_path):
    """
    Un hash pe care raportul nu-l poate citi trebuie sa apara ca atare. Sarit in
    tacere, ar micsora numitorul si ar umfla procentul de acoperire.
    """
    m = coverage.measure(
        [_fisier(SISTEM[0], "sistem"), {"sha256": "nu-e-un-hash", "origin": "sistem"}],
        depozit,
    )

    assert m["hash_uri_necitibile"] == 1
    assert m["total"]["fisiere"] == 1


# ── Verificarile de sanatate ────────────────────────────────────────────────

def test_both_sanity_checks_pass_on_a_healthy_store(intrari, depozit):
    rezultate = coverage.sanity_checks(coverage.measure(intrari, depozit))

    assert [trecut for _, trecut, _ in rezultate] == [True, True]


def test_a_compiled_artifact_found_in_rds_fails_the_check(intrari, depozit):
    """
    Artefactele compilate exista tocmai ca sa fie benigne SI necunoscute in
    acelasi timp (CORPUS.md 3.1). Daca RDS le cunoaste, categoria aia nu exista,
    iar banda ar invata ca tot ce e necunoscut e malitios.
    """
    rds = reputation_build.record_source(
        depozit, "NSRL RDS", "software", "2026.03.1", 0
    )
    depozit.execute(
        "INSERT INTO reputation (sha256, known_software, software_source) "
        "VALUES (?, 1, ?)",
        (COMPILAT[0], rds),
    )
    depozit.commit()

    rezultate = dict((nume, trecut) for nume, trecut, _ in
                     coverage.sanity_checks(coverage.measure(intrari, depozit)))

    assert rezultate["artefactele compilate lipsesc din RDS"] is False


def test_missing_system_binaries_fail_the_check(intrari, depozit):
    """
    Esecul asta NU inseamna corpus gresit, inseamna editie RDS care nu acopera
    versiunea de Windows folosita. Intrarea de decizie permite un reimport.
    """
    depozit.execute(
        "DELETE FROM reputation WHERE sha256 IN (%s)"
        % ",".join("?" * (len(SISTEM) - 2)),
        SISTEM[:-2],
    )
    depozit.commit()

    rezultate = dict((nume, trecut) for nume, trecut, _ in
                     coverage.sanity_checks(coverage.measure(intrari, depozit)))

    assert rezultate["binarele de sistem apar in RDS"] is False


# ── Amprenta declarata ──────────────────────────────────────────────────────

def test_the_report_refuses_a_snapshot_it_was_not_asked_for(intrari, depozit, tmp_path):
    """
    O cale gresita ar produce zerouri, adica cea mai flatanta cifra posibila
    despre un sistem de confidentialitate, obtinuta dintr-o greseala de tastare.
    """
    sigilat = tmp_path / "reputation.db"
    reputation_build.seal(depozit, sigilat)

    manifest = _manifest(tmp_path, intrari)

    cod = coverage.main([
        "--manifest", str(manifest),
        "--instantaneu", str(sigilat),
        "--amprenta", "0" * 64,
    ])

    assert cod == 1


def test_the_report_runs_end_to_end_on_a_sealed_snapshot(intrari, depozit, tmp_path, capsys):
    sigilat = tmp_path / "reputation.db"
    amprenta = reputation_build.seal(depozit, sigilat)

    manifest = _manifest(tmp_path, intrari)

    cod = coverage.main([
        "--manifest", str(manifest),
        "--instantaneu", str(sigilat),
        "--amprenta", amprenta,
    ])

    iesire = capsys.readouterr().out

    assert cod == 0
    assert amprenta in iesire
    assert "NSRL RDS" in iesire
    assert "TOTAL" in iesire


def test_a_report_needs_a_real_manifest(tmp_path):
    strain = tmp_path / "altceva.json"
    strain.write_text('{"nimic": 1}', encoding="utf-8")

    with pytest.raises(coverage.CoverageError):
        coverage.load_manifest(strain)
