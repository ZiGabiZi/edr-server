"""
Schemele Pydantic trebuie să corespundă contractului de fir partajat cu agentul.

De ce există acest fișier:
    O cheie pe care schema nu o declară este aruncată la validare: agentul
    primește 200 OK, iar câmpul rămâne None. WireModel o loghează acum cu numele
    ei (app/schemas/wire.py), dar abia când un payload greșit ajunge efectiv la
    server, într-o rulare reală. Redenumirea unui câmp de aici nu produce nicio
    eroare nicăieri — produce date lipsă, descoperite luni mai târziu.

    edr-agent nu poate importa modulele acestea (repo-uri separate), deci până
    acum își ținea propria copie a numelor, actualizată doar din memoria unui om.
    contracts/wire-contract.json înlocuiește copia: e comis identic în ambele
    repo-uri, agentul își validează builderii față de el, iar testul de față
    validează modelele Pydantic față de același text.

    Câștigul concret: o redenumire aici pică testele *aici*, în commit-ul care o
    face — nu peste luni, în celălalt repo, dacă cineva se întâmplă să ruleze
    suita cu ambele clone pe disc.
"""

import json
import os
from pathlib import Path
from typing import Optional

import pytest

from app.schemas.agent import AgentRegisterRequest
from app.schemas.event import EventCreateRequest, EventMeasurements
from app.schemas.heartbeat import HeartbeatDirective, HeartbeatRequest, HeartbeatResponse


SERVER_REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACT_RELATIVE_PATH = Path("contracts") / "wire-contract.json"

# Documentul de autentificare, ținut lângă contractul de fir dar separat de el:
# wire-contract.json descrie CORPURI (modele, câmpuri, obligativitate), iar
# autentificarea trăiește în ANTETE, pe care contractul nu le modelează.
# Sincronizarea lui între repo-uri contează la fel de mult: numele antetelor sunt
# scrise de mână în ambele părți, iar o divergență nu produce o eroare de import,
# ci un 401 permanent care arată exact ca o cheie greșită.
AUTH_DOC_RELATIVE_PATH = Path("contracts") / "AUTH.md"

# Repo-ul pereche și variabila care îi suprascrie locația. Convenția implicită
# este că cele două clone stau una lângă alta.
PEER_REPO_NAME = "edr-agent"
PEER_PATH_ENV_VAR = "EDR_AGENT_PATH"

# Comută absența repo-ului pereche între skip și eșec.
#
#   "1"    — obligatoriu: absența e eșec de suită
#   "0"    — opțional: absența e skip
#   nesetat — obligatoriu dacă rulăm sub CI, opțional altfel
#
# De ce nu e simplu skip întotdeauna: verificările cross-repo sunt singurele
# care confruntă cele două părți ale contractului, iar un skip e o linie gri
# printre sute de puncte verzi. Pe o mașină de integrare care clonează un
# singur repo, cel mai puternic test din suită tace exact acolo unde ar trebui
# să vorbească — regresia trece, iar raportul spune „totul verde".
#
# De ce nu e simplu eșec întotdeauna: o clonă singură trebuie să rămână
# testabilă. Cine ia doar acest repo și rulează suita nu a greșit cu nimic.
#
# CI (setat de GitHub Actions, GitLab, CircleCI, Azure și altele) desparte
# cele două situații fără ca nimeni să trebuiască să-și amintească ceva.
PEER_REQUIRED_ENV_VAR = "EDR_REQUIRE_PEER_REPO"


# Legătura dintre numele logice din contract și modelele care le implementează.
# Un model adăugat în contract fără intrare aici ar rămâne nevalidat — testul
# test_every_contract_model_is_bound_to_a_schema păzește exact asta.
CONTRACT_MODELS = {
    "agent_register_request": AgentRegisterRequest,
    "event_create_request": EventCreateRequest,
    "heartbeat_request": HeartbeatRequest,
    "heartbeat_response": HeartbeatResponse,
    "heartbeat_directive": HeartbeatDirective,
    "event_measurements": EventMeasurements,
}


def load_contract(repo_root: Path = SERVER_REPO_ROOT) -> dict:
    """Citește exemplarul de contract al unui repo."""
    contract_file = repo_root / CONTRACT_RELATIVE_PATH

    if not contract_file.is_file():
        raise FileNotFoundError(
            f"Contractul de fir lipsește: {contract_file}. Fără el, schemele nu au "
            f"față de ce fi validate."
        )

    # utf-8-sig, nu utf-8: editoarele Windows salvează des cu BOM, iar json.loads
    # crapă atunci cu o eroare care nu spune nimic despre contract. Fără BOM,
    # utf-8-sig se comportă identic cu utf-8.
    return json.loads(contract_file.read_text(encoding="utf-8-sig"))


CONTRACT = load_contract()


def find_peer_repo() -> Optional[Path]:
    """
    Localizează clona edr-agent, dacă e disponibilă.

    Întoarce None când repo-ul pereche lipsește — serverul trebuie să rămână
    testabil dintr-o clonă singură. O cale explicită greșită e însă eroare, nu
    None: o variabilă de mediu scrisă greșit ar transforma verificarea de
    sincronizare exact în skip-ul tăcut pe care contractul îl elimină.
    """
    configured_path = os.environ.get(PEER_PATH_ENV_VAR)

    if configured_path:
        candidate = Path(configured_path)

        if not (candidate / CONTRACT_RELATIVE_PATH).is_file():
            raise RuntimeError(
                f"{PEER_PATH_ENV_VAR}={configured_path!r} nu conține "
                f"{CONTRACT_RELATIVE_PATH.as_posix()}. Corectează calea sau "
                f"elimină variabila."
            )

        return candidate

    sibling = SERVER_REPO_ROOT.parent / PEER_REPO_NAME

    return sibling if (sibling / CONTRACT_RELATIVE_PATH).is_file() else None


def peer_repo_is_required() -> bool:
    """Dacă absența repo-ului pereche trebuie tratată ca eșec, nu ca skip."""
    configured = os.environ.get(PEER_REQUIRED_ENV_VAR)

    if configured is not None:
        return configured.strip().lower() in {"1", "true", "yes"}

    return bool(os.environ.get("CI"))


def require_peer_repo(what_goes_unverified: str) -> Path:
    """
    Repo-ul pereche, sau capătul testului — skip ori eșec, după mediu.

    what_goes_unverified numește exact ce rămâne neverificat. Mesajul ajunge
    și în raportul de skip, și în cel de eșec: cine îl citește trebuie să afle
    ce anume nu s-a verificat, nu doar că un fișier lipsea.
    """
    peer_repo = find_peer_repo()

    if peer_repo is not None:
        return peer_repo

    message = (
        f"{PEER_REPO_NAME} nu a fost găsit lângă server, deci {what_goes_unverified} "
        f"rămâne neverificat în această rulare. Clonează cele două repo-uri "
        f"alături, sau indică {PEER_PATH_ENV_VAR} către clona {PEER_REPO_NAME}."
    )

    if peer_repo_is_required():
        pytest.fail(
            f"{message} Rulare marcată ca obligatorie "
            f"({PEER_REQUIRED_ENV_VAR}=1 sau CI setat). Dacă acest job chiar "
            f"clonează un singur repo, setează {PEER_REQUIRED_ENV_VAR}=0 — "
            f"explicit, ca golul să fie o decizie, nu o scăpare."
        )

    pytest.skip(message)


@pytest.mark.parametrize("model_name", sorted(CONTRACT_MODELS))
def test_schema_declares_exactly_the_fields_the_contract_lists(model_name: str):
    """
    Egalitate, în ambele direcții.

    Un câmp dispărut din schemă e cazul periculos: agentul îl trimite mai departe,
    Pydantic îl aruncă, nimeni nu vede nimic. Un câmp apărut în schemă și absent
    din contract e mai blând, dar tot o rupere: agentul nu are de unde ști că
    există, iar contractul încetează să descrie fața reală a API-ului.
    """
    spec = CONTRACT["models"][model_name]
    schema = CONTRACT_MODELS[model_name]

    declared_by_contract = set(spec["required"]) | set(spec["optional"])
    declared_by_schema = set(schema.model_fields)

    missing_from_schema = declared_by_contract - declared_by_schema
    assert not missing_from_schema, (
        f"{schema.__name__} nu mai declară câmpuri promise de contract: "
        f"{sorted(missing_from_schema)}. Au fost redenumite sau șterse; orice "
        f"payload care le mai trimite e aruncat la validare. Dacă schimbarea "
        f"e intenționată, actualizează contracts/wire-contract.json în ambele "
        f"repo-uri și incrementează contract_version."
    )

    absent_from_contract = declared_by_schema - declared_by_contract
    assert not absent_from_contract, (
        f"{schema.__name__} declară câmpuri necunoscute contractului: "
        f"{sorted(absent_from_contract)}. Adaugă-le în contract (în ambele "
        f"repo-uri) — altfel agentul nu are de unde afla că le poate folosi."
    )


@pytest.mark.parametrize("model_name", sorted(CONTRACT_MODELS))
def test_schema_agrees_with_the_contract_on_what_is_mandatory(model_name: str):
    """
    Obligativitatea nu e un detaliu de documentație: un câmp care primește o
    valoare implicită încetează să mai fie cerut, iar un emitent care nu-l mai
    trimite trece de validare și lasă un None în store. Invers, un câmp care își
    pierde valoarea implicită începe să întoarcă 422 unor agenți care funcționau.
    """
    spec = CONTRACT["models"][model_name]
    schema = CONTRACT_MODELS[model_name]

    required_by_contract = set(spec["required"])
    required_by_schema = {
        name for name, field in schema.model_fields.items() if field.is_required()
    }

    assert required_by_schema == required_by_contract, (
        f"{schema.__name__} și contractul nu sunt de acord ce e obligatoriu. "
        f"Obligatorii doar în schemă (agenții conformi primesc 422): "
        f"{sorted(required_by_schema - required_by_contract)}. Obligatorii doar în "
        f"contract (schema acceptă tăcut absența lor): "
        f"{sorted(required_by_contract - required_by_schema)}."
    )


@pytest.mark.parametrize("model_name", sorted(CONTRACT_MODELS))
def test_schema_does_not_declare_a_field_the_contract_forbids(model_name: str):
    """
    Câmpurile interzise nu sunt curățenie: fiecare are în contract, la 'notes',
    invarianta pe care prezența lui o rupe. Cazul concret e agent_instance_id în
    AgentRegisterRequest — declarat acolo, reînregistrarea de la repornire
    suprascrie baseline-ul incarnării prin update(), iar restart_detected nu mai
    devine True niciodată.
    """
    spec = CONTRACT["models"][model_name]
    schema = CONTRACT_MODELS[model_name]

    declared_but_forbidden = set(spec["forbidden"]) & set(schema.model_fields)

    assert not declared_but_forbidden, (
        f"{schema.__name__} declară câmpuri interzise de contract: "
        f"{sorted(declared_but_forbidden)}. Motivul interdicției e în "
        f"contracts/wire-contract.json, la models.{model_name}.notes."
    )


def test_every_contract_model_is_bound_to_a_schema():
    """
    Fără această verificare, contractul poate crește fără ca serverul să observe:
    un model adăugat în JSON, dar nelegat de o clasă aici, ar fi validat doar de
    agent. Testele ar rămâne verzi tocmai pentru că nimeni nu le-a scris.
    """
    assert set(CONTRACT["models"]) == set(CONTRACT_MODELS), (
        f"Modele din contract fără schemă legată: "
        f"{sorted(set(CONTRACT['models']) - set(CONTRACT_MODELS))}. "
        f"Legături fără model în contract: "
        f"{sorted(set(CONTRACT_MODELS) - set(CONTRACT['models']))}."
    )


def test_the_peer_repository_carries_the_same_contract():
    """
    Contractul își câștigă rostul doar dacă ambele repo-uri validează *același*
    text. Un exemplar actualizat pe o singură parte readuce exact problema pe care
    fișierul o rezolvă — doar că mai greu de observat, pentru că acum arată ca un
    mecanism care funcționează.
    """
    peer_repo = require_peer_repo(
        "sincronizarea celor două exemplare de contract"
    )
    peer_contract = load_contract(peer_repo)

    # Comparăm JSON-ul parsat, nu octeții: repo-urile sunt clonate și pe Windows,
    # și prin WSL, iar o diferență CRLF/LF ar produce eșecuri false care n-au
    # nicio legătură cu numele de pe fir.
    assert peer_contract.get("contract_version") == CONTRACT["contract_version"], (
        f"Exemplarele de contract sunt la versiuni diferite (local "
        f"v{CONTRACT['contract_version']}, {peer_repo.name} "
        f"v{peer_contract.get('contract_version')}). Copiază versiunea nouă în "
        f"repo-ul rămas în urmă — până atunci, cele două părți validează reguli "
        f"diferite."
    )

    # Aceeași versiune, conținut diferit: cineva a editat un exemplar fără să
    # incrementeze. Raportăm modelele care diferă, nu întregul JSON.
    peer_models = peer_contract["models"]
    local_models = CONTRACT["models"]
    differing_models = sorted(
        name
        for name in set(local_models) | set(peer_models)
        if local_models.get(name) != peer_models.get(name)
    )

    assert not differing_models, (
        f"Exemplarele au aceeași versiune, dar descriu diferit modelele: "
        f"{differing_models}. Un exemplar a fost editat fără să fie propagat."
    )

    assert peer_contract == CONTRACT, "Exemplarele diferă în afara secțiunii 'models'."


def _read_auth_document(repo_root: Path) -> str:
    """
    Citește AUTH.md normalizând terminatoarele de linie.

    Repo-urile sunt clonate și pe Windows, și prin WSL; o diferență CRLF/LF ar
    produce un eșec fals care n-are nicio legătură cu numele antetelor.
    """
    document = repo_root / AUTH_DOC_RELATIVE_PATH

    if not document.is_file():
        raise FileNotFoundError(
            f"Documentul de autentificare lipsește: {document}. Fără el, numele "
            f"antetelor rămân o convenție ținută minte de un om."
        )

    return document.read_text(encoding="utf-8-sig").replace("\r\n", "\n")


def test_the_peer_repository_carries_the_same_auth_document():
    """
    Cele două exemplare de AUTH.md trebuie să spună același lucru.

    Un exemplar actualizat pe o singură parte e mai periculos aici decât la
    contractul de fir: acolo divergența pică un test de schemă, aici produce un
    agent care trimite `X-Agent-Key` unui server care așteaptă altceva. Rezultatul
    e 401 la fiecare cerere — adică exact simptomul unei chei greșite, căutat în
    locul greșit.
    """
    peer_repo = require_peer_repo(
        "sincronizarea celor două exemplare de AUTH.md"
    )

    assert _read_auth_document(peer_repo) == _read_auth_document(SERVER_REPO_ROOT), (
        f"Exemplarele de AUTH.md diferă între server și {peer_repo.name}. "
        f"Copiază versiunea nouă în repo-ul rămas în urmă."
    )
