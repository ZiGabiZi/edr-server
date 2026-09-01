import logging
from contextlib import asynccontextmanager
from logging.handlers import RotatingFileHandler
from pathlib import Path

from fastapi import FastAPI

from app.routes import agents, events, heartbeat, metrics, runs
from app.services import reputation_store
from app.services.reputation_disposition import REPUTATION_UNAVAILABLE
from app.wire_middleware import install_wire_accounting


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
#
# De ce e nevoie de configurarea asta:
#     Fără ea, mesajele emise de codul serverului nu ajungeau nicăieri anume.
#     Python le trecea prin handler-ul lui de rezervă (logging.lastResort), care
#     e o plasă de siguranță, nu o configurare: scrie textul gol pe stderr, fără
#     oră, fără nivel și fără numele modulului. Uvicorn își are propriile loguri
#     formatate, deci avertismentele noastre apăreau lângă ele ca text anonim.
#
#     Pentru un server EDR, întrebarea nu e daca ceva e stricat, ci de cand si la
#     care agent. Un avertisment fără oră nu poate fi legat de heartbeat-ul care
#     l-a produs, iar unul fără nivel nu poate fi filtrat dintre miile de linii
#     INFO ale unei zile de rulare.
#
#     Fișierul închide și a doua gaură: mesajul de pe stderr dispare odată cu
#     terminalul, iar sub un serviciu de sistem nu există niciun terminal la care
#     să te uiți. Agentul rezolva deja asta la fel (agent.py); serverul rămăsese
#     singurul din cele două fără caiet propriu.
#
# Ce NU intră aici: logurile de acces ale uvicorn. Uvicorn își configurează
# separat propriile logger-e, cu propagate dezactivat, deci server.log conține
# doar mesajele codului nostru — exact ce vrei când cauți un avertisment.

_BASE_DIR = Path(__file__).resolve().parent.parent
_LOG_FILE_PATH = _BASE_DIR / "server.log"
_LOG_FILE_MAX_BYTES: int = 10 * 1024 * 1024
_LOG_FILE_BACKUP_COUNT: int = 5

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - %(name)s - %(message)s",
    handlers=[
        RotatingFileHandler(
            _LOG_FILE_PATH,
            maxBytes=_LOG_FILE_MAX_BYTES,
            backupCount=_LOG_FILE_BACKUP_COUNT,
            encoding="utf-8",
        ),
        logging.StreamHandler(),
    ],
)

logger = logging.getLogger(__name__)


def warm_reputation_snapshot() -> None:
    """
    Deschide și amprentează instantaneul de reputație ÎNAINTE de primul eveniment.

    De ce la pornire și nu la prima nevoie, cum era:
        Amprenta e SHA-256 peste tot fișierul livrat — 3,28 GB azi, deci 8,3
        secunde măsurate. Calculată leneș, cădea pe calea de ingestie, adică pe
        PRIMUL eveniment cu hash al fiecărei porniri de server. Timeout-ul
        agentului e de 5 secunde (`edr-agent/services/transport.py`), deci acel
        prim eveniment expira garantat, de fiecare dată.

        Nu se pierdea nimic — un timeout nu e 4xx, deci coada îl reia și a doua
        încercare durează 8 ms. Dar prețul se plătea în altă parte: contabilizarea
        de fir numără FIECARE plecare, iar cererea expirată ajunsese deja la
        server și fusese cântărită. Fiecare pornire injecta deci o retransmisie
        în numărătorul măsurat al afirmației principale — mică, sistematică și
        produsă de noi, nu de rețea.

        Mutată aici, secundele se plătesc unde nu așteaptă nimeni: serverul spune
        „startup complete" mai târziu, iar prima cerere e la fel de rapidă ca a
        doua.

    Absența instantaneului NU oprește pornirea. Un server fără depozit e un
    server care răspunde `reputation_unavailable` — stare declarată, nu defect —
    iar telemetria trebuie să curgă și atunci. Cuplarea inversă e chiar decizia
    refuzată la F4.
    """
    try:
        identitate = reputation_store.snapshot_identity()
    except reputation_store.ReputationStoreError as error:
        logger.warning(
            "No reputation snapshot could be opened at startup (%s). Events "
            "carrying a hash will be answered '%s' until one is in place.",
            error,
            REPUTATION_UNAVAILABLE,
        )
        return

    logger.info(
        "Reputation snapshot ready: fingerprint %s, built %s, sources %s.",
        identitate["fingerprint"][:16],
        identitate["built_at"],
        ", ".join(
            f"{s['name']}@{s['version']} ({s['row_count']} rows)"
            for s in identitate["sources"]
        )
        or "none",
    )


@asynccontextmanager
async def lifespan(_: FastAPI):
    warm_reputation_snapshot()
    yield


app = FastAPI(
    title="EDR Server",
    description="Backend minimal pentru sistemul EDR",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health")
def health_check() -> dict:
    return {
        "status": "ok",
        "service": "EDR Server",
        "version": "0.1.0",
    }


# Contabilizarea octetilor primiti, inainte de rutare: o cerere respinsa cu 401
# nu ajunge la nicio ruta, dar octetii ei au parasit endpoint-ul si au ajuns
# aici. Vezi app/wire_middleware.py pentru de ce nu se numara in rute.
install_wire_accounting(app)


app.include_router(agents.router)
app.include_router(events.router)
app.include_router(heartbeat.router)
app.include_router(metrics.router)
app.include_router(runs.router)
