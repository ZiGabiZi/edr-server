import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from fastapi import FastAPI

from app.routes import agents, events, heartbeat, metrics
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

app = FastAPI(
    title="EDR Server",
    description="Backend minimal pentru sistemul EDR",
    version="0.1.0",
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
