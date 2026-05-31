from fastapi import FastAPI

from app.routes import agents, events

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


app.include_router(agents.router)
app.include_router(events.router)
