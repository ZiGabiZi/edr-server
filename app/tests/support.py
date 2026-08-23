"""
Clientul de test care se autentifică singur.
============================================

De ce există:
    Odată cu autentificarea, fiecare scriere are nevoie de antetul X-Agent-Key,
    iar cheia se află abia din răspunsul la înregistrare. Fără ajutorul de aici,
    fiecare test existent ar fi trebuit rescris ca să poarte credențiale — și
    ar fi început să testeze autentificarea în loc de ce testa înainte.

Ce face:
    - atașează secretul de înrolare la orice cerere (harness-ul are voie să
      înroleze agenți, exact ca un instalator);
    - reține cheile emise, citindu-le din răspunsurile la /api/agents/register;
    - la fiecare cerere, deduce despre ce agent e vorba și atașează cheia lui.

Ce NU face:
    Nu ascunde autentificarea de testele care o vizează. Un test care vrea să
    verifice un 401 sau un 403 trimite antetele explicit (headers=...), iar
    valorile date de test au prioritate — setdefault, nu suprascriere.

Deducerea identității ține cont de o subtilitate reală: la heartbeat, agentul
din CALE e cel care contează, nu cel din corp. Cele două pot să difere
intenționat (cazul respins cu 400), iar dacă am semna după corp, testul acela
ar primi 401 în loc de 400 — adică ar începe să verifice altceva decât verifica.
"""

import re
from typing import Any, Dict, Optional

from fastapi.testclient import TestClient

from app.main import app
from app.services import auth_service


_HEARTBEAT_PATH = re.compile(r"/api/agents/([^/]+)/heartbeat")
_REGISTER_PATH = "/api/agents/register"


class AuthenticatingTestClient(TestClient):
    """TestClient care poartă singur credențialele parcului simulat."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.issued_keys: Dict[str, str] = {}

    def forget_keys(self) -> None:
        """Uită cheile emise. De apelat între teste, lângă golirea store-urilor."""
        self.issued_keys.clear()

    def request(self, method: str, url: Any, *args: Any, **kwargs: Any):  # type: ignore[override]
        headers = dict(kwargs.get("headers") or {})

        headers.setdefault(
            auth_service.ENROLLMENT_SECRET_HEADER,
            auth_service.get_enrollment_secret(),
        )

        agent_id = self._agent_id_for(str(url), kwargs.get("json"))
        agent_key = self.issued_keys.get(agent_id) if agent_id else None

        if agent_key is not None:
            headers.setdefault(auth_service.AGENT_KEY_HEADER, agent_key)

        kwargs["headers"] = headers
        response = super().request(method, url, *args, **kwargs)
        self._capture_issued_key(str(url), response)

        return response

    @staticmethod
    def _agent_id_for(url: str, json_body: Any) -> Optional[str]:
        heartbeat = _HEARTBEAT_PATH.search(url)
        if heartbeat:
            return heartbeat.group(1)

        if isinstance(json_body, dict):
            agent_id = json_body.get("agent_id")
            if isinstance(agent_id, str):
                return agent_id

        return None

    def _capture_issued_key(self, url: str, response: Any) -> None:
        if _REGISTER_PATH not in url or response.status_code != 200:
            return

        try:
            body = response.json()
        except ValueError:
            return

        agent_key = body.get("agent_key")
        stored_agent = body.get("agent") or {}
        agent_id = stored_agent.get("agent_id")

        if agent_key and agent_id:
            self.issued_keys[agent_id] = agent_key


def make_test_client() -> AuthenticatingTestClient:
    return AuthenticatingTestClient(app)
