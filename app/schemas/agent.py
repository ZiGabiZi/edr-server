from typing import Optional
from pydantic import BaseModel


class AgentRegisterRequest(BaseModel):
    """
    Corpul acceptat la POST /api/agents/register.

    NU declara aici agent_instance_id. Incarnarea procesului este proprietatea
    exclusivă a canalului de heartbeat: register_agent() face
    existing_agent_by_id.update(agent_data), deci un agent_instance_id venit prin
    înregistrare ar suprascrie baseline-ul înainte ca primul heartbeat al noii
    incarnări să îl poată compara — și detecția de repornire n-ar mai declanșa
    niciodată. Gardat de test_event_contract.py::test_registration_does_not_adopt_the_incarnation.
    """
    
    agent_id: str
    agent_version: Optional[str] = None
    hostname: str
    operating_system: str
    architecture: str
    os_architecture: str
    machine_id_type: str
    machine_id_hash: Optional[str] = None
    ip_address: Optional[str] = None


class AgentResponse(BaseModel):
    agent_id: str
    hostname: str
    status: str
    message: Optional[str] = "Registered successfully"
