from typing import Optional
from pydantic import BaseModel


class AgentRegisterRequest(BaseModel):
    agent_id: str
    agent_version: Optional[str] = None
    hostname: str
    operating_system: str
    architecture: str
    os_architecture: str
    machine_id_type: str
    machine_id_hash: str
    ip_address: Optional[str] = None


class AgentResponse(BaseModel):
    agent_id: str
    hostname: str
    status: str
    message: Optional[str] = "Registered successfully"
