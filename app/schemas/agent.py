from typing import Optional
from pydantic import BaseModel


class AgentRegisterRequest(BaseModel):
    agent_id: str
    hostname: str
    operating_system: str
    ip_address: Optional[str] = None


class AgentResponse(BaseModel):
    agent_id: str
    hostname: str
    operating_system: str
    ip_address: Optional[str] = None
    status: str
