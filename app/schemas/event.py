from typing import Optional
from pydantic import BaseModel


class EventCreateRequest(BaseModel):
    agent_id: str
    event_type: str
    client_event_id: Optional[str] = None
    file_path: Optional[str] = None
    sha256: Optional[str] = None
    description: Optional[str] = None
    occurred_at: Optional[str] = None
    agent_instance_id: Optional[str] = None


class EventResponse(BaseModel):
    event_id: int
    client_event_id: Optional[str] = None
    agent_id: str
    agent_instance_id: Optional[str] = None
    event_type: str
    file_path: Optional[str] = None
    sha256: Optional[str] = None
    description: Optional[str] = None
    occurred_at: Optional[str] = None
    received_at: Optional[str] = None
    status: str
