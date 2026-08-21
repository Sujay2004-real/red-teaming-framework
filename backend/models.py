from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    scope_domain_ip: str = Field(min_length=1, max_length=255)
    authorized_scopes: List[str] = []

class AssessmentCreate(BaseModel):
    target_id: int
    objective: str = Field(min_length=1, max_length=1000)
    plan: Optional[List[Dict[str, Any]]] = None
    requirements: Optional[str] = Field(default=None, max_length=30000)

class SettingsUpdate(BaseModel):
    gemini_api_key: Optional[str] = None
    api_base_url: Optional[str] = None
    model_name: Optional[str] = None
    proxy_url: Optional[str] = None
    proxy_username: Optional[str] = None
    proxy_password: Optional[str] = None

class ExecuteRequest(BaseModel):
    step_index: int = Field(ge=0)
    approved: bool = False

class PlanUpdate(BaseModel):
    plan: List[Dict[str, Any]]
