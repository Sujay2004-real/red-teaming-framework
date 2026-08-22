from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    scope_domain_ip: str = Field(min_length=1, max_length=255)
    authorized_scopes: List[str] = Field(default_factory=list)

class AssessmentCreate(BaseModel):
    target_id: int
    objective: str = Field(min_length=1, max_length=1000)
    plan: Optional[List[Dict[str, Any]]] = None
    requirements: Optional[str] = Field(default=None, max_length=30000)

class SettingsUpdate(BaseModel):
    gemini_api_key: Optional[str] = Field(default=None, max_length=10000)
    api_base_url: Optional[str] = Field(default=None, max_length=2000)
    model_name: Optional[str] = Field(default=None, max_length=255)
    proxy_url: Optional[str] = Field(default=None, max_length=2000)
    proxy_username: Optional[str] = Field(default=None, max_length=255)
    proxy_password: Optional[str] = Field(default=None, max_length=10000)

class ExecuteRequest(BaseModel):
    step_index: int = Field(ge=0)
    approved: bool = False

class PlanUpdate(BaseModel):
    plan: List[Dict[str, Any]]
