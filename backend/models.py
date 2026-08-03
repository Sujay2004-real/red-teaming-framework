from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime

class TargetBase(BaseModel):
    name: str
    scope_domain_ip: str

class TargetCreate(TargetBase):
    pass

class Target(TargetBase):
    id: int
    created_at: datetime
    class Config:
        orm_mode = True

class AssessmentBase(BaseModel):
    target_id: int
    objective: str

class AssessmentCreate(AssessmentBase):
    pass

class Assessment(AssessmentBase):
    id: int
    status: str
    plan: Optional[List[Dict[str, Any]]]
    created_at: datetime
    class Config:
        orm_mode = True

class ToolExecutionBase(BaseModel):
    assessment_id: int
    tool_name: str
    command: str

class ToolExecutionCreate(ToolExecutionBase):
    pass

class ToolExecution(ToolExecutionBase):
    id: int
    stdout: Optional[str]
    stderr: Optional[str]
    return_code: Optional[int]
    executed_at: datetime
    class Config:
        orm_mode = True

class FindingBase(BaseModel):
    assessment_id: int
    title: str
    description: str
    severity: str
    evidence: str
    remediation: str

class FindingCreate(FindingBase):
    pass

class Finding(FindingBase):
    id: int
    class Config:
        orm_mode = True
