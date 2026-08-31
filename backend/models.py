from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator

MAX_AUTHORIZED_SCOPES = 50
MAX_SCOPE_CHARS = 255
# A client letter can only restrict tools the framework can run; anything
# longer than a tool name is noise from a misparsed document.
MAX_RESTRICTED_TOOLS = 20
MAX_TOOL_CHARS = 64
# The provider endpoint is an OpenAI-compatible REST API, so only HTTP applies.
PROVIDER_SCHEMES = ('http', 'https')
# HTTP_PROXY/HTTPS_PROXY are handed to curl and nuclei, both of which accept a
# SOCKS proxy there, so restricting this to HTTP would drop a real capability.
PROXY_SCHEMES = ('http', 'https', 'socks4', 'socks4a', 'socks5', 'socks5h')


def _required_text(value: str) -> str:
    """Reject a value that is only whitespace, and store it stripped.

    min_length runs against the raw string, so '   ' satisfies it and then
    strips to nothing downstream. A target whose scope is '' matches no
    authorized scope, so every command against it failed policy review with a
    confusing message instead of the field being rejected at the edge.
    """
    stripped = (value or '').strip()
    if not stripped:
        raise ValueError('must not be blank')
    return stripped


def _checked_url(value: Optional[str], schemes: tuple) -> Optional[str]:
    """Reject a URL whose scheme can never work, and pass '' through as a clear.

    Caught here, the operator is told which field is wrong. Caught later, a bad
    scheme surfaces as "the AI provider could not be reached", which points at
    the network instead of the typo.
    """
    if value is None:
        return value
    stripped = value.strip()
    if stripped and urlparse(stripped).scheme not in schemes:
        raise ValueError('must start with ' + ' or '.join(f'{scheme}://' for scheme in schemes))
    return stripped


class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    scope_domain_ip: str = Field(min_length=1, max_length=255)
    authorized_scopes: List[str] = Field(default_factory=list)
    criticality: int = Field(default=70, ge=0, le=100)
    # Tools the client's engagement letter rules out for this target; enforced
    # at approval time in addition to the global policy engine.
    restricted_tools: List[str] = Field(default_factory=list)

    _strip_name = field_validator('name', 'scope_domain_ip')(_required_text)

    @field_validator('authorized_scopes')
    @classmethod
    def _clean_scopes(cls, value: List[str]) -> List[str]:
        scopes = [scope.strip() for scope in value if isinstance(scope, str) and scope.strip()]
        if len(scopes) > MAX_AUTHORIZED_SCOPES:
            raise ValueError(f'cannot list more than {MAX_AUTHORIZED_SCOPES} authorized scopes')
        if any(len(scope) > MAX_SCOPE_CHARS for scope in scopes):
            raise ValueError(f'each authorized scope must be {MAX_SCOPE_CHARS} characters or fewer')
        return scopes

    @field_validator('restricted_tools')
    @classmethod
    def _clean_restricted_tools(cls, value: List[str]) -> List[str]:
        tools = [tool.strip() for tool in value if isinstance(tool, str) and tool.strip()]
        if len(tools) > MAX_RESTRICTED_TOOLS:
            raise ValueError(f'cannot list more than {MAX_RESTRICTED_TOOLS} restricted tools')
        if any(len(tool) > MAX_TOOL_CHARS for tool in tools):
            raise ValueError(f'each restricted tool name must be {MAX_TOOL_CHARS} characters or fewer')
        return tools


MAX_BRIEF_ITEMS = 100
MAX_BRIEF_CHARS = 20000


class AssessmentCreate(BaseModel):
    target_id: int
    objective: str = Field(min_length=1, max_length=1000)
    plan: Optional[List[Dict[str, Any]]] = None
    requirements: Optional[str] = Field(default=None, max_length=30000)
    # The parsed engagement letter, so the planner and report work from the
    # structured brief the operator reviewed instead of raw letter text.
    engagement_brief: Optional[Dict[str, Any]] = None

    _strip_objective = field_validator('objective')(_required_text)

    @field_validator('engagement_brief')
    @classmethod
    def _bounded_brief(cls, value: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if value is None:
            return None
        # The brief is written by the parser, but it round-trips through the
        # browser, so the same bounds the parser works within apply here too.
        for key, items in value.items():
            if isinstance(items, list) and len(items) > MAX_BRIEF_ITEMS:
                raise ValueError(f'engagement brief field "{key}" cannot hold more than {MAX_BRIEF_ITEMS} items')
        if len(str(value)) > MAX_BRIEF_CHARS:
            raise ValueError(f'engagement brief must be {MAX_BRIEF_CHARS} characters or fewer')
        return value


class SettingsUpdate(BaseModel):
    gemini_api_key: Optional[str] = Field(default=None, max_length=10000)
    api_base_url: Optional[str] = Field(default=None, max_length=2000)
    model_name: Optional[str] = Field(default=None, max_length=255)
    proxy_url: Optional[str] = Field(default=None, max_length=2000)
    proxy_username: Optional[str] = Field(default=None, max_length=255)
    proxy_password: Optional[str] = Field(default=None, max_length=10000)

    @field_validator('api_base_url')
    @classmethod
    def _provider_scheme(cls, value: Optional[str]) -> Optional[str]:
        return _checked_url(value, PROVIDER_SCHEMES)

    @field_validator('proxy_url')
    @classmethod
    def _proxy_scheme(cls, value: Optional[str]) -> Optional[str]:
        return _checked_url(value, PROXY_SCHEMES)


class ExecuteRequest(BaseModel):
    step_index: int = Field(ge=0)
    approved: bool = False


class PlanUpdate(BaseModel):
    plan: List[Dict[str, Any]]
