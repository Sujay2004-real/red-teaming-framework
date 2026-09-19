import ipaddress
import os
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator, model_validator
from datetime import datetime

from modules.phases import is_plan_phase

MAX_AUTHORIZED_SCOPES = 50
MAX_SCOPE_CHARS = 255
MAX_SUBNET_ADDRESSES = int(os.getenv('MAX_SUBNET_ADDRESSES', '256'))
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


class EngagementPolicy(BaseModel):
    excluded_scopes: List[str] = Field(default_factory=list, max_length=50)
    prohibited_tools: List[str] = Field(default_factory=list, max_length=20)
    starts_at: Optional[datetime] = None
    ends_at: Optional[datetime] = None
    max_executions: int = Field(default=100, ge=1, le=1000)
    max_rate: int = Field(default=30, ge=1, le=30)
    review_notes: str = Field(default='', max_length=4000)

    @field_validator('excluded_scopes', 'prohibited_tools')
    @classmethod
    def bounded_rules(cls, value):
        cleaned = [item.strip() for item in value if item.strip()]
        if any(len(item) > 255 or any(c in item for c in '\r\n\x00') for item in cleaned):
            raise ValueError('Rule values must be single lines of at most 255 characters')
        return list(dict.fromkeys(cleaned))

    @model_validator(mode='after')
    def window(self):
        for value in (self.starts_at, self.ends_at):
            if value and value.tzinfo is None:
                raise ValueError('Test-window timestamps must include a timezone')
        if self.starts_at and self.ends_at and self.starts_at >= self.ends_at:
            raise ValueError('Test-window end must be later than its start')
        return self


class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    scope_domain_ip: str = Field(min_length=1, max_length=255)
    authorized_scopes: List[str] = Field(default_factory=list)
    criticality: int = Field(default=70, ge=0, le=100)
    # Tools the client's engagement letter rules out for this target; enforced
    # at approval time in addition to the global policy engine.
    restricted_tools: List[str] = Field(default_factory=list)
    # True only when the letter authorizes controlled exploitation against
    # this target; the policy engine refuses exploitation-grade commands
    # (sqlmap, msfconsole, curl with a request body) otherwise.
    exploitation_authorized: bool = False
    # Opt-in aggressive lab mode: weaponized exploitation (data extraction,
    # single-command RCE, Metasploit exploit modules with payloads/sessions).
    # Only effective together with exploitation_authorized; per-step approval
    # still applies. Keep false for any target you do not fully own.
    aggressive_lab: bool = False
    engagement_policy: EngagementPolicy = Field(default_factory=EngagementPolicy)

    _strip_name = field_validator('name', 'scope_domain_ip')(_required_text)

    @field_validator('scope_domain_ip')
    @classmethod
    def _bounded_network_target(cls, value: str) -> str:
        """Keep primary CIDR sweeps within the executor's practical budget."""
        # A bare IP is a normal single-host target; ip_network would interpret
        # it as a /32 and rewrite the value, changing the existing workflow.
        if '/' not in value:
            return value
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return value
        if network.num_addresses > MAX_SUBNET_ADDRESSES:
            raise ValueError(
                f'network targets may contain at most {MAX_SUBNET_ADDRESSES} addresses; '
                'use a narrower CIDR or split the assessment into smaller ranges'
            )
        return str(network)

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
MAX_BRIEF_CHARS = 30000


def _checked_plan_step_phase(step: Dict[str, Any]) -> None:
    """Reject a plan step whose phase tag is not a real plan phase.

    A mistyped phase would silently orphan the step: it would never count
    toward any phase's completion, and the phase stepper would ignore it.
    """
    phase = step.get('phase', 'recon')
    if phase is None:
        return
    if not isinstance(phase, str) or not is_plan_phase(phase):
        raise ValueError(f'plan step phase must be one of recon / exploitation / post_exploitation, not {phase!r}')


class AssessmentCreate(BaseModel):
    target_id: int
    objective: str = Field(min_length=1, max_length=1000)
    plan: Optional[List[Dict[str, Any]]] = None
    requirements: Optional[str] = Field(default=None, max_length=30000)
    # The parsed engagement letter, so the planner and report work from the
    # structured brief the operator reviewed instead of raw letter text.
    engagement_brief: Optional[Dict[str, Any]] = None

    _strip_objective = field_validator('objective')(_required_text)

    @field_validator('plan')
    @classmethod
    def _checked_plan_phases(cls, value: Optional[List[Dict[str, Any]]]) -> Optional[List[Dict[str, Any]]]:
        if value is None:
            return value
        for step in value:
            if isinstance(step, dict):
                _checked_plan_step_phase(step)
        return value

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
    execution_mode: Optional[str] = Field(default=None, max_length=32)
    ssh_host: Optional[str] = Field(default=None, max_length=255)
    ssh_port: Optional[int] = Field(default=None, ge=1, le=65535)
    ssh_username: Optional[str] = Field(default=None, max_length=255)
    ssh_password: Optional[str] = Field(default=None, max_length=10000)
    ssh_fingerprint: Optional[str] = Field(default=None, max_length=100)
    ssh_private_key: Optional[str] = Field(default=None, max_length=20000)
    ssh_key_passphrase: Optional[str] = Field(default=None, max_length=1000)

    @field_validator('api_base_url')
    @classmethod
    def _provider_scheme(cls, value: Optional[str]) -> Optional[str]:
        return _checked_url(value, PROVIDER_SCHEMES)

    @field_validator('proxy_url')
    @classmethod
    def _proxy_scheme(cls, value: Optional[str]) -> Optional[str]:
        return _checked_url(value, PROXY_SCHEMES)

    @field_validator('execution_mode')
    @classmethod
    def _execution_mode(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        stripped = value.strip()
        if stripped not in ('local', 'kali_vm'):
            raise ValueError('must be either "local" or "kali_vm"')
        return stripped

    @field_validator('ssh_host', 'ssh_username')
    @classmethod
    def _strip_ssh_text(cls, value: Optional[str]) -> Optional[str]:
        # Not _required_text: an empty submission means "clear the field",
        # which is how every other settings field behaves.
        return value.strip() if isinstance(value, str) else value


class ExecuteRequest(BaseModel):
    step_index: int = Field(ge=0)
    approved: bool = False
    background: bool = False
    plan_version: Optional[int] = Field(default=None, ge=1)


class PlanUpdate(BaseModel):
    plan: List[Dict[str, Any]]
    plan_version: Optional[int] = Field(default=None, ge=1)

    @field_validator('plan')
    @classmethod
    def _checked_plan_phases(cls, value: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        for step in value:
            if isinstance(step, dict):
                _checked_plan_step_phase(step)
        return value
