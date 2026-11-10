"""Validated, portable scenario documents with immutable technique versions."""
import hashlib
import json
import re
from typing import Literal

from pydantic import BaseModel, Field, model_validator
from modules.phases import ALL_PLAN_PHASES
from modules.techniques import technique, validate_input

ID = r'^[a-z][a-z0-9_.-]{0,63}$'


class StrictModel(BaseModel):
    model_config = {'extra': 'forbid'}


class InputSpec(StrictModel):
    type: Literal['url', 'host', 'ports', 'parameter']
    label: str = Field(min_length=1, max_length=120)
    default: str | None = Field(default=None, max_length=1000)


class Dependency(StrictModel):
    step: str = Field(pattern=ID)
    condition: Literal['succeeded', 'failed', 'completed', 'verified'] = 'succeeded'


class Node(StrictModel):
    id: str = Field(pattern=ID)
    technique: str = Field(min_length=1, max_length=100)
    inputs: dict[str, str]
    depends_on: list[Dependency] = Field(default_factory=list, max_length=20)
    verify: dict | None = None


class Scenario(StrictModel):
    schema_version: Literal[1] = 1
    id: str = Field(pattern=ID)
    version: str = Field(pattern=r'^\d{1,3}\.\d{1,3}\.\d{1,3}$')
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(min_length=1, max_length=2000)
    inputs: dict[str, InputSpec] = Field(default_factory=dict, max_length=20)
    steps: list[Node] = Field(min_length=1, max_length=50)
    stop_on_failure: bool = False

    @model_validator(mode='after')
    def validate_graph(self):
        seen = {}
        last_phase = -1
        if any(not re.fullmatch(ID, name) for name in self.inputs):
            raise ValueError('Invalid scenario input name')
        for name, spec in self.inputs.items():
            if spec.default is not None:
                validate_input(spec.type, spec.default)
        for node in self.steps:
            adapter = technique(node.technique)
            phase = ALL_PLAN_PHASES.index(adapter.phase)
            if node.id in seen:
                raise ValueError('Step IDs must be unique')
            if phase < last_phase:
                raise ValueError('Steps must be ordered by assessment phase')
            last_phase = phase
            if set(node.inputs) != {name for name, _ in adapter.inputs}:
                raise ValueError(f'Inputs do not match {adapter.key}')
            for name, kind in adapter.inputs:
                value = node.inputs[name]
                match = re.fullmatch(r'\{\{([a-z][a-z0-9_.-]*)\}\}', value)
                if match:
                    spec = self.inputs.get(match[1])
                    if spec is None or spec.type != kind:
                        raise ValueError(f'{node.id}.{name} needs a declared {kind} input')
                else:
                    validate_input(kind, value)
            if len({dep.step for dep in node.depends_on}) != len(node.depends_on):
                raise ValueError('Dependencies must be unique')
            for dep in node.depends_on:
                if dep.step not in seen:
                    raise ValueError('Dependencies must reference earlier steps; cycles are not allowed')
                if dep.condition == 'verified' and (not seen[dep.step].verify
                        or technique(seen[dep.step].technique).phase == adapter.phase):
                    raise ValueError('Verified dependencies require an objective in an earlier analyzed phase')
            seen[node.id] = node
        if technique(self.steps[0].technique).phase != 'recon':
            raise ValueError('A scenario must start with reconnaissance')
        return self


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def bind_value(value, bindings):
    if isinstance(value, str):
        match = re.fullmatch(r'\{\{([a-z][a-z0-9_.-]*)\}\}', value)
        if match:
            if match[1] not in bindings:
                raise ValueError(f'Unknown input: {match[1]}')
            return bindings[match[1]]
    if isinstance(value, dict):
        return {key: bind_value(item, bindings) for key, item in value.items()}
    return value


def compile_scenario(document, bindings):
    from modules.objective_adapters import validate_criterion, url_identity
    scenario = Scenario.model_validate(document)
    if set(bindings) - set(scenario.inputs):
        raise ValueError('Unknown scenario inputs')
    values = {name: validate_input(spec.type, bindings.get(name, spec.default)) for name, spec in scenario.inputs.items()}
    plan, criteria = [], []
    for node in scenario.steps:
        adapter = technique(node.technique)
        step = adapter.compile(bind_value(node.inputs, values))
        step['scenario_node'] = node.id
        plan.append(step)
        if node.verify:
            criterion = validate_criterion(bind_value(node.verify, values))
            inputs = bind_value(node.inputs, values)
            supported = {'http.headers': 'http_response', 'network.services': 'tcp_service',
                         'web.sql-injection': 'sql_injection', 'web.database-banner': 'database_banner'}
            if criterion['kind'] != supported.get(adapter.id):
                raise ValueError(f'{node.id}: objective is not supported by this technique')
            if criterion['kind'] == 'tcp_service':
                matches = (criterion['endpoint'].lower().rstrip('.') == inputs['host'].lower().rstrip('.')
                           and criterion['port'] in {int(port) for port in inputs['ports'].split(',')})
            else:
                matches = url_identity(criterion['endpoint']) == url_identity(inputs['url'])
                if 'parameter' in criterion:
                    matches = matches and criterion['parameter'] == inputs['parameter']
            if not matches:
                raise ValueError(f'{node.id}: objective must match the technique target and inputs')
            criterion['node_id'] = node.id
            criteria.append(criterion)
    return {'definition': scenario.model_dump(mode='json'), 'bindings': values,
            'digest': digest(scenario.model_dump(mode='json')), 'plan_digest': digest(plan),
            'criteria': criteria}, plan


BUILTINS = [
    {'id': 'web-baseline', 'version': '1.0.0', 'name': 'Web application assessment',
     'description': 'Response headers, technology inventory, and exposure checks for one application.',
     'inputs': {'url': {'type': 'url', 'label': 'Application URL'}},
     'steps': [
         {'id': 'headers', 'technique': 'http.headers@1.0.0', 'inputs': {'url': '{{url}}'},
          'verify': {'kind': 'http_response', 'endpoint': '{{url}}'}},
         {'id': 'fingerprint', 'technique': 'http.fingerprint@1.0.0', 'inputs': {'url': '{{url}}'},
          'depends_on': [{'step': 'headers'}]},
         {'id': 'exposures', 'technique': 'web.templates@1.0.0', 'inputs': {'url': '{{url}}'},
          'depends_on': [{'step': 'headers'}]},
     ]},
    {'id': 'web-injection', 'version': '1.0.0', 'name': 'Web injection and bounded impact',
     'description': 'Verify a designated query parameter and collect database version evidence only after confirmation.',
     'inputs': {'url': {'type': 'url', 'label': 'Endpoint with query parameter'},
                'parameter': {'type': 'parameter', 'label': 'Query parameter'}},
     'steps': [
         {'id': 'headers', 'technique': 'http.headers@1.0.0', 'inputs': {'url': '{{url}}'}},
         {'id': 'injection', 'technique': 'web.sql-injection@1.0.0', 'inputs': {'url': '{{url}}', 'parameter': '{{parameter}}'},
          'depends_on': [{'step': 'headers'}], 'verify': {'kind': 'sql_injection', 'endpoint': '{{url}}', 'parameter': '{{parameter}}'}},
         {'id': 'banner', 'technique': 'web.database-banner@1.0.0', 'inputs': {'url': '{{url}}', 'parameter': '{{parameter}}'},
          'depends_on': [{'step': 'injection', 'condition': 'verified'}],
          'verify': {'kind': 'database_banner', 'endpoint': '{{url}}', 'parameter': '{{parameter}}'}},
     ]},
    {'id': 'network-inventory', 'version': '1.0.0', 'name': 'Network service assessment',
     'description': 'Inventory selected TCP services on a single host with a fixed scanner rate.',
     'inputs': {'host': {'type': 'host', 'label': 'Host or IP'},
                'ports': {'type': 'ports', 'label': 'TCP ports', 'default': '22,80,443,8080'}},
     'steps': [{'id': 'services', 'technique': 'network.services@1.0.0',
                'inputs': {'host': '{{host}}', 'ports': '{{ports}}'}}]},
]


def builtin_scenarios():
    return [Scenario.model_validate(item).model_dump(mode='json') for item in BUILTINS]
