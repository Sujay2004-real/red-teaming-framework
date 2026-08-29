import pytest
from pydantic import ValidationError

from models import MAX_AUTHORIZED_SCOPES, AssessmentCreate, SettingsUpdate, TargetCreate


# min_length runs against the raw string, so '   ' satisfies it and then strips
# to nothing downstream. A target whose scope is '' matches no authorized scope,
# so every command against it failed policy review with a confusing message
# instead of the field being rejected at the edge.
@pytest.mark.parametrize('payload', [
    {'name': '   ', 'scope_domain_ip': 'juice-shop'},
    {'name': 'Juice Shop', 'scope_domain_ip': '  '},
    {'name': '\u00a0', 'scope_domain_ip': 'juice-shop'},
])
def test_whitespace_only_target_fields_are_rejected(payload):
    with pytest.raises(ValidationError):
        TargetCreate(**payload)


def test_target_fields_are_stored_stripped():
    target = TargetCreate(
        name='  Juice Shop  ',
        scope_domain_ip='  juice-shop:3000  ',
        authorized_scopes=['  ', 'a.example', ' b.example '],
    )

    assert target.name == 'Juice Shop'
    assert target.scope_domain_ip == 'juice-shop:3000'
    # Blank entries are dropped rather than kept as scopes nothing can match.
    assert target.authorized_scopes == ['a.example', 'b.example']


def test_authorized_scopes_are_bounded():
    with pytest.raises(ValidationError):
        TargetCreate(
            name='Juice Shop',
            scope_domain_ip='juice-shop',
            authorized_scopes=['a.example'] * (MAX_AUTHORIZED_SCOPES + 1),
        )


def test_whitespace_only_objective_is_rejected():
    with pytest.raises(ValidationError):
        AssessmentCreate(target_id=1, objective='   ')


# Caught here, the operator is told which field is wrong. Caught later, a bad
# scheme surfaces as "the AI provider could not be reached", which points at the
# network instead of the typo.
@pytest.mark.parametrize('field,value', [
    ('api_base_url', 'https://api.example/v1'),
    ('api_base_url', 'http://localhost:11434/v1'),
    ('api_base_url', ''),
    ('proxy_url', 'http://proxy:8080'),
    # curl and nuclei both accept a SOCKS proxy in HTTP_PROXY/HTTPS_PROXY, so
    # restricting the proxy field to HTTP would drop a real capability.
    ('proxy_url', 'socks5://proxy:1080'),
    ('proxy_url', 'socks5h://proxy:1080'),
    ('proxy_url', ''),
])
def test_usable_urls_are_accepted(field, value):
    assert getattr(SettingsUpdate(**{field: value}), field) == value


@pytest.mark.parametrize('field,value', [
    ('api_base_url', 'file:///etc/passwd'),
    ('api_base_url', 'socks5://proxy:1080'),
    ('proxy_url', 'file:///etc/passwd'),
    ('proxy_url', 'ftp://proxy:21'),
])
def test_unusable_url_schemes_are_rejected(field, value):
    with pytest.raises(ValidationError):
        SettingsUpdate(**{field: value})


def test_urls_are_stored_stripped():
    assert SettingsUpdate(api_base_url='  https://api.example/v1  ').api_base_url == 'https://api.example/v1'
