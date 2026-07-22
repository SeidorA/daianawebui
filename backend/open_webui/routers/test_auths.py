import base64
import hashlib
import hmac
import importlib
import json
import time
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Response, status

from open_webui.routers import auths

main = importlib.import_module('open_webui.main')


def _b64url(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data, separators=(',', ':')).encode()).decode().rstrip('=')


def _handoff_token(secret: str, payload: dict, header: dict | None = None) -> str:
    encoded_header = _b64url(header or {'alg': 'HS256', 'typ': 'JWT'})
    encoded_payload = _b64url(payload)
    signed_value = f'{encoded_header}.{encoded_payload}'.encode('utf-8')
    signature = (
        base64.urlsafe_b64encode(hmac.new(secret.encode('utf-8'), signed_value, hashlib.sha256).digest())
        .decode()
        .rstrip('=')
    )
    return f'{encoded_header}.{encoded_payload}.{signature}'


async def _get_unauthenticated_app_config(monkeypatch):
    async def fake_has_users():
        return True

    async def fake_get_many(*_keys):
        return {}

    monkeypatch.setattr(main.Users, 'has_users', fake_has_users)
    monkeypatch.setattr(main.Config, 'get_many', fake_get_many)

    return await main.get_app_config(SimpleNamespace(headers={}, cookies={}))


@pytest.mark.asyncio
async def test_app_config_exposes_return_to_origins_before_authentication(monkeypatch):
    monkeypatch.setattr(main, 'WEBUI_AUTH_RETURN_TO_ORIGINS', 'https://daiana.example.test')

    config = await _get_unauthenticated_app_config(monkeypatch)

    assert config['auth']['return_to_origins'] == 'https://daiana.example.test'


@pytest.mark.asyncio
async def test_app_config_does_not_expose_handoff_secret(monkeypatch):
    monkeypatch.setattr(auths, 'WEBUI_AUTH_HANDOFF_SECRET', 'private-handoff-secret')

    config = await _get_unauthenticated_app_config(monkeypatch)
    serialized_config = json.dumps(config)

    assert 'WEBUI_AUTH_HANDOFF_SECRET' not in serialized_config
    assert 'private-handoff-secret' not in serialized_config


def test_decode_handoff_token_accepts_signed_token_before_expiry(monkeypatch):
    secret = 'handoff-secret'
    monkeypatch.setattr(auths, 'WEBUI_AUTH_HANDOFF_SECRET', secret)
    token = _handoff_token(secret, {'email': 'User@Example.test', 'exp': int(time.time()) + 30})

    payload = auths._decode_handoff_token(token)

    assert payload['email'] == 'User@Example.test'


@pytest.mark.parametrize('expires_in', [0, -1, 61])
def test_decode_handoff_token_rejects_expired_or_too_distant_expiry(monkeypatch, expires_in):
    secret = 'handoff-secret'
    monkeypatch.setattr(auths, 'WEBUI_AUTH_HANDOFF_SECRET', secret)
    token = _handoff_token(secret, {'email': 'user@example.test', 'exp': int(time.time()) + expires_in})

    with pytest.raises(HTTPException) as exc_info:
        auths._decode_handoff_token(token)

    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST


def test_decode_handoff_token_requires_configured_secret(monkeypatch):
    monkeypatch.setattr(auths, 'WEBUI_AUTH_HANDOFF_SECRET', '')

    with pytest.raises(HTTPException) as exc_info:
        auths._decode_handoff_token('header.payload.signature')

    assert exc_info.value.status_code == status.HTTP_503_SERVICE_UNAVAILABLE


def test_decode_handoff_token_rejects_invalid_signature(monkeypatch):
    monkeypatch.setattr(auths, 'WEBUI_AUTH_HANDOFF_SECRET', 'expected-secret')
    token = _handoff_token('wrong-secret', {'email': 'user@example.test', 'exp': int(time.time()) + 30})

    with pytest.raises(HTTPException) as exc_info:
        auths._decode_handoff_token(token)

    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
async def test_handoff_creates_missing_user_and_returns_session(monkeypatch):
    secret = 'handoff-secret'
    email = 'user@example.test'
    created = []
    user = SimpleNamespace(
        id='user-id',
        email=email,
        name='User Name',
        role='user',
        profile_image_url='/avatar.png',
    )

    async def fake_get_user_by_email(*_args, **_kwargs):
        return None

    monkeypatch.setattr(auths, 'WEBUI_AUTH_HANDOFF_SECRET', secret)
    monkeypatch.setattr(auths.Users, 'get_user_by_email', fake_get_user_by_email)

    async def fake_signup_handler(
        request,
        signup_email,
        password,
        name,
        profile_image_url='/user.png',
        *,
        db,
        source='api',
    ):
        created.append({'email': signup_email, 'name': name, 'source': source})
        return user

    async def fake_authenticate_user_by_email(signin_email, db=None):
        assert signin_email == email
        return user

    async def fake_create_session_response(request, session_user, db, response, set_cookie=False, source='api'):
        assert session_user is user
        assert set_cookie is True
        assert source == 'handoff'
        return {'token': 'session-token', 'email': session_user.email, 'id': session_user.id}

    monkeypatch.setattr(auths, 'signup_handler', fake_signup_handler)
    monkeypatch.setattr(auths.Auths, 'authenticate_user_by_email', fake_authenticate_user_by_email)
    monkeypatch.setattr(auths, 'create_session_response', fake_create_session_response)

    token = _handoff_token(secret, {'email': email, 'name': 'User Name', 'exp': int(time.time()) + 30})

    result = await auths.handoff(SimpleNamespace(headers={}), Response(), auths.HandoffForm(token=token), db=object())

    assert created == [{'email': email, 'name': 'User Name', 'source': 'handoff'}]
    assert result == {'token': 'session-token', 'email': email, 'id': 'user-id'}


@pytest.mark.asyncio
async def test_delegate_rejects_when_trusted_header_auth_is_not_configured(monkeypatch):
    monkeypatch.setattr(auths, 'WEBUI_AUTH_TRUSTED_EMAIL_HEADER', '')

    with pytest.raises(HTTPException) as exc_info:
        await auths.delegated_signin(SimpleNamespace(headers={}), Response(), db=object())

    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_delegate_rejects_missing_configured_trusted_email_header(monkeypatch):
    monkeypatch.setattr(auths, 'WEBUI_AUTH_TRUSTED_EMAIL_HEADER', 'X-User-Email')

    with pytest.raises(HTTPException) as exc_info:
        await auths.delegated_signin(SimpleNamespace(headers={}), Response(), db=object())

    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
async def test_delegate_creates_missing_user_and_returns_cookie_session(monkeypatch):
    email = 'delegate@example.test'
    created = []
    user = SimpleNamespace(
        id='delegate-user-id',
        email=email,
        name='Delegate User',
        role='user',
        profile_image_url='/avatar.png',
    )

    async def fake_get_user_by_email(*_args, **_kwargs):
        return None

    async def fake_signup_handler(
        request,
        signup_email,
        password,
        name,
        profile_image_url='/user.png',
        *,
        db,
        source='api',
    ):
        created.append(
            {
                'email': signup_email,
                'name': name,
                'profile_image_url': profile_image_url,
                'source': source,
            }
        )
        return user

    async def fake_authenticate_user_by_email(signin_email, db=None):
        assert signin_email == email
        return user

    async def fake_create_session_response(request, session_user, db, response, set_cookie=False, source='api'):
        assert session_user is user
        assert set_cookie is True
        assert source == 'trusted_header'
        return {'token': 'session-token', 'email': session_user.email, 'id': session_user.id}

    monkeypatch.setattr(auths, 'WEBUI_AUTH_TRUSTED_EMAIL_HEADER', 'X-User-Email')
    monkeypatch.setattr(auths, 'WEBUI_AUTH_TRUSTED_NAME_HEADER', 'X-User-Name')
    monkeypatch.setattr(auths.Users, 'get_user_by_email', fake_get_user_by_email)
    monkeypatch.setattr(auths, 'signup_handler', fake_signup_handler)
    monkeypatch.setattr(auths.Auths, 'authenticate_user_by_email', fake_authenticate_user_by_email)
    monkeypatch.setattr(auths, 'create_session_response', fake_create_session_response)

    result = await auths.delegated_signin(
        SimpleNamespace(headers={'X-User-Email': 'Delegate@Example.test', 'X-User-Name': 'Delegate%20User'}),
        Response(),
        db=object(),
    )

    assert created == [
        {
            'email': email,
            'name': 'Delegate User',
            'profile_image_url': '/user.png',
            'source': 'trusted_header',
        }
    ]
    assert result == {'token': 'session-token', 'email': email, 'id': 'delegate-user-id'}


@pytest.mark.asyncio
async def test_delegate_syncs_trusted_groups_and_role_before_session(monkeypatch):
    initial_user = SimpleNamespace(
        id='delegate-user-id',
        email='delegate@example.test',
        name='Delegate User',
        role='user',
        profile_image_url='/avatar.png',
    )
    updated_user = SimpleNamespace(
        id='delegate-user-id',
        email='delegate@example.test',
        name='Delegate User',
        role='admin',
        profile_image_url='/avatar.png',
    )
    synced_groups = []
    updated_roles = []

    async def fake_get_user_by_email(*_args, **_kwargs):
        return initial_user

    async def fake_authenticate_user_by_email(signin_email, db=None):
        assert signin_email == initial_user.email
        return initial_user

    async def fake_sync_groups_by_group_names(user_id, group_names, db=None):
        synced_groups.append((user_id, group_names))

    async def fake_update_user_role_by_id(user_id, role, db=None):
        updated_roles.append((user_id, role))

    async def fake_get_user_by_id(user_id, db=None):
        assert user_id == initial_user.id
        return updated_user

    async def fake_create_session_response(request, session_user, db, response, set_cookie=False, source='api'):
        assert session_user is updated_user
        assert set_cookie is True
        assert source == 'trusted_header'
        return {'role': session_user.role}

    monkeypatch.setattr(auths, 'WEBUI_AUTH_TRUSTED_EMAIL_HEADER', 'X-User-Email')
    monkeypatch.setattr(auths, 'WEBUI_AUTH_TRUSTED_GROUPS_HEADER', 'X-User-Groups')
    monkeypatch.setattr(auths, 'WEBUI_AUTH_TRUSTED_ROLE_HEADER', 'X-User-Role')
    monkeypatch.setattr(auths.Users, 'get_user_by_email', fake_get_user_by_email)
    monkeypatch.setattr(auths.Auths, 'authenticate_user_by_email', fake_authenticate_user_by_email)
    monkeypatch.setattr(auths.Groups, 'sync_groups_by_group_names', fake_sync_groups_by_group_names)
    monkeypatch.setattr(auths.Users, 'update_user_role_by_id', fake_update_user_role_by_id)
    monkeypatch.setattr(auths.Users, 'get_user_by_id', fake_get_user_by_id)
    monkeypatch.setattr(auths, 'create_session_response', fake_create_session_response)

    result = await auths.delegated_signin(
        SimpleNamespace(
            headers={
                'X-User-Email': 'delegate@example.test',
                'X-User-Groups': 'admin-team, product ,',
                'X-User-Role': 'admin',
            }
        ),
        Response(),
        db=object(),
    )

    assert synced_groups == [('delegate-user-id', ['admin-team', 'product'])]
    assert updated_roles == [('delegate-user-id', 'admin')]
    assert result == {'role': 'admin'}


@pytest.mark.asyncio
async def test_signup_is_forbidden_when_trusted_header_auth_is_enabled(monkeypatch):
    monkeypatch.setattr(auths, 'WEBUI_AUTH_TRUSTED_EMAIL_HEADER', 'X-User-Email')

    with pytest.raises(HTTPException) as exc_info:
        await auths.signup(
            SimpleNamespace(headers={}),
            Response(),
            auths.SignupForm(name='User', email='user@example.test', password='password'),
            db=object(),
        )

    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
