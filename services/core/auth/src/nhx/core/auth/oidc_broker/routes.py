# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Confidential OIDC login broker.

The auth service is the OAuth client. Studio receives an HTTP-only session
cookie. The CLI receives a user access token after a localhost one-time code
exchange. The client secret never leaves this service.
"""

from __future__ import annotations

import base64
import json
import secrets
from typing import Annotated
from urllib.parse import urlencode, urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from nhx.common.config import get_auth_config
from nhx.core.auth.oidc_broker.crypto import client_secret_basic_header, pkce_challenge, read_env
from nhx.core.auth.oidc_broker.store import OidcLoginStore
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

router = APIRouter(tags=["Authentication"])

SESSION_COOKIE = "nhx_session"
CSRF_HEADER = "x-nhx-requested-by"
_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}

_store_override: object | None = None


class CliLoginStart(BaseModel):
    redirect_uri: str


class CliTokenRequest(BaseModel):
    grant_type: str
    code: str | None = None
    refresh_token: str | None = None


def set_login_store(store: object | None) -> None:
    """Install a store for tests. Production leaves this unset."""
    global _store_override
    _store_override = store


async def get_login_store() -> OidcLoginStore:
    if _store_override is not None:
        return _store_override  # type: ignore[return-value]
    auth = get_auth_config()
    oidc = auth.oidc
    if oidc.token_endpoint_auth_method != "client_secret_basic":
        raise HTTPException(status_code=404, detail="Confidential OIDC login is not configured")
    if not oidc.session_encryption_key_env_var:
        raise HTTPException(status_code=503, detail="Session encryption is not configured")
    from nhx.core.entities.app.repository import get_async_session_maker

    try:
        key = read_env(oidc.session_encryption_key_env_var)
        session_maker = await get_async_session_maker()
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail="Confidential OIDC login is not available") from exc
    return OidcLoginStore(session_maker, key)


LoginStore = Annotated[OidcLoginStore, Depends(get_login_store)]


def _require_confidential() -> None:
    oidc = get_auth_config().oidc
    if oidc.token_endpoint_auth_method != "client_secret_basic":
        raise HTTPException(status_code=404, detail="Confidential OIDC login is not configured")
    if not oidc.client_secret_env_var or not oidc.token_endpoint or not oidc.authorization_endpoint:
        raise HTTPException(status_code=503, detail="Confidential OIDC login is not available")


def _client_secret() -> str:
    oidc = get_auth_config().oidc
    if not oidc.client_secret_env_var:
        raise HTTPException(status_code=503, detail="Confidential OIDC login is not available")
    try:
        return read_env(oidc.client_secret_env_var)
    except ValueError as exc:
        raise HTTPException(status_code=503, detail="Confidential OIDC login is not available") from exc


def _redirect_uri(request: Request) -> str:
    configured = get_auth_config().oidc.login_redirect_uri
    if configured:
        return configured
    return str(request.base_url).rstrip("/") + "/apis/auth/v2/login/callback"


def _claims_from_tokens(token_payload: dict[str, object]) -> dict[str, str]:
    id_token = token_payload.get("id_token")
    claims: dict[str, str] = {}
    if isinstance(id_token, str) and id_token.count(".") >= 2:
        payload = id_token.split(".")[1]
        padding = "=" * (-len(payload) % 4)
        try:
            decoded = json.loads(base64.urlsafe_b64decode(payload + padding))
        except (ValueError, json.JSONDecodeError):
            decoded = {}
        if isinstance(decoded, dict):
            for key in ("sub", "email", "name"):
                value = decoded.get(key)
                if isinstance(value, str):
                    claims[key] = value
    if "sub" not in claims:
        claims["sub"] = "unknown"
    return claims


async def _finish_cli_login(payload: dict[str, str], code: str, store: OidcLoginStore) -> RedirectResponse:
    tokens = await _exchange_code(code, payload["verifier"], payload["idp_redirect_uri"])
    one_time = secrets.token_urlsafe(32)
    stored = {"access_token": str(tokens["access_token"])}
    refresh_token = tokens.get("refresh_token")
    if isinstance(refresh_token, str):
        stored["refresh_token"] = refresh_token
    await store.put("cli_code", one_time, stored, ttl_seconds=120)
    separator = "&" if "?" in payload["redirect_uri"] else "?"
    return RedirectResponse(f"{payload['redirect_uri']}{separator}code={one_time}", status_code=302)


async def _exchange_code(code: str, verifier: str, redirect_uri: str) -> dict[str, object]:
    oidc = get_auth_config().oidc
    if not oidc.token_endpoint:
        raise HTTPException(status_code=503, detail="Confidential OIDC login is not available")
    response = await _post_token(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        }
    )
    return response


async def _post_token(form: dict[str, str]) -> dict[str, object]:
    oidc = get_auth_config().oidc
    if not oidc.token_endpoint:
        raise HTTPException(status_code=503, detail="Confidential OIDC login is not available")
    headers = {"Authorization": client_secret_basic_header(oidc.client_id, _client_secret())}
    async with httpx.AsyncClient() as client:
        response = await client.post(oidc.token_endpoint, data=form, headers=headers)
    if response.status_code != 200:
        raise HTTPException(status_code=502, detail="Identity provider token request failed")
    payload = response.json()
    if not isinstance(payload, dict) or not isinstance(payload.get("access_token"), str):
        raise HTTPException(status_code=502, detail="Identity provider token response was incomplete")
    return payload


def _loopback_redirect(redirect_uri: str) -> None:
    parsed = urlparse(redirect_uri)
    if parsed.scheme != "http" or parsed.hostname not in _LOOPBACK_HOSTS:
        raise HTTPException(status_code=400, detail="CLI redirect_uri must be an http loopback address")


@router.get("/v2/login")
async def start_login(request: Request, store: LoginStore, return_to: str = "/") -> RedirectResponse:
    _require_confidential()
    verifier = secrets.token_urlsafe(48)
    state = secrets.token_urlsafe(24)
    await store.put(
        "studio_txn",
        state,
        {"verifier": verifier, "return_to": return_to, "redirect_uri": _redirect_uri(request)},
        ttl_seconds=600,
    )
    query = urlencode(
        {
            "response_type": "code",
            "client_id": get_auth_config().oidc.client_id,
            "redirect_uri": _redirect_uri(request),
            "state": state,
            "code_challenge": pkce_challenge(verifier),
            "code_challenge_method": "S256",
            "scope": get_auth_config().oidc.default_scopes,
        }
    )
    authorization_endpoint = get_auth_config().oidc.authorization_endpoint
    return RedirectResponse(f"{authorization_endpoint}?{query}", status_code=302)


@router.get("/v2/login/callback")
async def login_callback(
    request: Request,
    store: LoginStore,
    code: str,
    state: str,
) -> RedirectResponse:
    _require_confidential()
    cli_record = await store.pop("cli_txn", state)
    if cli_record is not None:
        return await _finish_cli_login(cli_record.payload, code, store)
    record = await store.pop("studio_txn", state)
    if record is None:
        raise HTTPException(status_code=400, detail="Login transaction was not found")
    tokens = await _exchange_code(code, record.payload["verifier"], record.payload["redirect_uri"])
    session_id = secrets.token_urlsafe(32)
    claims = _claims_from_tokens(tokens)
    await store.put("session", session_id, claims, ttl_seconds=60 * 60 * 8)
    response = RedirectResponse(record.payload.get("return_to") or "/", status_code=302)
    response.set_cookie(
        SESSION_COOKIE,
        session_id,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="lax",
        path="/",
    )
    return response


@router.post("/v2/logout")
async def logout(request: Request, store: LoginStore) -> Response:
    if request.headers.get(CSRF_HEADER) != "1":
        raise HTTPException(status_code=403, detail="Missing X-NHX-Requested-By")
    session_id = request.cookies.get(SESSION_COOKIE)
    if session_id:
        await store.pop("session", session_id)
    response = Response(status_code=204)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@router.get("/v2/session")
async def session(request: Request, store: LoginStore) -> dict[str, str]:
    session_id = request.cookies.get(SESSION_COOKIE)
    if not session_id:
        raise HTTPException(status_code=401, detail="Missing session")
    record = await store.get("session", session_id)
    if record is None:
        raise HTTPException(status_code=401, detail="Missing session")
    return {"id": record.payload.get("sub", ""), "email": record.payload.get("email", "")}


@router.post("/v2/cli/login")
async def start_cli_login(body: CliLoginStart, request: Request, store: LoginStore) -> dict[str, str]:
    _require_confidential()
    _loopback_redirect(body.redirect_uri)
    verifier = secrets.token_urlsafe(48)
    transaction_id = secrets.token_urlsafe(24)
    await store.put(
        "cli_txn",
        transaction_id,
        {
            "verifier": verifier,
            "redirect_uri": body.redirect_uri,
            "idp_redirect_uri": _redirect_uri(request),
        },
        ttl_seconds=600,
    )
    login_url = str(request.base_url).rstrip("/") + f"/apis/auth/v2/cli/login/{transaction_id}"
    return {"login_url": login_url, "transaction_id": transaction_id}


@router.get("/v2/cli/login/{transaction_id}")
async def continue_cli_login(transaction_id: str, store: LoginStore) -> RedirectResponse:
    _require_confidential()
    record = await store.get("cli_txn", transaction_id)
    if record is None:
        raise HTTPException(status_code=400, detail="Login transaction was not found")
    query = urlencode(
        {
            "response_type": "code",
            "client_id": get_auth_config().oidc.client_id,
            "redirect_uri": record.payload["idp_redirect_uri"],
            "state": transaction_id,
            "code_challenge": pkce_challenge(record.payload["verifier"]),
            "code_challenge_method": "S256",
            "scope": get_auth_config().oidc.default_scopes,
        }
    )
    authorization_endpoint = get_auth_config().oidc.authorization_endpoint
    return RedirectResponse(f"{authorization_endpoint}?{query}", status_code=302)


@router.post("/v2/cli/token")
async def cli_token(body: CliTokenRequest, store: LoginStore) -> dict[str, str | int]:
    _require_confidential()
    if body.grant_type == "authorization_code":
        if not body.code:
            raise HTTPException(status_code=400, detail="code is required")
        record = await store.pop("cli_code", body.code)
        if record is None:
            raise HTTPException(status_code=400, detail="Login code was not found")
        if "refresh_token" in record.payload:
            await store.put(
                "cli_refresh",
                record.payload["refresh_token"],
                record.payload,
                ttl_seconds=60 * 60 * 24 * 30,
            )
        return _token_response(record.payload)
    if body.grant_type == "refresh_token":
        if not body.refresh_token:
            raise HTTPException(status_code=400, detail="refresh_token is required")
        stored = await store.get("cli_refresh", body.refresh_token)
        if stored is None:
            raise HTTPException(status_code=400, detail="Refresh token was not found")
        refreshed = await _post_token({"grant_type": "refresh_token", "refresh_token": body.refresh_token})
        await store.pop("cli_refresh", body.refresh_token)
        payload = {"access_token": str(refreshed["access_token"])}
        new_refresh = refreshed.get("refresh_token")
        payload["refresh_token"] = str(new_refresh) if isinstance(new_refresh, str) else body.refresh_token
        await store.put("cli_refresh", payload["refresh_token"], payload, ttl_seconds=60 * 60 * 24 * 30)
        return _token_response(payload)
    raise HTTPException(status_code=400, detail="Unsupported grant_type")


def _token_response(payload: dict[str, str]) -> dict[str, str | int]:
    response: dict[str, str | int] = {
        "access_token": payload["access_token"],
        "token_type": "Bearer",
        "expires_in": 3600,
    }
    if "refresh_token" in payload:
        response["refresh_token"] = payload["refresh_token"]
    return response


async def sqlite_store(database_url: str, encryption_key: str) -> tuple[OidcLoginStore, object]:
    """Create an isolated store for tests."""
    engine = create_async_engine(database_url)
    from nhx.core.auth.oidc_broker.store import DBOIDCLoginRecord

    async with engine.begin() as connection:
        await connection.run_sync(DBOIDCLoginRecord.__table__.create)
    session_maker: async_sessionmaker[AsyncSession] = async_sessionmaker(engine, expire_on_commit=False)
    return OidcLoginStore(session_maker, encryption_key), engine
