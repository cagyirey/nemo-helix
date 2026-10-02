# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import base64
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx
from fastapi import FastAPI
from fastapi.testclient import TestClient
from nhx.common.config import Configuration
from nhx.common.config.base import AuthConfig, OIDCConfig
from nhx.core.auth.oidc_broker.crypto import client_secret_basic_header, pkce_challenge
from nhx.core.auth.oidc_broker.routes import set_login_store


class MemoryLoginStore:
    def __init__(self) -> None:
        self.rows: dict[str, tuple[str, dict[str, str]]] = {}

    async def put(self, kind: str, record_id: str, payload: dict[str, str], ttl_seconds: int) -> None:
        self.rows[record_id] = (kind, dict(payload))

    async def get(self, kind: str, record_id: str):
        row = self.rows.get(record_id)
        if row is None or row[0] != kind:
            return None
        from datetime import datetime, timezone

        from nhx.core.auth.oidc_broker.store import LoginRecord

        return LoginRecord(kind=kind, payload=row[1], expires_at=datetime.now(timezone.utc))

    async def pop(self, kind: str, record_id: str):
        record = await self.get(kind, record_id)
        if record is not None:
            del self.rows[record_id]
        return record


def test_client_secret_basic_form_encodes_then_base64() -> None:
    header = client_secret_basic_header("client id", "secret/value")
    encoded = header.removeprefix("Basic ")
    decoded = base64.b64decode(encoded).decode()
    assert decoded == "client%20id:secret%2Fvalue"


def test_pkce_s256_is_stable() -> None:
    challenge = pkce_challenge("verifier")
    assert challenge
    assert "=" not in challenge
    assert challenge == pkce_challenge("verifier")


@pytest.fixture
def broker_app(monkeypatch: pytest.MonkeyPatch):
    store = MemoryLoginStore()
    set_login_store(store)
    config = AuthConfig(
        enabled=True,
        oidc=OIDCConfig(
            enabled=True,
            issuer="https://idp.example.com",
            client_id="nemo-helix-user",
            token_endpoint_auth_method="client_secret_basic",
            client_secret_env_var="NHX_OIDC_CLIENT_SECRET",
            session_encryption_key_env_var="NHX_AUTH_SESSION_ENCRYPTION_KEY",
            authorization_endpoint="https://idp.example.com/authorize",
            token_endpoint="https://idp.example.com/token",
            public_client_id="nemo-helix-cli",
        ),
    )
    Configuration.set_override(config)
    monkeypatch.setenv("NHX_OIDC_CLIENT_SECRET", "user-login-secret")
    app = FastAPI()
    from nhx.core.auth.oidc_broker.routes import router

    app.include_router(router, prefix="/apis/auth")
    yield TestClient(app), store
    set_login_store(None)
    Configuration.clear_overrides()


def test_login_uses_basic_auth_and_sets_cookie(broker_app) -> None:
    client, _store = broker_app
    id_token = (
        "e30." + base64.urlsafe_b64encode(b'{"sub":"user-1","email":"user@example.com"}').decode().rstrip("=") + ".sig"
    )
    with respx.mock:
        respx.post("https://idp.example.com/token").mock(
            return_value=httpx.Response(
                200, json={"access_token": "access", "id_token": id_token, "refresh_token": "refresh"}
            )
        )
        start = client.get("/apis/auth/v2/login", follow_redirects=False)
        assert start.status_code == 302
        query = parse_qs(urlparse(start.headers["location"]).query)
        assert query["client_id"] == ["nemo-helix-user"]
        assert query["code_challenge_method"] == ["S256"]
        assert "client_secret" not in query
        callback = client.get(
            "/apis/auth/v2/login/callback",
            params={"code": "auth-code", "state": query["state"][0]},
            follow_redirects=False,
        )
        assert callback.status_code == 302
        assert "nhx_session" in callback.cookies
        session = client.get("/apis/auth/v2/session")
        assert session.json()["id"] == "user-1"
        assert "access" not in session.text
        token_call = respx.calls.last
        assert token_call.request.headers["authorization"].startswith("Basic ")


def test_discovery_advertises_only_configured_clients() -> None:
    from nhx.core.auth.api.v2.discovery.endpoints import get_auth_discovery

    config = AuthConfig(
        enabled=True,
        oidc=OIDCConfig(
            enabled=True,
            issuer="https://idp.example.com",
            client_id="nemo-helix-user",
            token_endpoint_auth_method="client_secret_basic",
            client_secret_env_var="NHX_OIDC_CLIENT_SECRET",
            session_encryption_key_env_var="NHX_AUTH_SESSION_ENCRYPTION_KEY",
            authorization_endpoint="https://idp.example.com/authorize",
            token_endpoint="https://idp.example.com/token",
            public_client_id="nemo-helix-cli",
        ),
    )
    Configuration.set_override(config)
    try:
        import asyncio

        result = asyncio.run(get_auth_discovery())
    finally:
        Configuration.clear_overrides()
    assert result.oidc is not None
    dumped = result.oidc.model_dump()
    assert dumped["client_id"] == "nemo-helix-user"
    assert [client["name"] for client in dumped["clients"]] == ["platform", "public"]
    assert dumped["clients"][0]["default"] is True
    assert "client_secret" not in dumped
    assert "NHX_OIDC_CLIENT_SECRET" not in str(dumped)
