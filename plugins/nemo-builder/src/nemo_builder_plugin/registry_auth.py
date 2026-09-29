# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Registry credentials, obtained from the registry's own token service."""

from __future__ import annotations

import base64
import binascii
import json
import logging
import re
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx

logger = logging.getLogger(__name__)

#: One `WWW-Authenticate` challenge's scheme, then each of its parameters, read per challenge: a
#: header can carry several, and httpx joins repeated headers with `, `.
_SCHEME = re.compile(r"[\s,]*([A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]*)(?=\s|$)")
_PARAM = re.compile(r'\s*([A-Za-z0-9!#$%&\'*+.^_`|~-]+)\s*=\s*("(?:[^"\\]|\\.)*"|[^\s,]*)\s*(?:,|$)')

#: What the token specification says a token lives for when the service does not say.
_DEFAULT_EXPIRES_IN = 60


def parse_challenges(header: str) -> list[tuple[str, dict[str, str]]]:
    """``[(scheme, {param: value})]``, schemes and parameter names lowercased (RFC 9110)."""
    challenges: list[tuple[str, dict[str, str]]] = []
    position = 0
    while scheme := _SCHEME.match(header, position):
        position = scheme.end()
        params: dict[str, str] = {}
        while param := _PARAM.match(header, position):
            value = param.group(2)
            if value.startswith('"'):
                value = re.sub(r"\\(.)", r"\1", value[1:-1])
            params[param.group(1).lower()] = value
            position = param.end()
        challenges.append((scheme.group(1).lower(), params))
    return challenges


class RegistryAuthError(Exception):
    """No credential could be obtained: the registry or its token service failed, or refused."""


class ScopeWidened(RegistryAuthError):
    """The token service granted more than was asked for, where it is required not to."""


class CredentialReturned(RegistryAuthError):
    """The token service returned the credential it was given, not a token for the scope asked."""


@dataclass(frozen=True, slots=True)
class IssuedToken:
    token: str
    expires_in: int
    #: Whether the token stays within what was asked for; None when it is opaque.
    narrowed: bool | None
    #: What the token's `access` claim grants, as `<type>:<name>:<actions>`; None when it is opaque.
    granted: tuple[str, ...] | None = None
    #: The token's `jti`, if it states one.
    token_id: str | None = None


class CredentialSource(Protocol):
    """The builder's own credential for the registry's token service."""

    def read(self) -> tuple[str, str]:
        """``(username, password)``, read fresh: the source may have rotated since the last call."""
        ...


class RegistryCredentials(Protocol):
    """How the builder obtains a scoped, short-lived credential for one registry."""

    def issue(self, repositories: Sequence[str], actions: Sequence[str]) -> IssuedToken:
        """A token for exactly ``actions`` on each of ``repositories``. Raises :class:`RegistryAuthError`."""
        ...


@dataclass(frozen=True, slots=True)
class FileCredential:
    username: str
    password_file: Path

    def read(self) -> tuple[str, str]:
        try:
            password = Path(self.password_file).read_text().strip()
        except OSError as exc:
            raise RegistryAuthError(f"cannot read the builder's registry credential: {exc}") from exc
        if not password:
            raise RegistryAuthError(f"the builder's registry credential at {self.password_file} is empty")
        return self.username, password


def _jwt_claims(token: str) -> dict[str, Any] | None:
    """A JWT's claims, unverified -- or None if the token is not a readable JWT.

    Only read to report what the token grants and for how long: the registry verifies it.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    return claims if isinstance(claims, dict) else None


def _jwt_access(token: str) -> list[object] | None:
    access = (_jwt_claims(token) or {}).get("access")
    return access if isinstance(access, list) else None


def _jwt_grants(token: str) -> tuple[str, ...] | None:
    access = _jwt_access(token)
    if access is None:
        return None
    grants = []
    for entry in access:
        if not isinstance(entry, dict):
            grants.append(repr(entry))
            continue
        actions = entry.get("actions")
        listed = ",".join(str(a) for a in actions) if isinstance(actions, list) else repr(actions)
        grants.append(f"{entry.get('type')}:{entry.get('name')}:{listed}")
    return tuple(grants)


def _jwt_lifetime(token: str, *, now: float) -> int | None:
    expiry = (_jwt_claims(token) or {}).get("exp")
    if not isinstance(expiry, int | float) or isinstance(expiry, bool):
        return None
    return max(0, int(expiry - now))


def narrowed(token: str, repositories: Sequence[str], actions: Sequence[str]) -> bool | None:
    access = _jwt_access(token)
    if access is None:
        return None
    for entry in access:
        if not isinstance(entry, dict) or entry.get("type") != "repository":
            return False
        granted = entry.get("actions")
        if entry.get("name") not in repositories or not isinstance(granted, list):
            return False
        if any(action not in actions for action in granted):
            return False
    return True


class DistributionTokenClient:
    """:class:`RegistryCredentials` by the Distribution token specification."""

    def __init__(
        self,
        registry: str,
        credential: CredentialSource,
        *,
        plain_http: bool = False,
        require_narrowing: bool = False,
        http: httpx.Client | None = None,
        timeout: float = 15.0,
    ) -> None:
        self._registry = registry
        self._credential = credential
        self._scheme = "http" if plain_http else "https"
        self._require_narrowing = require_narrowing
        # A redirect would carry the credential somewhere the challenge never named.
        self._http = http or httpx.Client(timeout=timeout, follow_redirects=False)
        self._challenge: tuple[str, str] | None = None

    def _realm(self) -> tuple[str, str]:
        if self._challenge is not None:
            return self._challenge
        try:
            response = self._http.get(f"{self._scheme}://{self._registry}/v2/")
        except httpx.HTTPError as exc:
            raise RegistryAuthError(f"{self._registry} could not be reached: {type(exc).__name__}") from exc
        if response.status_code != 401:
            raise RegistryAuthError(
                f"{self._registry} answered /v2/ with {response.status_code}, not a 401 challenge: it does not "
                "authenticate by the token specification"
            )
        challenges = dict(parse_challenges(response.headers.get("WWW-Authenticate", "")))
        bearer = challenges.get("bearer")
        if bearer is None or not bearer.get("realm"):
            schemes = ", ".join(sorted(challenges)) or "none"
            raise RegistryAuthError(
                f"{self._registry} challenged with {schemes}, not Bearer: it does not issue scoped tokens, and "
                "the builder will not hand out its own credential instead"
            )
        realm = bearer["realm"]
        # The registry names the realm, and the credential goes to it: never in clear unless the
        # registry itself is reached in clear.
        if self._scheme == "https" and urlsplit(realm).scheme != "https":
            raise RegistryAuthError(f"{self._registry} named a token realm that is not HTTPS")
        self._challenge = (realm, bearer.get("service", self._registry))
        return self._challenge

    def issue(self, repositories: Sequence[str], actions: Sequence[str]) -> IssuedToken:
        if not repositories or not actions:
            raise ValueError("a token is issued for at least one repository and one action")
        realm, service = self._realm()
        username, password = self._credential.read()
        scope = ",".join(actions)
        params: list[tuple[str, str | int | float | None]] = [
            ("service", service),
            *(("scope", f"repository:{name}:{scope}") for name in repositories),
        ]
        try:
            response = self._http.get(realm, params=params, auth=(username, password))
        except httpx.HTTPError as exc:
            raise RegistryAuthError(
                f"{self._registry}'s token service could not be reached: {type(exc).__name__}"
            ) from exc
        if response.status_code != 200:
            # The body is not echoed: a token service's error page is not ours to repeat.
            raise RegistryAuthError(f"{self._registry}'s token service refused the builder: {response.status_code}")
        try:
            body = response.json()
        except ValueError as exc:
            raise RegistryAuthError(
                f"{self._registry}'s token service answered with something that is not JSON"
            ) from exc
        token = (body.get("token") or body.get("access_token")) if isinstance(body, dict) else None
        if not isinstance(token, str) or not token:
            raise RegistryAuthError(f"{self._registry}'s token service returned no token")
        if token == password:
            # Artifactory's does: what a push step holds must at least expire, and be no wider than asked.
            raise CredentialReturned(
                f"{self._registry}'s token service returned the credential it was given, not a token for "
                "the scope asked; the builder does not hand out its own credential"
            )
        stated = body.get("expires_in")
        if not isinstance(stated, int) or isinstance(stated, bool) or stated <= 0:
            stated = _DEFAULT_EXPIRES_IN
        lifetime = _jwt_lifetime(token, now=time.time())
        expires_in = lifetime if lifetime is not None else stated

        within = narrowed(token, repositories, actions)
        if within is False and self._require_narrowing:
            raise ScopeWidened(
                f"{self._registry}'s token service granted more than {', '.join(repositories)}:{scope}; "
                "the deployment says it narrows, so the token is refused rather than handed on"
            )
        jti = (_jwt_claims(token) or {}).get("jti")
        return IssuedToken(
            token=token,
            expires_in=expires_in,
            narrowed=within,
            granted=_jwt_grants(token),
            token_id=jti if isinstance(jti, str) and jti else None,
        )
