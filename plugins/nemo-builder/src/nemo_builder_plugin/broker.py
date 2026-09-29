# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""The credential broker: the builder's registry credential and signing key, and who may use them.

Callers name no scope and no key: both come from the image's row, and every use is audited first.
"""

from __future__ import annotations

import json
import logging
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import httpx
from cryptography.exceptions import UnsupportedAlgorithm
from nemo_builder_plugin.config import BuilderConfig
from nemo_builder_plugin.entities import ContainerImage, Signature
from nemo_builder_plugin.identity import DIGEST_PATTERN, ImageIdentityError, compose_system_tag, validate_repository
from nemo_builder_plugin.registry import (
    INDEX_MEDIA_TYPES,
    REGISTRY_TIMEOUT_SECONDS,
    ManifestNotFound,
    Registry,
    RegistryError,
)
from nemo_builder_plugin.registry_auth import (
    DistributionTokenClient,
    FileCredential,
    RegistryAuthError,
    RegistryCredentials,
)
from nemo_builder_plugin.signing import (
    DeploymentKey,
    SignatureInvalid,
    SigningKey,
    attach_signature,
    signature_annotations,
    simple_signing_payload,
)
from nemo_helix_plugin.auth import current_auth_context, platform_auth_enabled
from nemo_helix_plugin.log_utils import sanitize_for_log
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

PUSH_ACTIONS = ("pull", "push")


class PushCredentials(BaseModel):
    """A registry token for one image's repository, as the Docker config crane reads."""

    auths: dict[str, dict[str, str]] = Field(description='`{<registry>: {"registrytoken": <token>}}`.')
    expires_in: int = Field(description="Seconds the token lives, as its token service says.")
    narrowed: bool | None = Field(
        description="Whether the token stays within the repository asked for; null when it can't be read."
    )
    repository: str


class CompleteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    digest: str = Field(
        pattern=DIGEST_PATTERN,
        description="The manifest digest the push step pushed under the image's system tag.",
    )


@dataclass(frozen=True, slots=True)
class Caller:
    """Who is asking. With platform auth off, nobody in particular."""

    auth: bool
    #: The principal the request came as: with a job's token, the job step.
    actor: str | None = None
    #: Whom the actor acts for, when it is delegated.
    submitter: str | None = None

    def audit(self) -> dict[str, object]:
        return {"actor": self.actor, "submitter": self.submitter}


def current_caller() -> Caller:
    """The caller of the current request, from the platform's auth context."""
    if not platform_auth_enabled():
        return Caller(auth=False)
    context = current_auth_context()
    if context is None:
        return Caller(auth=True)
    return Caller(auth=True, actor=context.principal_id, submitter=context.principal_on_behalf_of)


def caller_refusal(row: ContainerImage, caller: Caller) -> str | None:
    """Why ``caller`` may not publish or complete ``row``, or None if it may.

    A user's own token is refused: holding a push token, they could publish anything as built here.
    """
    if not caller.auth:
        return None
    if caller.submitter is None:
        return "only a job step acting for the image's submitter may publish or complete it"
    if caller.submitter != row.created_by:
        return f"{row.name} was submitted by someone else"
    return None


def _under(prefix: str, *parts: str) -> str:
    # The trailing slash keeps workspace `a` from matching `ab/...`.
    return "/".join(part for part in (prefix, *parts) if part) + "/"


def _within(repository: str, bound: str) -> bool:
    try:
        validate_repository(repository)
    except ImageIdentityError:
        return False
    return repository.startswith(bound)


def row_refusal(row: ContainerImage, *, registry: str, repository_prefix: str) -> str | None:
    """Why ``row`` can't be published or signed here, or None.

    Rows are data: the repository must lie under ``<repository_prefix>/<workspace>/``, and the system tag be valid.
    """
    if row.registry != registry:
        return f"{row.name} is on {row.registry}, not this deployment's registry"
    if not _within(row.repository, _under(repository_prefix, row.workspace)):
        return f"{row.name}'s repository {row.repository!r} is not a repository in workspace {row.workspace}"
    try:
        compose_system_tag(row.workspace, row.name)
    except ImageIdentityError:
        return f"{row.name} in workspace {row.workspace} has no valid system tag"
    return None


class BrokerUnconfigured(Exception):
    """A setting the broker needs is unset, so nothing can be published (409)."""


class AuditUnavailable(Exception):
    """An audit line could not be written, so nothing was issued or signed (503)."""


class TagMoved(Exception):
    """The image's system tag holds a digest other than the one the push step pushed. Nothing was signed (409)."""


class SigningFailed(Exception):
    """The registry or the key failed. No signature was recorded on the row (502)."""


@dataclass(frozen=True, slots=True)
class SignedImage:
    digest: str
    payload: bytes
    signature: bytes


class ImageSigner(Protocol):
    def sign(
        self, row: ContainerImage, *, digest: str, annotations: Mapping[str, str], record: Callable[[str], None]
    ) -> SignedImage:
        """Sign ``digest`` if ``row``'s system tag still holds it. Raises :class:`TagMoved` or :class:`SigningFailed`.

        ``record`` writes the audit line first; if it raises, nothing is signed.
        """
        ...


class KeySigner:
    """Signs with the deployment's key in cosign's format, and stores the signature where cosign looks."""

    def __init__(
        self, config: BuilderConfig, registry: RegistryCredentials, key: SigningKey, *, http: httpx.Client | None = None
    ) -> None:
        if not config.registry:
            raise ValueError("builder.registry is needed to sign")
        self._host = config.registry
        self._plain_http = config.registry_plain_http
        self._registry = registry
        self._key = key
        # A redirect would carry the token somewhere the registry never named.
        self._http = http or httpx.Client(timeout=REGISTRY_TIMEOUT_SECONDS, follow_redirects=False)

    def sign(
        self, row: ContainerImage, *, digest: str, annotations: Mapping[str, str], record: Callable[[str], None]
    ) -> SignedImage:
        try:
            # push: the signature is stored beside the image.
            issued = self._registry.issue([row.repository], list(PUSH_ACTIONS))
            registry = Registry(self._host, issued.token, http=self._http, plain_http=self._plain_http)
            # What the system tag holds is what gets signed, and only if it is what the step pushed.
            try:
                found, manifest = registry.manifest(row.repository, compose_system_tag(row.workspace, row.name))
            except ManifestNotFound:
                raise TagMoved(
                    f"{row.name}'s system tag holds nothing, not the {digest} the push step pushed"
                ) from None
            if found != digest:
                raise TagMoved(f"{row.name}'s system tag holds {found}, not the {digest} the push step pushed")
            if manifest.get("mediaType") in INDEX_MEDIA_TYPES or "manifests" in manifest:
                raise SigningFailed(
                    f"{row.repository}@{digest} is an index; this builder signs single-platform manifests"
                )
            record(digest)
            payload = simple_signing_payload(f"{self._host}/{row.repository}", digest, annotations)
            signature = self._key.sign(payload)
            attach_signature(registry, row.repository, digest, payload, signature)
        except (RegistryAuthError, RegistryError, ImageIdentityError) as exc:
            raise SigningFailed(f"{type(exc).__name__}: {exc}") from exc
        return SignedImage(digest=digest, payload=payload, signature=signature)


def _signing_key(key_file: str, password_file: str | None, trusted: DeploymentKey) -> SigningKey:
    """The deployment's private key, refused unless it is the key ``signing_public_key`` names."""
    try:
        # A mounted Secret's file often ends in a newline that was never part of the password.
        password = Path(password_file).read_bytes().rstrip(b"\r\n") if password_file else None
        key = SigningKey(Path(key_file).read_bytes(), password)
    except (OSError, ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise BrokerUnconfigured(f"builder.signing_key can't be loaded: {exc}") from exc
    if key.trust_root != trusted.trust_root:
        raise BrokerUnconfigured(
            f"builder.signing_key is not the key builder.signing_public_key names, {trusted.trust_root}"
        )
    return key


def write_audit(record: Mapping[str, object]) -> None:
    """One decision, one line on stdout, prefixed ``audit``. Raises if it can't be written."""
    sys.stdout.write("audit " + json.dumps(record, sort_keys=True) + "\n")
    sys.stdout.flush()


class Broker:
    def __init__(
        self,
        config: BuilderConfig,
        *,
        registry: RegistryCredentials,
        signer: ImageSigner,
        key: DeploymentKey,
        audit: Callable[[Mapping[str, object]], None] = write_audit,
    ) -> None:
        if not config.registry:
            raise BrokerUnconfigured("builder.registry is not configured")
        self._host = config.registry
        self._prefix = config.repository_prefix
        self._registry = registry
        self._signer = signer
        self._key = key
        self._audit = audit

    @classmethod
    def from_config(cls, config: BuilderConfig) -> Broker:
        host, username, password_file = config.registry, config.registry_username, config.registry_password_file
        key_file, public_key = config.signing_key, config.signing_public_key
        if not (host and username and password_file and key_file and public_key):
            required = ("registry", "registry_username", "registry_password_file", "signing_key", "signing_public_key")
            missing = ", ".join(f"builder.{name}" for name in required if not getattr(config, name))
            raise BrokerUnconfigured(f"{missing} not configured; nothing can be published")
        trusted = DeploymentKey(public_key)
        signing_key = _signing_key(key_file, config.signing_key_password_file, trusted)
        registry = DistributionTokenClient(
            host,
            FileCredential(username, Path(password_file)),
            plain_http=config.registry_plain_http,
            require_narrowing=config.registry_narrows_scope,
        )
        return cls(config, registry=registry, signer=KeySigner(config, registry, signing_key), key=trusted)

    def refusal(self, row: ContainerImage, caller: Caller) -> str | None:
        """Why ``caller`` may not publish or sign ``row``, whatever its status, or None."""
        return caller_refusal(row, caller) or row_refusal(row, registry=self._host, repository_prefix=self._prefix)

    def refused(self, row: ContainerImage, caller: Caller, decision: str, reason: str) -> None:
        logger.warning(
            "%s for %s/%s refused: %s",
            decision,
            sanitize_for_log(row.workspace),
            sanitize_for_log(row.name),
            sanitize_for_log(reason),
        )
        self._audit_after(
            {"decision": f"{decision}-refused", "image": row.name, "workspace": row.workspace, "reason": reason}
            | caller.audit()
        )

    def credentials(self, row: ContainerImage, caller: Caller) -> PushCredentials:
        """A registry token for ``row``'s repository. Raises ``RegistryAuthError`` or :class:`AuditUnavailable`."""
        issued = self._registry.issue([row.repository], list(PUSH_ACTIONS))
        self._record(
            {
                "decision": "credentials",
                "image": row.name,
                "workspace": row.workspace,
                "requested": [f"repository:{row.repository}:{','.join(PUSH_ACTIONS)}"],
                "granted": list(issued.granted) if issued.granted is not None else None,
                "narrowed": issued.narrowed,
                "expires_in": issued.expires_in,
                "token_id": issued.token_id,
            }
            | caller.audit()
        )
        return PushCredentials(
            auths={self._host: {"registrytoken": issued.token}},
            expires_in=issued.expires_in,
            narrowed=issued.narrowed,
            repository=row.repository,
        )

    def sign(self, row: ContainerImage, digest: str, caller: Caller) -> Signature:
        """Sign ``digest`` for ``row``, and check the signature against the deployment's public key.

        Raises :class:`TagMoved`, :class:`SigningFailed` or :class:`AuditUnavailable`.
        """
        annotations = signature_annotations(row)
        detail = {"image": row.name, "workspace": row.workspace} | caller.audit()

        def record(found: str) -> None:
            self._record({"decision": "sign", "reference": f"{row.registry}/{row.repository}@{found}"} | detail)

        try:
            signed = self._signer.sign(row, digest=digest, annotations=annotations, record=record)
            self._key.verify(signed.payload, signed.signature)
        except TagMoved as exc:
            self._audit_after({"decision": "sign-refused", "reason": str(exc)} | detail)
            raise
        except SigningFailed as exc:
            self._audit_after({"decision": "sign-failed", "reason": str(exc)} | detail)
            raise
        except SignatureInvalid as exc:
            self._audit_after({"decision": "sign-failed", "reason": str(exc)} | detail)
            raise SigningFailed(f"{exc}: the signing key is not the one signing_public_key names") from exc
        self._audit_after({"decision": "signed", "reference": f"{row.registry}/{row.repository}@{digest}"} | detail)
        return Signature(verified_against=self._key.trust_root, signer=annotations)

    def _record(self, record: Mapping[str, object]) -> None:
        try:
            self._audit(record)
        except OSError as exc:
            raise AuditUnavailable(str(exc)) from exc

    def _audit_after(self, record: Mapping[str, object]) -> None:
        """An audit line nothing waits on: a refusal, or an outcome. If it can't be written, that is logged."""
        try:
            self._audit(record)
        except OSError:
            logger.exception("the audit line for a %s could not be written", record.get("decision"))


_loaded: tuple[BuilderConfig, Broker] | None = None


def load_broker(config: BuilderConfig) -> Broker:
    """The broker for ``config``, built once: its token client remembers the registry's challenge."""
    global _loaded
    if _loaded is None or _loaded[0] is not config:
        _loaded = (config, Broker.from_config(config))
    return _loaded[1]
