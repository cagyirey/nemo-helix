# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""The credential broker: who may publish or complete an image, what is issued, and what is signed."""

from __future__ import annotations

import base64
import json
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from nemo_builder_plugin import broker as broker_module
from nemo_builder_plugin.broker import (
    AuditUnavailable,
    Broker,
    BrokerUnconfigured,
    Caller,
    KeySigner,
    SignedImage,
    SigningFailed,
    TagMoved,
    caller_refusal,
    current_caller,
    load_broker,
    row_refusal,
)
from nemo_builder_plugin.config import BuilderConfig
from nemo_builder_plugin.entities import ContainerImage, Provenance
from nemo_builder_plugin.registry import OCI_INDEX, OCI_MANIFEST
from nemo_builder_plugin.registry_auth import IssuedToken, RegistryAuthError
from nemo_builder_plugin.signing import (
    SIGNATURE_ANNOTATION,
    DeploymentKey,
    SigningKey,
    key_fingerprint,
    signature_annotations,
    signature_tag,
)
from nemo_helix_plugin.auth import AuthContext

REGISTRY = "reg.example.com"
DIGEST = "sha256:" + "d" * 64
KEY = ec.generate_private_key(ec.SECP256R1())
PUBLIC_KEY = KEY.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
CONFIG = BuilderConfig(
    registry=REGISTRY,
    registry_username="builder",
    registry_password_file="/var/run/registry/token",
    signing_key="/var/run/signing/signing.key",
    signing_public_key=PUBLIC_KEY.decode(),
)
STEP = Caller(auth=True, actor="job-step", submitter="alice")


def _row(
    name: str = "build-1-0",
    *,
    workspace: str = "ws-a",
    repository: str = "ws-a/app",
    registry: str = REGISTRY,
    submitter: str | None = "alice",
) -> ContainerImage:
    row = ContainerImage(
        name=name,
        workspace=workspace,
        registry=registry,
        repository=repository,
        provenance=Provenance(
            build_set="build", revision=1, job=f"{workspace}/build-1", request_digest="sha256:" + "a" * 64
        ),
    )
    # What the entity store records for whoever created the row: the submit's effective principal.
    row._created_by = submitter
    return row


class TestTheCaller:
    def test_with_platform_auth_off_no_caller_is_checked(self) -> None:
        assert caller_refusal(_row(), Caller(auth=False)) is None

    def test_a_job_step_acting_for_the_images_submitter_may(self) -> None:
        assert caller_refusal(_row(), STEP) is None

    def test_a_users_own_token_is_refused(self) -> None:
        refusal = caller_refusal(_row(), Caller(auth=True, actor="alice"))
        assert refusal is not None and "job step" in refusal

    def test_a_job_step_acting_for_someone_else_is_refused(self) -> None:
        refusal = caller_refusal(_row(), Caller(auth=True, actor="job-step", submitter="bob"))
        assert refusal is not None and "someone else" in refusal

    def test_a_row_with_no_recorded_submitter_is_refused(self) -> None:
        assert caller_refusal(_row(submitter=None), STEP) is not None

    def test_the_caller_comes_from_the_platforms_auth_context(self, monkeypatch: pytest.MonkeyPatch) -> None:
        context = AuthContext(principal_id="job-step", principal_on_behalf_of="alice")
        monkeypatch.setattr(broker_module, "current_auth_context", lambda: context)
        monkeypatch.setattr(broker_module, "platform_auth_enabled", lambda: True)
        assert current_caller() == STEP
        monkeypatch.setattr(broker_module, "platform_auth_enabled", lambda: False)
        assert current_caller() == Caller(auth=False)


class TestTheRow:
    """Rows are data: they only narrow the workspace bound, never widen it."""

    def test_a_row_in_its_workspaces_part_of_the_registry_may_be_published(self) -> None:
        assert row_refusal(_row(), registry=REGISTRY, repository_prefix="") is None

    def test_the_bound_includes_the_prefix(self) -> None:
        assert row_refusal(_row(repository="proj/ws-a/app"), registry=REGISTRY, repository_prefix="proj") is None
        assert row_refusal(_row(repository="ws-a/app"), registry=REGISTRY, repository_prefix="proj") is not None

    @pytest.mark.parametrize(
        ("row", "reason"),
        [
            (_row(registry="elsewhere.example.com"), "not this deployment's registry"),
            (_row(repository="ws-b/app"), "not a repository in workspace ws-a"),
            (_row(repository="ws-ab/app"), "not a repository in workspace ws-a"),
            # It goes into a token scope as written, where a space asks for a second repository.
            (_row(repository="ws-a/x:pull repository:ws-b/app"), "not a repository in workspace ws-a"),
            (_row(repository="ws-a/../ws-b/app"), "not a repository in workspace ws-a"),
            # A row written around the submit path can have a name no tag can carry.
            (_row(name="build+1"), "has no valid system tag"),
        ],
    )
    def test_anything_else_is_refused_with_a_reason(self, row: ContainerImage, reason: str) -> None:
        refusal = row_refusal(row, registry=REGISTRY, repository_prefix="")
        assert refusal is not None and reason in refusal


class FakeRegistry:
    def __init__(self, *, granted: tuple[str, ...] | None = ("repository:ws-a/app:pull,push",)) -> None:
        self.asked: list[tuple[list[str], list[str]]] = []
        self.granted = granted
        self.fail = False

    def issue(self, repositories: Sequence[str], actions: Sequence[str]) -> IssuedToken:
        self.asked.append((list(repositories), list(actions)))
        if self.fail:
            raise RegistryAuthError("token service down")
        return IssuedToken(
            token="registry-token", expires_in=300, narrowed=True, granted=self.granted, token_id="jti-1"
        )


class FakeSigner:
    """Signs whatever it is asked to, if the tag holds it, with ``key``."""

    def __init__(self, *, key: ec.EllipticCurvePrivateKey = KEY, found: str = DIGEST) -> None:
        self.key = key
        self.found = found
        self.signed: list[tuple[str, str, dict[str, str]]] = []
        self.fail = False

    def sign(
        self, row: ContainerImage, *, digest: str, annotations: Mapping[str, str], record: Callable[[str], None]
    ) -> SignedImage:
        if self.fail:
            raise SigningFailed("registry unreachable")
        if self.found != digest:
            raise TagMoved(f"{row.name}'s system tag holds {self.found}, not {digest}")
        record(digest)
        self.signed.append((row.name, digest, dict(annotations)))
        payload = json.dumps({"digest": digest, "optional": dict(annotations)}).encode()
        return SignedImage(digest=digest, payload=payload, signature=self.key.sign(payload, ec.ECDSA(hashes.SHA256())))


def _broker(
    *,
    registry: FakeRegistry | None = None,
    signer: FakeSigner | None = None,
    audit: Callable[[Mapping[str, object]], None] | None = None,
) -> tuple[Broker, list[dict[str, object]]]:
    lines: list[dict[str, object]] = []
    broker = Broker(
        CONFIG,
        registry=registry or FakeRegistry(),
        signer=signer or FakeSigner(),
        key=DeploymentKey(PUBLIC_KEY.decode()),
        audit=audit or (lambda record: lines.append(dict(record))),
    )
    return broker, lines


def _unwritable(record: Mapping[str, object]) -> None:
    raise OSError("stdout closed")


class TestCredentials:
    def test_a_token_for_the_images_repository_and_nothing_else(self) -> None:
        registry = FakeRegistry()
        broker, _ = _broker(registry=registry)
        issued = broker.credentials(_row(), STEP)
        assert registry.asked == [(["ws-a/app"], ["pull", "push"])]
        assert issued.auths == {REGISTRY: {"registrytoken": "registry-token"}}
        assert (issued.repository, issued.expires_in, issued.narrowed) == ("ws-a/app", 300, True)

    def test_the_audit_records_what_was_asked_for_and_what_was_granted(self) -> None:
        broker, audit = _broker(registry=FakeRegistry(granted=("repository:ws-a/app:pull",)))
        broker.credentials(_row(), STEP)
        assert audit == [
            {
                "decision": "credentials",
                "image": "build-1-0",
                "workspace": "ws-a",
                "requested": ["repository:ws-a/app:pull,push"],
                "granted": ["repository:ws-a/app:pull"],
                "narrowed": True,
                "expires_in": 300,
                "token_id": "jti-1",
                "actor": "job-step",
                "submitter": "alice",
            }
        ]

    def test_an_opaque_token_is_audited_as_granting_unknown(self) -> None:
        broker, audit = _broker(registry=FakeRegistry(granted=None))
        broker.credentials(_row(), STEP)
        assert audit[0]["granted"] is None

    def test_no_audit_line_means_no_token(self) -> None:
        broker, _ = _broker(audit=_unwritable)
        with pytest.raises(AuditUnavailable):
            broker.credentials(_row(), STEP)

    def test_a_token_service_failure_issues_and_audits_nothing(self) -> None:
        registry = FakeRegistry()
        registry.fail = True
        broker, audit = _broker(registry=registry)
        with pytest.raises(RegistryAuthError):
            broker.credentials(_row(), STEP)
        assert audit == []

    def test_a_refusal_is_audited(self) -> None:
        broker, audit = _broker()
        broker.refused(_row(), STEP, "credentials", "build-1-0 was submitted by someone else")
        assert audit[0]["decision"] == "credentials-refused" and audit[0]["submitter"] == "alice"


class TestSign:
    def test_the_digest_the_step_pushed_is_signed_with_the_rows_annotations(self) -> None:
        signer = FakeSigner()
        broker, audit = _broker(signer=signer)
        signature = broker.sign(_row(), DIGEST, STEP)
        assert signer.signed == [("build-1-0", DIGEST, signature_annotations(_row()))]
        assert signature.verified_against == key_fingerprint(KEY.public_key())
        assert signature.signer == signature_annotations(_row())
        assert [line["decision"] for line in audit] == ["sign", "signed"]
        assert audit[0]["reference"] == f"{REGISTRY}/ws-a/app@{DIGEST}"

    def test_a_tag_that_moved_is_not_signed_and_the_refusal_is_audited(self) -> None:
        broker, audit = _broker(signer=FakeSigner(found="sha256:" + "e" * 64))
        with pytest.raises(TagMoved):
            broker.sign(_row(), DIGEST, STEP)
        assert [line["decision"] for line in audit] == ["sign-refused"]

    def test_a_signing_failure_is_audited_as_one(self) -> None:
        signer = FakeSigner()
        signer.fail = True
        broker, audit = _broker(signer=signer)
        with pytest.raises(SigningFailed):
            broker.sign(_row(), DIGEST, STEP)
        assert [line["decision"] for line in audit] == ["sign-failed"]

    def test_a_key_that_is_not_the_one_consumers_trust_fails(self) -> None:
        broker, audit = _broker(signer=FakeSigner(key=ec.generate_private_key(ec.SECP256R1())))
        with pytest.raises(SigningFailed, match="signing_public_key"):
            broker.sign(_row(), DIGEST, STEP)
        assert [line["decision"] for line in audit] == ["sign", "sign-failed"]

    def test_no_audit_line_means_no_signature(self) -> None:
        signer = FakeSigner()
        broker, _ = _broker(signer=signer, audit=_unwritable)
        with pytest.raises(AuditUnavailable):
            broker.sign(_row(), DIGEST, STEP)
        assert signer.signed == []


def _private_pem(key: ec.EllipticCurvePrivateKey, password: bytes | None = None) -> bytes:
    encryption = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)


def _keyed(tmp_path: Path, *, key: ec.EllipticCurvePrivateKey = KEY, password: bytes | None = None) -> BuilderConfig:
    """CONFIG, with its signing key, and password if any, written where the broker reads them."""
    (tmp_path / "signing.key").write_bytes(_private_pem(key, password))
    update: dict[str, object] = {"signing_key": str(tmp_path / "signing.key")}
    if password:
        # As a mounted Secret often is: with a newline that was never part of the password.
        (tmp_path / "password").write_bytes(password + b"\n")
        update["signing_key_password_file"] = str(tmp_path / "password")
    return CONFIG.model_copy(update=update)


class TestConfiguration:
    def test_every_setting_the_broker_needs_is_named_when_missing(self) -> None:
        config = CONFIG.model_copy(update={"signing_key": None, "registry_username": None})
        with pytest.raises(BrokerUnconfigured, match="builder.registry_username, builder.signing_key"):
            Broker.from_config(config)

    def test_the_broker_is_built_once_per_config(self, tmp_path: Path) -> None:
        config = _keyed(tmp_path)
        assert load_broker(config) is load_broker(config)

    def test_a_key_that_cannot_be_read_is_refused_before_any_build(self) -> None:
        with pytest.raises(BrokerUnconfigured, match="can't be loaded"):
            Broker.from_config(CONFIG)

    def test_a_key_that_is_not_the_one_consumers_trust_is_refused_before_any_build(self, tmp_path: Path) -> None:
        with pytest.raises(BrokerUnconfigured, match="not the key builder.signing_public_key names"):
            Broker.from_config(_keyed(tmp_path, key=ec.generate_private_key(ec.SECP256R1())))

    def test_the_key_password_is_read_without_its_trailing_newline(self, tmp_path: Path) -> None:
        Broker.from_config(_keyed(tmp_path, password=b"hunter2"))


class TestKeySigner:
    MANIFEST: dict[str, object] = {"schemaVersion": 2, "mediaType": OCI_MANIFEST, "config": {}, "layers": []}
    TAG = "ws-a--build-1-0"

    def _sign(
        self,
        oci_registry,
        digest: str,
        *,
        record: Callable[[str], None] = lambda digest: None,
        config: BuilderConfig = CONFIG,
    ) -> SignedImage:
        signer = KeySigner(config, FakeRegistry(), SigningKey(_private_pem(KEY)), http=oci_registry.client())
        return signer.sign(_row(), digest=digest, annotations=signature_annotations(_row()), record=record)

    def test_it_signs_what_the_system_tag_holds_and_stores_it_where_cosign_looks(self, oci_registry) -> None:
        digest = oci_registry.push("ws-a/app", self.TAG, self.MANIFEST)
        recorded: list[str] = []
        signed = self._sign(oci_registry, digest, record=recorded.append)
        assert recorded == [digest]
        DeploymentKey(PUBLIC_KEY.decode()).verify(signed.payload, signed.signature)
        claims = json.loads(signed.payload)
        assert claims["critical"]["image"]["docker-manifest-digest"] == digest
        assert claims["critical"]["identity"]["docker-reference"] == f"{REGISTRY}/ws-a/app"
        assert claims["optional"] == signature_annotations(_row())
        [layer] = oci_registry.manifest("ws-a/app", signature_tag(digest))["layers"]
        assert base64.b64decode(layer["annotations"][SIGNATURE_ANNOTATION]) == signed.signature
        assert oci_registry.blobs[("ws-a/app", layer["digest"])] == signed.payload

    def test_a_plain_http_registry_is_signed_over_http(self, oci_registry) -> None:
        digest = oci_registry.push("ws-a/app", self.TAG, self.MANIFEST)
        self._sign(oci_registry, digest, config=BuilderConfig(registry=f"http://{REGISTRY}"))
        assert {request.url.scheme for request in oci_registry.requests} == {"http"}

    def test_a_tag_that_holds_another_digest_is_never_signed(self, oci_registry) -> None:
        oci_registry.push("ws-a/app", self.TAG, self.MANIFEST)
        recorded: list[str] = []
        with pytest.raises(TagMoved, match="holds sha256:"):
            self._sign(oci_registry, DIGEST, record=recorded.append)
        assert recorded == [] and ("ws-a/app", signature_tag(DIGEST)) not in oci_registry.manifests

    def test_a_tag_that_holds_nothing_is_never_signed(self, oci_registry) -> None:
        with pytest.raises(TagMoved, match="holds nothing"):
            self._sign(oci_registry, DIGEST)

    def test_nothing_is_signed_if_it_cannot_be_recorded(self, oci_registry) -> None:
        digest = oci_registry.push("ws-a/app", self.TAG, self.MANIFEST)

        def record(digest: str) -> None:
            raise AuditUnavailable("stdout closed")

        with pytest.raises(AuditUnavailable):
            self._sign(oci_registry, digest, record=record)
        assert ("ws-a/app", signature_tag(digest)) not in oci_registry.manifests

    def test_an_index_is_not_signed(self, oci_registry) -> None:
        digest = oci_registry.push("ws-a/app", self.TAG, {"mediaType": OCI_INDEX, "manifests": []}, OCI_INDEX)
        recorded: list[str] = []
        with pytest.raises(SigningFailed, match="index"):
            self._sign(oci_registry, digest, record=recorded.append)
        assert recorded == []

    def test_a_token_service_that_fails_is_a_signing_failure(self, oci_registry) -> None:
        registry = FakeRegistry()
        registry.fail = True
        signer = KeySigner(CONFIG, registry, SigningKey(_private_pem(KEY)), http=oci_registry.client())
        with pytest.raises(SigningFailed, match="RegistryAuthError"):
            signer.sign(_row(), digest=DIGEST, annotations={}, record=lambda digest: None)
