# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""The builder's routes, over HTTP, with the entity store faked."""

from __future__ import annotations

from typing import Literal
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from nemo_builder_plugin.broker import (
    AuditUnavailable,
    Caller,
    PushCredentials,
    SigningFailed,
    TagMoved,
    current_caller,
)
from nemo_builder_plugin.config import BuilderConfig
from nemo_builder_plugin.entities import ContainerImage, Provenance, Signature
from nemo_builder_plugin.registry_auth import RegistryAuthError
from nemo_builder_plugin.service import BuilderService, get_broker
from nemo_helix_plugin.entity_client import NemoEntityNotFoundError, get_entity_client


def _app(entities: AsyncMock, broker: object | None = None, caller: Caller = Caller(auth=False)) -> FastAPI:
    app = FastAPI()
    for spec in BuilderService().get_routers():
        app.include_router(spec.router, prefix=spec.prefix)
    app.dependency_overrides[get_entity_client] = lambda: entities
    if broker is not None:
        app.dependency_overrides[get_broker] = lambda: broker
    app.dependency_overrides[current_caller] = lambda: caller
    return app


def _empty_page() -> MagicMock:
    page = MagicMock()
    page.data = []
    return page


class TestListingOneJobsImages:
    def test_a_job_and_a_status_filter_on_the_stored_fields(self) -> None:
        entities = AsyncMock()
        entities.list.return_value = _empty_page()
        response = TestClient(_app(entities)).get(
            "/v2/workspaces/team-a/container-images", params={"job": "demo-1", "status": "pending"}
        )
        assert response.status_code == 200
        assert entities.list.await_args.kwargs["filter_obj"] == {
            "provenance.job": "team-a/demo-1",
            "status": "pending",
        }

    def test_the_job_is_always_in_the_path_workspace(self) -> None:
        entities = AsyncMock()
        response = TestClient(_app(entities)).get(
            "/v2/workspaces/team-a/container-images", params={"job": "team-b/demo-1"}
        )
        assert response.status_code == 422
        entities.list.assert_not_awaited()

    def test_no_filter_lists_the_workspace(self) -> None:
        entities = AsyncMock()
        entities.list.return_value = _empty_page()
        TestClient(_app(entities)).get("/v2/workspaces/team-a/container-images")
        assert entities.list.await_args.kwargs["filter_obj"] is None

    def test_an_unknown_status_is_refused(self) -> None:
        entities = AsyncMock()
        response = TestClient(_app(entities)).get("/v2/workspaces/team-a/container-images", params={"status": "done"})
        assert response.status_code == 422
        entities.list.assert_not_awaited()


DIGEST = "sha256:" + "d" * 64
SIGNATURE = Signature(verified_against="key:sha256:" + "f" * 64, signer={"nhx.nvidia.com/image": "build-1-0"})
IMAGE = "/v2/workspaces/ws-a/container-images/build-1-0"


def _row(status: Literal["pending", "ready", "failed"] = "pending", digest: str | None = None) -> ContainerImage:
    row = ContainerImage(
        name="build-1-0",
        workspace="ws-a",
        registry="reg.example.com",
        repository="ws-a/app",
        provenance=Provenance(
            build_set="build",
            revision=1,
            job="ws-a/build-1",
            request_digest="sha256:" + "a" * 64,
        ),
    )
    row.status, row.digest = status, digest
    return row


def _entities(row: ContainerImage) -> AsyncMock:
    entities = AsyncMock()
    entities.get.return_value = row
    entities.update.side_effect = lambda updated: updated
    return entities


class FakeBroker:
    def __init__(self, *, refusal: str | None = None, error: Exception | None = None) -> None:
        self.refusal_reason = refusal
        self.error = error
        self.issued: list[str] = []
        self.signed: list[tuple[str, str]] = []
        self.refusals: list[str] = []

    def refusal(self, row: ContainerImage, caller: Caller) -> str | None:
        return self.refusal_reason

    def refused(self, row: ContainerImage, caller: Caller, decision: str, reason: str) -> None:
        self.refusals.append(decision)

    def credentials(self, row: ContainerImage, caller: Caller) -> PushCredentials:
        if self.error is not None:
            raise self.error
        self.issued.append(row.name)
        return PushCredentials(
            auths={"reg.example.com": {"registrytoken": "t"}}, expires_in=300, narrowed=True, repository=row.repository
        )

    def sign(self, row: ContainerImage, digest: str, caller: Caller) -> Signature:
        if self.error is not None:
            raise self.error
        self.signed.append((row.name, digest))
        return SIGNATURE


class TestPushCredentials:
    def _post(self, row: ContainerImage, broker: FakeBroker):
        return TestClient(_app(_entities(row), broker)).post(f"{IMAGE}/push-credentials")

    def test_a_pending_image_gets_a_token_for_its_repository(self) -> None:
        broker = FakeBroker()
        response = self._post(_row(), broker)
        assert response.status_code == 200
        assert response.json()["auths"] == {"reg.example.com": {"registrytoken": "t"}}
        assert broker.issued == ["build-1-0"]

    def test_a_refused_caller_is_a_403_and_is_audited(self) -> None:
        broker = FakeBroker(refusal="build-1-0 was submitted by someone else")
        assert self._post(_row(), broker).status_code == 403
        assert broker.issued == [] and broker.refusals == ["credentials"]

    @pytest.mark.parametrize("status", ["ready", "failed"])
    def test_a_settled_image_is_a_409(self, status: Literal["ready", "failed"]) -> None:
        broker = FakeBroker()
        assert self._post(_row(status), broker).status_code == 409
        assert broker.issued == []

    def test_an_image_that_does_not_exist_is_a_404(self) -> None:
        entities = AsyncMock()
        entities.get.side_effect = NemoEntityNotFoundError("no")
        response = TestClient(_app(entities, FakeBroker())).post(f"{IMAGE}/push-credentials")
        assert response.status_code == 404

    @pytest.mark.parametrize(
        ("error", "status"), [(RegistryAuthError("down"), 502), (AuditUnavailable("stdout closed"), 503)]
    )
    def test_nothing_issued_is_an_error(self, error: Exception, status: int) -> None:
        assert self._post(_row(), FakeBroker(error=error)).status_code == status


class TestComplete:
    def _post(self, row: ContainerImage, broker: FakeBroker, body: dict[str, str] | None = None):
        entities = _entities(row)
        body = {"digest": DIGEST} if body is None else body
        response = TestClient(_app(entities, broker)).post(f"{IMAGE}/complete", json=body)
        return response, entities

    def test_the_pushed_digest_is_signed_and_the_image_made_ready(self) -> None:
        broker = FakeBroker()
        response, entities = self._post(_row(), broker)
        assert response.status_code == 200
        assert (response.json()["status"], response.json()["digest"]) == ("ready", DIGEST)
        assert response.json()["signature"]["verified_against"] == SIGNATURE.verified_against
        assert broker.signed == [("build-1-0", DIGEST)]
        entities.update.assert_awaited_once()

    def test_an_image_already_ready_at_that_digest_is_returned_unsigned(self) -> None:
        broker = FakeBroker()
        response, entities = self._post(_row("ready", DIGEST), broker)
        assert response.status_code == 200
        assert broker.signed == []
        entities.update.assert_not_awaited()

    @pytest.mark.parametrize("row", [_row("ready", "sha256:" + "e" * 64), _row("failed")])
    def test_an_image_that_settled_otherwise_is_a_409(self, row: ContainerImage) -> None:
        broker = FakeBroker()
        response, _ = self._post(row, broker)
        assert response.status_code == 409
        assert broker.signed == []

    def test_a_refused_caller_is_a_403_and_nothing_is_signed(self) -> None:
        broker = FakeBroker(refusal="only a job step acting for the image's submitter may publish or complete it")
        response, entities = self._post(_row(), broker)
        assert response.status_code == 403
        assert broker.signed == [] and broker.refusals == ["sign"]
        entities.update.assert_not_awaited()

    @pytest.mark.parametrize(
        ("error", "status"),
        [
            (TagMoved("the system tag holds another digest"), 409),
            (SigningFailed("cosign failed"), 502),
            (AuditUnavailable("stdout closed"), 503),
        ],
    )
    def test_a_signature_not_made_writes_nothing(self, error: Exception, status: int) -> None:
        response, entities = self._post(_row(), FakeBroker(error=error))
        assert response.status_code == status
        entities.update.assert_not_awaited()

    @pytest.mark.parametrize("body", [{"digest": "sha256:abc"}, {"digest": DIGEST, "signature": "x"}, {}])
    def test_anything_but_a_digest_is_refused(self, body: dict[str, str]) -> None:
        broker = FakeBroker()
        response, _ = self._post(_row(), broker, body)
        assert response.status_code == 422
        assert broker.signed == []


class TestAnUnconfiguredDeployment:
    def test_publishing_is_a_409_naming_what_is_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(BuilderConfig, "get", classmethod(lambda cls: BuilderConfig(registry="reg.example.com")))
        response = TestClient(_app(_entities(_row()))).post(f"{IMAGE}/push-credentials")
        assert response.status_code == 409
        assert "builder.signing_key" in response.json()["detail"]
