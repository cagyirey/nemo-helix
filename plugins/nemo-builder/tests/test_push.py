# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""The push step: a registry token per image from the builder, then the builder signs and completes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import httpx
import pytest
from nemo_builder_plugin.client import BuilderClient
from nemo_builder_plugin.entities import ContainerImage
from nemo_builder_plugin.run import push as push_module
from nemo_builder_plugin.run.push import Builder, Refused, _publish_all, _push_one
from nemo_builder_plugin.steps import PushImage, PushStepConfig
from nemo_helix_plugin.client.errors import NemoHTTPError
from nemo_helix_plugin.jobs.constants import PERSISTENT_JOB_STORAGE_PATH_ENVVAR

REGISTRY = "reg.example.com"
IMAGES = "/apis/builder/v2/workspaces/ws/container-images"


def _layout(root: Path) -> str:
    manifest = json.dumps({"schemaVersion": 2, "layers": []}).encode()
    digest = hashlib.sha256(manifest).hexdigest()
    (root / "blobs" / "sha256").mkdir(parents=True)
    (root / "blobs" / "sha256" / digest).write_bytes(manifest)
    (root / "oci-layout").write_text(json.dumps({"imageLayoutVersion": "1.0.0"}))
    (root / "index.json").write_text(json.dumps({"schemaVersion": 2, "manifests": [{"digest": f"sha256:{digest}"}]}))
    return f"sha256:{digest}"


def _image(name: str = "demo-1-0", *, caller: bool = True) -> PushImage:
    return PushImage(
        image=name,
        system_ref=f"{REGISTRY}/ws/team/app:ws--demo-1-{name[-1]}",
        caller_ref=f"{REGISTRY}/ws/team/app:v1" if caller else None,
    )


def _row(digest: str | None = None, status: str = "ready") -> dict[str, object]:
    return {
        "name": "demo-1-0",
        "workspace": "ws",
        "status": status,
        "registry": REGISTRY,
        "repository": "ws/team/app",
        "digest": digest,
        "provenance": {"build_set": "demo", "revision": 1, "job": "ws/demo-1", "request_digest": "sha256:" + "a" * 64},
    }


class FakeBuilder:
    """Grants a token per image, and completes each at ``digest``."""

    def __init__(self, digest: str, statuses: dict[str, str] | None = None) -> None:
        self.digest = digest
        self.statuses = statuses or {}
        self.calls: list[str] = []

    def credentials(self, image: str) -> dict[str, object]:
        self.calls.append(f"credentials:{image}")
        return {"auths": {REGISTRY: {"registrytoken": f"token-{len(self.calls)}"}}}

    def complete(self, image: str, digest: str) -> ContainerImage:
        self.calls.append(f"complete:{image}:{digest}")
        return ContainerImage.model_validate(_row(self.digest) | {"name": image})

    def status(self, image: str) -> str:
        return self.statuses.get(image, "pending")


@pytest.fixture
def crane(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    calls: list[list[str]] = []

    def run(args: list[str], *, env: object = None) -> str:
        calls.append(args)
        return ""

    monkeypatch.setattr(push_module, "run_tool", run)
    return calls


class TestTheBuilderClient:
    def _builder(self, responses: list[httpx.Response]) -> tuple[Builder, list[httpx.Request], list[float]]:
        seen: list[httpx.Request] = []

        def platform(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return responses.pop(0)

        sleeps: list[float] = []
        client = BuilderClient(
            base_url="http://platform", http_client=httpx.Client(transport=httpx.MockTransport(platform))
        )
        return Builder(client, workspace="ws", sleep=sleeps.append), seen, sleeps

    def test_credentials_are_asked_for_by_image_and_name_no_scope(self) -> None:
        credentials = {"auths": {REGISTRY: {"registrytoken": "t"}}, "expires_in": 300, "narrowed": True}
        builder, seen, _ = self._builder([httpx.Response(200, json=credentials | {"repository": "ws/team/app"})])
        assert builder.credentials("demo-1-0") == {"auths": {REGISTRY: {"registrytoken": "t"}}}
        assert (seen[0].method, seen[0].url.path) == ("POST", f"{IMAGES}/demo-1-0/push-credentials")
        assert seen[0].content in (b"", b"null")

    def test_no_credential_is_refused(self) -> None:
        empty = {"auths": {}, "expires_in": 300, "narrowed": None, "repository": "ws/team/app"}
        builder, _, _ = self._builder([httpx.Response(200, json=empty)])
        with pytest.raises(Refused, match="no credential"):
            builder.credentials("demo-1-0")

    def test_completing_names_the_digest_this_step_pushed(self) -> None:
        digest = "sha256:" + "d" * 64
        builder, seen, _ = self._builder([httpx.Response(200, json=_row(digest))])
        assert builder.complete("demo-1-0", digest).digest == digest
        assert seen[0].url.path == f"{IMAGES}/demo-1-0/complete"
        assert json.loads(seen[0].content) == {"digest": digest}

    def test_a_platform_that_is_briefly_down_is_retried(self) -> None:
        digest = "sha256:" + "d" * 64
        builder, _, sleeps = self._builder(
            [httpx.Response(503, json={"detail": "down"}), httpx.Response(200, json=_row(digest))]
        )
        builder.complete("demo-1-0", digest)
        assert sleeps == [1.0]

    def test_a_refusal_is_not_retried(self) -> None:
        builder, _, sleeps = self._builder(
            [httpx.Response(409, json={"detail": "the system tag holds another digest"})]
        )
        with pytest.raises(NemoHTTPError):
            builder.complete("demo-1-0", "sha256:" + "d" * 64)
        assert sleeps == []

    def test_a_platform_that_stays_down_is_given_up_on(self) -> None:
        builder, _, sleeps = self._builder([httpx.Response(503, json={"detail": "down"}) for _ in range(5)])
        with pytest.raises(NemoHTTPError):
            builder.complete("demo-1-0", "sha256:" + "d" * 64)
        assert sleeps == [1.0, 2.0, 4.0, 8.0]


class TestPushOne:
    def test_pushes_the_callers_tag_then_the_system_tag_then_completes(
        self, tmp_path: Path, crane: list[list[str]]
    ) -> None:
        digest = _layout(tmp_path / "out")
        builder = FakeBuilder(digest)
        _push_one(_image(), tmp_path / "out", builder=builder, docker_config=tmp_path, plain_http=False)
        assert [call[3] for call in crane] == [f"{REGISTRY}/ws/team/app:v1", f"{REGISTRY}/ws/team/app:ws--demo-1-0"]
        assert builder.calls == ["credentials:demo-1-0", f"complete:demo-1-0:{digest}"]
        written = json.loads((tmp_path / "config.json").read_text())
        assert written == {"auths": {REGISTRY: {"registrytoken": "token-1"}}}
        assert (tmp_path / "config.json").stat().st_mode & 0o777 == 0o600

    def test_a_plain_http_registry_is_pushed_over_http_only_when_configured(
        self, tmp_path: Path, crane: list[list[str]]
    ) -> None:
        digest = _layout(tmp_path / "out")
        _push_one(
            _image(caller=False), tmp_path / "out", builder=FakeBuilder(digest), docker_config=tmp_path, plain_http=True
        )
        assert crane == [["crane", "push", str(tmp_path / "out"), f"{REGISTRY}/ws/team/app:ws--demo-1-0", "--insecure"]]

    def test_an_image_completed_at_another_digest_is_a_failure(self, tmp_path: Path, crane: list[list[str]]) -> None:
        _layout(tmp_path / "out")
        with pytest.raises(Refused, match="not ready at"):
            _push_one(
                _image(),
                tmp_path / "out",
                builder=FakeBuilder("sha256:" + "e" * 64),
                docker_config=tmp_path,
                plain_http=False,
            )


class TestPublishAll:
    def _config(self, *names: str) -> PushStepConfig:
        return PushStepConfig(images=[_image(name) for name in names], registry=REGISTRY)

    def _work(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *built: str) -> str:
        monkeypatch.setenv(PERSISTENT_JOB_STORAGE_PATH_ENVVAR, str(tmp_path))
        digest = ""
        for name in built:
            digest = _layout(tmp_path / "out" / name)
        return digest

    def _completed(self, builder: FakeBuilder) -> list[str]:
        return [call.split(":")[1] for call in builder.calls if call.startswith("complete:")]

    def test_every_built_image_is_published_and_completed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, crane: list[list[str]]
    ) -> None:
        digest = self._work(tmp_path, monkeypatch, "demo-1-0", "demo-1-1")
        builder = FakeBuilder(digest)
        code = _publish_all(self._config("demo-1-0", "demo-1-1"), builder=builder, docker_config=tmp_path)
        assert code == 0 and self._completed(builder) == ["demo-1-0", "demo-1-1"]

    def test_a_missing_layout_fails_that_image_and_not_the_rest(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, crane: list[list[str]]
    ) -> None:
        digest = self._work(tmp_path, monkeypatch, "demo-1-1")
        builder = FakeBuilder(digest)
        code = _publish_all(self._config("demo-1-0", "demo-1-1"), builder=builder, docker_config=tmp_path)
        assert code == 1 and self._completed(builder) == ["demo-1-1"]

    def test_a_rerun_skips_what_already_settled(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, crane: list[list[str]]
    ) -> None:
        digest = self._work(tmp_path, monkeypatch, "demo-1-0", "demo-1-1")
        builder = FakeBuilder(digest, {"demo-1-0": "ready"})
        code = _publish_all(self._config("demo-1-0", "demo-1-1"), builder=builder, docker_config=tmp_path)
        assert code == 0 and self._completed(builder) == ["demo-1-1"]
        assert "credentials:demo-1-0" not in builder.calls

    def test_a_row_that_already_failed_counts_as_a_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, crane: list[list[str]]
    ) -> None:
        digest = self._work(tmp_path, monkeypatch, "demo-1-0")
        builder = FakeBuilder(digest, {"demo-1-0": "failed"})
        assert _publish_all(self._config("demo-1-0"), builder=builder, docker_config=tmp_path) == 1
