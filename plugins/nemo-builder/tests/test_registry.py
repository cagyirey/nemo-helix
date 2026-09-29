# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""The registry calls the builder makes itself: reading a manifest, and writing blobs and manifests."""

from __future__ import annotations

import hashlib
import json

import httpx
import pytest
from nemo_builder_plugin.registry import OCI_MANIFEST, ManifestNotFound, Registry, RegistryError

HOST = "reg.example.com"
TOKEN = "registry-token"


def _answering(*responses: httpx.Response) -> tuple[Registry, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return responses[len(seen) - 1]

    return Registry(HOST, TOKEN, http=httpx.Client(transport=httpx.MockTransport(handle))), seen


class TestManifest:
    def test_its_digest_is_computed_from_the_bytes_returned(self, oci_registry) -> None:
        digest = oci_registry.push("ws/app", "v1", {"schemaVersion": 2, "layers": []})
        found, manifest = Registry(HOST, TOKEN, http=oci_registry.client()).manifest("ws/app", "v1")
        assert (found, manifest) == (digest, {"schemaVersion": 2, "layers": []})
        sent = oci_registry.requests[0]
        assert sent.headers["Authorization"] == f"Bearer {TOKEN}" and OCI_MANIFEST in sent.headers["Accept"]

    def test_nothing_at_the_tag_is_its_own_error(self, oci_registry) -> None:
        with pytest.raises(ManifestNotFound):
            Registry(HOST, TOKEN, http=oci_registry.client()).manifest("ws/app", "v1")

    def test_a_plain_http_registry_is_reached_over_http(self, oci_registry) -> None:
        oci_registry.push("ws/app", "v1", {})
        Registry(HOST, TOKEN, http=oci_registry.client(), plain_http=True).manifest("ws/app", "v1")
        assert oci_registry.requests[0].url.scheme == "http"


class TestWrites:
    def test_a_blob_is_uploaded_where_the_registry_says_with_its_digest(self, oci_registry) -> None:
        digest = Registry(HOST, TOKEN, http=oci_registry.client()).put_blob("ws/app", b"payload")
        assert digest == "sha256:" + hashlib.sha256(b"payload").hexdigest()
        assert oci_registry.blobs[("ws/app", digest)] == b"payload"

    def test_a_manifest_is_written_under_its_tag(self, oci_registry) -> None:
        registry = Registry(HOST, TOKEN, http=oci_registry.client())
        config = registry.put_blob("ws/app", b"{}")
        body = json.dumps({"schemaVersion": 2, "config": {"digest": config}, "layers": []}).encode()
        registry.put_manifest("ws/app", "v1", body, OCI_MANIFEST)
        assert oci_registry.manifests[("ws/app", "v1")] == (body, OCI_MANIFEST)


class TestRefusals:
    def test_an_upload_location_on_another_host_is_refused_before_the_token_goes_there(self) -> None:
        registry, seen = _answering(httpx.Response(202, headers={"Location": "https://elsewhere.example.com/upload"}))
        with pytest.raises(RegistryError, match="another host"):
            registry.put_blob("ws/app", b"payload")
        assert len(seen) == 1

    def test_a_refusal_names_the_status_but_not_the_body(self) -> None:
        registry, _ = _answering(httpx.Response(403, text="internal details"))
        with pytest.raises(RegistryError, match="answered 403") as raised:
            registry.manifest("ws/app", "v1")
        assert "internal" not in str(raised.value)

    def test_a_manifest_that_is_not_json_is_refused(self) -> None:
        registry, _ = _answering(httpx.Response(200, content=b"<html>"))
        with pytest.raises(RegistryError, match="not a JSON manifest"):
            registry.manifest("ws/app", "v1")

    def test_an_unreachable_registry_is_a_registry_error(self) -> None:
        def down(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

        registry = Registry(HOST, TOKEN, http=httpx.Client(transport=httpx.MockTransport(down)))
        with pytest.raises(RegistryError, match="could not be reached"):
            registry.manifest("ws/app", "v1")
