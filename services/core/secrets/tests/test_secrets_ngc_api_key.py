# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for NGC API key access via the secrets API.

Uses the default platform config (system workspace, ngc-api-key name) and
NGC_API_KEY environment variable — no mocks.
"""

import pytest
from fastapi.testclient import TestClient

NGC_API_KEY_VALUE = "test-ngc-key-value"


@pytest.fixture(autouse=True)
def ngc_api_key_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set NGC_API_KEY so the default NGC API key secret is available in tests."""
    monkeypatch.setenv("NGC_API_KEY", NGC_API_KEY_VALUE)


async def test_list_secrets_includes_default_ngc_api_key_in_system_workspace(
    test_client: TestClient,
) -> None:
    """Listing secrets in the NGC workspace includes the default NGC API key."""
    response = test_client.get(
        "/apis/secrets/v2/workspaces/system/secrets",
        params={"page": 1, "page_size": 10},
    )
    assert response.status_code == 200
    data = response.json()
    names = [s["name"] for s in data["data"]]
    assert "ngc-api-key" in names
    ngc_secret = next(s for s in data["data"] if s["name"] == "ngc-api-key")
    assert ngc_secret["workspace"] == "system"
    assert ngc_secret["description"] == "Default NGC API key secret for the platform"
    assert "data" not in ngc_secret
    assert "value" not in ngc_secret
    assert data["pagination"]["total_results"] >= 1


async def test_list_secrets_system_workspace_only_ngc_key_has_one_page(
    test_client: TestClient,
) -> None:
    """When the only secret is the default NGC key, there is exactly one page with one item."""
    response = test_client.get(
        "/apis/secrets/v2/workspaces/system/secrets",
        params={"page": 1, "page_size": 10},
    )
    assert response.status_code == 200
    data = response.json()
    pagination = data["pagination"]
    assert pagination["total_results"] == 1
    assert pagination["total_pages"] == 1, "exactly one page when only the NGC key exists"
    assert len(data["data"]) == 1
    assert data["data"][0]["name"] == "ngc-api-key"
    assert data["data"][0]["workspace"] == "system"


async def test_list_secrets_other_workspace_does_not_include_default_ngc(
    test_client: TestClient,
) -> None:
    """Listing secrets in a non-system workspace does not add the default NGC key."""
    response = test_client.get(
        "/apis/secrets/v2/workspaces/default/secrets",
        params={"page": 1, "page_size": 10},
    )
    assert response.status_code == 200
    data = response.json()
    system_ngc = [s for s in data["data"] if s["name"] == "ngc-api-key" and s["workspace"] == "system"]
    assert len(system_ngc) == 0


async def test_list_secrets_non_system_workspace_zero_secrets_returns_empty_list(
    test_client: TestClient,
) -> None:
    """Listing secrets in a non-system workspace with no secrets returns an empty list."""
    response = test_client.get(
        "/apis/secrets/v2/workspaces/default/secrets",
        params={"page": 1, "page_size": 10},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["data"] == []
    assert data["pagination"]["total_results"] == 0
    assert data["pagination"]["current_page_size"] == 0


async def test_list_secrets_system_workspace_ngc_key_only_on_last_page(
    test_client: TestClient,
) -> None:
    """Default NGC API key appears only on the last page; total_results is stable across pages.

    With zero stored secrets: total_results=1, total_pages=1. We inject the NGC key only
    when page == total_pages (i.e. page 1). So page 1 returns [ngc-api-key]; page 2 is not
    the last page, so we do not inject there and the store returns [] for page 2. Hence
    ngc-api-key is in names1 and not in names2.
    """
    page_size = 10
    page1 = test_client.get(
        "/apis/secrets/v2/workspaces/system/secrets",
        params={"page": 1, "page_size": page_size},
    )
    page2 = test_client.get(
        "/apis/secrets/v2/workspaces/system/secrets",
        params={"page": 2, "page_size": page_size},
    )
    assert page1.status_code == 200
    assert page2.status_code == 200
    data1 = page1.json()
    data2 = page2.json()
    names1 = [s["name"] for s in data1["data"]]
    names2 = [s["name"] for s in data2["data"]]
    total1 = data1["pagination"]["total_results"]
    total2 = data2["pagination"]["total_results"]
    assert "ngc-api-key" in names1, "NGC API key should appear on the last page (here, page 1)"
    assert "ngc-api-key" not in names2, "Page 2 is not the last page, so we do not inject; names2 is empty"
    assert total1 == total2, "total_results must be the same on every page"
    assert data1["pagination"]["total_pages"] == data2["pagination"]["total_pages"]


async def test_list_secrets_system_workspace_ngc_key_on_last_page_with_multiple_pages(
    test_client: TestClient,
) -> None:
    """With multiple pages of stored secrets, NGC key appears only on the last page as the last item."""
    page_size = 10
    num_extra_secrets = 15  # 15 stored + 1 NGC = 16 total -> 2 pages; NGC on page 2
    created_names = []
    for i in range(num_extra_secrets):
        name = f"ngc-paging-{i:02d}"
        resp = test_client.post(
            "/apis/secrets/v2/workspaces/system/secrets",
            json={"name": name, "value": "paging-test"},
        )
        assert resp.status_code == 201, resp.text
        created_names.append(name)
    try:
        page1 = test_client.get(
            "/apis/secrets/v2/workspaces/system/secrets",
            params={"page": 1, "page_size": page_size},
        )
        page2 = test_client.get(
            "/apis/secrets/v2/workspaces/system/secrets",
            params={"page": 2, "page_size": page_size},
        )
        assert page1.status_code == 200
        assert page2.status_code == 200
        data1 = page1.json()
        data2 = page2.json()
        names1 = [s["name"] for s in data1["data"]]
        names2 = [s["name"] for s in data2["data"]]
        assert data1["pagination"]["total_results"] == 16
        assert data1["pagination"]["total_pages"] == 2
        assert "ngc-api-key" not in names1, "NGC key must not appear on page 1"
        assert "ngc-api-key" in names2, "NGC key must appear on the last page (page 2)"
        assert names2[-1] == "ngc-api-key", "NGC key must be the last item on the last page"
    finally:
        for name in created_names:
            test_client.delete(f"/apis/secrets/v2/workspaces/system/secrets/{name}")


async def test_get_default_ngc_api_key_returns_metadata(
    test_client: TestClient,
) -> None:
    """GET the default NGC API key secret returns metadata only (no data field)."""
    response = test_client.get("/apis/secrets/v2/workspaces/system/secrets/ngc-api-key")
    assert response.status_code == 200
    secret = response.json()
    assert secret["name"] == "ngc-api-key"
    assert secret["workspace"] == "system"
    assert secret["description"] == "Default NGC API key secret for the platform"
    assert "data" not in secret
    assert "value" not in secret
    assert "_data" not in secret


async def test_access_default_ngc_api_key_returns_value(
    test_client: TestClient,
) -> None:
    """GET .../access for the default NGC API key returns the secret value."""
    response = test_client.get("/apis/secrets/v2/workspaces/system/secrets/ngc-api-key/access")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "ngc-api-key"
    assert data["workspace"] == "system"
    assert data["value"] == NGC_API_KEY_VALUE


async def test_create_default_ngc_api_key_forbidden(
    test_client: TestClient,
) -> None:
    """Creating a secret with the default NGC API key name in system workspace returns 403."""
    response = test_client.post(
        "/apis/secrets/v2/workspaces/system/secrets",
        json={"name": "ngc-api-key", "value": "attempted-override"},
    )
    assert response.status_code == 403
    assert "Cannot overwrite the default NGC API key secret" in response.json()["detail"]


async def test_update_default_ngc_api_key_forbidden(
    test_client: TestClient,
) -> None:
    """Updating the default NGC API key secret returns 403."""
    response = test_client.patch(
        "/apis/secrets/v2/workspaces/system/secrets/ngc-api-key",
        json={"description": "Updated description"},
    )
    assert response.status_code == 403
    assert "Cannot update the default NGC API key secret" in response.json()["detail"]


async def test_delete_default_ngc_api_key_forbidden(
    test_client: TestClient,
) -> None:
    """Deleting the default NGC API key secret returns 403."""
    response = test_client.delete("/apis/secrets/v2/workspaces/system/secrets/ngc-api-key")
    assert response.status_code == 403
    assert "Cannot delete the default NGC API key secret" in response.json()["detail"]


async def test_get_other_workspace_ngc_name_not_treated_as_default(
    test_client: TestClient,
) -> None:
    """A secret named ngc-api-key in a non-system workspace is not the default and returns 404 if missing."""
    response = test_client.get("/apis/secrets/v2/workspaces/default/secrets/ngc-api-key")
    assert response.status_code == 404


async def test_list_secrets_system_workspace_omits_default_ngc_key_when_env_unset(
    test_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """"Unset NGC_API_KEY: the list does not crash, and the secret simply is not in it.

    The synthesized default is appended to the listing from the environment on demand, so with
    the variable unset there is nothing to append - the endpoint used to surface that failure as
    a 500 on what is otherwise a plain read.
    """
    monkeypatch.delenv("NGC_API_KEY", raising=False)
    response = test_client.get(
        "/apis/secrets/v2/workspaces/system/secrets",
        params={"page": 1, "page_size": 10},
    )
    assert response.status_code == 200
    data = response.json()
    assert [s["name"] for s in data["data"]] == []
    assert data["pagination"]["total_results"] == 0
    # An empty listing has no pages, which is how the store reports it for the non-NGC workspace
    # too - asserted here so the unset-key path provably does not re-add the pad the set-key
    # path would have counted.
    assert data["pagination"]["total_pages"] == 0


async def test_get_default_ngc_api_key_when_env_unset_returns_404_with_env_hint(
    test_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unset NGC_API_KEY: GET of the synthesized secret is a 404 naming the variable, not a 500."""
    monkeypatch.delenv("NGC_API_KEY", raising=False)
    response = test_client.get("/apis/secrets/v2/workspaces/system/secrets/ngc-api-key")
    assert response.status_code == 404
    assert "NGC_API_KEY" in response.json()["detail"]


async def test_access_default_ngc_api_key_when_env_unset_returns_404(
    test_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unset NGC_API_KEY: the access endpoint 404s like any other missing secret."""
    monkeypatch.delenv("NGC_API_KEY", raising=False)
    response = test_client.get("/apis/secrets/v2/workspaces/system/secrets/ngc-api-key/access")
    assert response.status_code == 404
    assert "NGC_API_KEY" in response.json()["detail"]
