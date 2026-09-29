# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Completion: the one write that makes a row `ready`, and everything that must not."""

from __future__ import annotations

import pytest
from nemo_builder_plugin.completion import CompletionConflict, complete
from nemo_builder_plugin.entities import ContainerImage, Provenance, Signature
from nemo_helix_plugin.entities import EntityConflictError

DIGEST = "sha256:" + "d" * 64
SIGNATURE = Signature(verified_against="key:sha256:" + "f" * 64, signer={"nhx.nvidia.com/image": "build-1-0"})


def _row() -> ContainerImage:
    return ContainerImage(
        name="build-1-0",
        workspace="ws-a",
        registry="reg.example.com",
        repository="ws-a/app",
        provenance=Provenance(build_set="build", revision=1, job="ws-a/build-1", request_digest="sha256:" + "a" * 64),
    )


class FakeRows:
    def __init__(self, row: ContainerImage) -> None:
        self.row = row
        self.version = 1
        self.writes = 0
        self.interfere: ContainerImage | None = None

    async def get(self, entity_type: type[ContainerImage], *, name: str, workspace: str) -> ContainerImage:
        assert (name, workspace) == (self.row.name, self.row.workspace)
        copy = self.row.model_copy(deep=True)
        copy._db_version = self.version
        return copy

    async def update(self, entity: ContainerImage) -> ContainerImage:
        if self.interfere is not None:
            # Someone else writes between this completion's read and its write.
            self.row, self.interfere = self.interfere, None
            self.version += 1
        if entity.db_version != self.version:
            raise EntityConflictError("version mismatch")
        self.writes += 1
        self.version += 1
        self.row = entity
        return entity


async def _complete(rows: FakeRows, digest: str = DIGEST) -> ContainerImage:
    return await complete(rows, workspace="ws-a", name="build-1-0", digest=digest, signature=SIGNATURE)


class TestComplete:
    @pytest.mark.asyncio
    async def test_a_pending_row_is_made_ready_in_one_write(self) -> None:
        rows = FakeRows(_row())
        ready = await _complete(rows)
        assert (ready.status, ready.digest, ready.signature) == ("ready", DIGEST, SIGNATURE)
        assert rows.writes == 1

    @pytest.mark.asyncio
    async def test_the_same_digest_again_is_accepted_and_writes_nothing(self) -> None:
        rows = FakeRows(_row())
        await _complete(rows)
        again = await _complete(rows)
        assert again.status == "ready" and rows.writes == 1

    @pytest.mark.asyncio
    async def test_another_digest_on_a_ready_row_is_a_conflict(self) -> None:
        rows = FakeRows(_row())
        await _complete(rows)
        with pytest.raises(CompletionConflict, match="already ready"):
            await _complete(rows, "sha256:" + "e" * 64)

    @pytest.mark.asyncio
    async def test_a_failed_row_is_never_made_ready(self) -> None:
        row = _row()
        row.status, row.status_detail = "failed", "not built: build revision 1 belongs to a different request"
        rows = FakeRows(row)
        with pytest.raises(CompletionConflict, match="already failed"):
            await _complete(rows)
        assert rows.writes == 0

    @pytest.mark.asyncio
    async def test_a_row_failed_in_between_wins(self) -> None:
        rows = FakeRows(_row())
        failed = _row()
        failed.status, failed.status_detail = "failed", "not built: build revision 1 belongs to a different request"
        rows.interfere = failed
        with pytest.raises(CompletionConflict, match="already failed"):
            await _complete(rows)

    @pytest.mark.asyncio
    async def test_a_twin_completion_that_finishes_first_is_success(self) -> None:
        rows = FakeRows(_row())
        twin = await _complete(FakeRows(_row()))
        rows.interfere = twin
        assert (await _complete(rows)).status == "ready"
