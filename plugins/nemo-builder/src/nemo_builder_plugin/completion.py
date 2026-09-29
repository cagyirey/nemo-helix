# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Completion: the one write that makes a row ``ready``, once the builder has signed its digest."""

from __future__ import annotations

from typing import Protocol

from nemo_builder_plugin.entities import ContainerImage, Signature
from nemo_helix_plugin.entities import EntityConflictError


class CompletionConflict(Exception):
    """The row has already settled, and not as this completion would settle it (409)."""


class _Rows(Protocol):
    async def get(self, entity_type: type[ContainerImage], *, name: str, workspace: str) -> ContainerImage: ...

    async def update(self, entity: ContainerImage) -> ContainerImage: ...


def settled(row: ContainerImage, digest: str) -> bool:
    """Whether ``row`` is already ``ready`` at ``digest``. Raises :class:`CompletionConflict` if it settled otherwise."""
    if row.status == "ready":
        if row.digest == digest:
            return True
        raise CompletionConflict(f"{row.name} is already ready as {row.digest}, not {digest}")
    if row.status == "failed":
        raise CompletionConflict(f"{row.name} has already failed ({row.status_detail}); ready is not reachable from it")
    return False


async def complete(rows: _Rows, *, workspace: str, name: str, digest: str, signature: Signature) -> ContainerImage:
    """Write the row ``name`` ``ready`` at ``digest``, conditional on the version it was read at.

    Raises :class:`CompletionConflict` if the row settled otherwise, or the store's not-found error.
    """
    for _ in range(2):
        row = await rows.get(ContainerImage, name=name, workspace=workspace)
        if settled(row, digest):
            return row
        row.digest = digest
        row.signature = signature
        row.status = "ready"
        row.status_detail = None
        try:
            return await rows.update(row)
        except EntityConflictError:
            continue
    raise CompletionConflict(f"{name} kept changing while it was being completed")
