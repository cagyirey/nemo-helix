# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""The builder's request surface, registered under ``nemo.services``."""

from __future__ import annotations

import asyncio
import logging
from typing import ClassVar, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from nemo_builder_plugin._perms import BuildPerms, ContainerImagePerms
from nemo_builder_plugin.authz import scope
from nemo_builder_plugin.backend import BackendRefused
from nemo_builder_plugin.backends import load_backend
from nemo_builder_plugin.broker import (
    AuditUnavailable,
    Broker,
    BrokerUnconfigured,
    Caller,
    CompleteRequest,
    PushCredentials,
    SigningFailed,
    TagMoved,
    current_caller,
    load_broker,
)
from nemo_builder_plugin.completion import CompletionConflict, complete, settled
from nemo_builder_plugin.config import BuilderConfig
from nemo_builder_plugin.entities import ContainerImage
from nemo_builder_plugin.registry_auth import RegistryAuthError
from nemo_builder_plugin.schema import BuildSet
from nemo_builder_plugin.submit import BuildConflict, InvalidBuildRequest, submit_build_set
from nemo_helix import AsyncNeMoHelix
from nemo_helix_plugin.authz import CallerKind, path_rule
from nemo_helix_plugin.client.adapter import client_from_platform
from nemo_helix_plugin.client.errors import NemoHTTPError, PermissionDeniedError
from nemo_helix_plugin.dependencies import get_sdk_client
from nemo_helix_plugin.entity_client import (
    NemoEntitiesClient,
    NemoEntityNotFoundError,
    get_entity_client,
)
from nemo_helix_plugin.jobs.client import AsyncJobsClient
from nemo_helix_plugin.log_utils import sanitize_for_log
from nemo_helix_plugin.service import NemoService, RouterSpec
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class SubmitBuildResponse(BaseModel):
    """The submitted build's job and images."""

    job: str = Field(description="Name of the build job, for logs and debugging.")
    images: list[ContainerImage] = Field(
        description="One row per build spec, created `pending`. POLL THESE, not the job."
    )


def get_broker() -> Broker:
    """The deployment's credential broker: 409 if it can't publish."""
    try:
        return load_broker(BuilderConfig.get())
    except BrokerUnconfigured as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


async def _get_row(entity_client: NemoEntitiesClient, workspace: str, name: str) -> ContainerImage:
    try:
        return await entity_client.get(ContainerImage, name=name, workspace=workspace)
    except NemoEntityNotFoundError as exc:
        raise HTTPException(status_code=404, detail=f"Container image '{name}' not found.") from exc


class BuilderService(NemoService):
    name: ClassVar[str] = "builder"
    dependencies: ClassVar[list[str]] = ["entities", "jobs"]

    def get_routers(self) -> list[RouterSpec]:
        return [
            RouterSpec(
                _build_router(),
                tag="Builder",
                description="Submit container image builds and read the images they produce.",
                prefix="/v2/workspaces/{workspace}",
            )
        ]


def _build_router() -> APIRouter:
    router = APIRouter()

    # A deployment that can't publish refuses here, rather than running builds nothing could complete.
    @router.post(
        "/builds",
        response_model=SubmitBuildResponse,
        status_code=201,
        tags=["Builder"],
        dependencies=[Depends(get_broker)],
    )
    @scope.write
    @path_rule(callers=[CallerKind.PRINCIPAL], permissions=[BuildPerms.CREATE])
    async def submit_build(
        workspace: str,
        body: BuildSet,
        entity_client: NemoEntitiesClient = Depends(get_entity_client),
        sdk: AsyncNeMoHelix = Depends(get_sdk_client),
    ) -> SubmitBuildResponse:
        """Submit a set of images to build.

        Creates one `pending` ``ContainerImage`` per spec, then the job that builds them.
        """
        backend = load_backend(BuilderConfig.get())
        jobs_client = client_from_platform(sdk, AsyncJobsClient)

        async def create_job(request):
            return await jobs_client.create_job(workspace=workspace, body=request)

        async def get_job_fields(name: str):
            return (await jobs_client.retrieve(name, workspace=workspace)).custom_fields or {}

        try:
            result = await submit_build_set(
                body,
                backend=backend,
                workspace=workspace,
                entity_client=entity_client,
                create_job=create_job,
                get_job_fields=get_job_fields,
            )
        except InvalidBuildRequest as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except (BackendRefused, BuildConflict) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except PermissionDeniedError as exc:
            # The rows and the job are created as the caller, so this refusal is the caller's.
            raise HTTPException(status_code=403, detail=f"Not permitted: {exc.detail}") from exc
        except NemoHTTPError as exc:
            logger.exception("a platform service refused build set %r", sanitize_for_log(body.name))
            raise HTTPException(
                status_code=502, detail=f"A platform service refused the build (HTTP {exc.status_code})."
            ) from exc
        except Exception as exc:
            logger.exception("failed to submit build set %r", sanitize_for_log(body.name))
            raise HTTPException(status_code=500, detail="Failed to submit build.") from exc

        return SubmitBuildResponse(job=result.job, images=result.images)

    @router.get("/container-images", response_model=list[ContainerImage], tags=["Builder"])
    @scope.read
    @path_rule(callers=[CallerKind.PRINCIPAL], permissions=[ContainerImagePerms.LIST])
    async def list_container_images(
        workspace: str,
        job: str | None = Query(
            default=None,
            max_length=128,
            pattern=r"^[^/]+$",
            description="Only the images this build job produces: the `job` a submit returned, in this workspace.",
        ),
        status: Literal["pending", "ready", "failed"] | None = Query(
            default=None, description="Only images in this state."
        ),
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=100, ge=1, le=100),
        entity_client: NemoEntitiesClient = Depends(get_entity_client),
    ) -> list[ContainerImage]:
        """List the images in a workspace, in whatever state they are in, or only one job's."""
        filters: dict[str, object] = {}
        if job is not None:
            filters["provenance.job"] = f"{workspace}/{job}"
        if status is not None:
            filters["status"] = status
        response = await entity_client.list(
            ContainerImage, workspace=workspace, filter_obj=filters or None, page=page, page_size=page_size
        )
        return response.data

    @router.get("/container-images/{name}", response_model=ContainerImage, tags=["Builder"])
    @scope.read
    @path_rule(callers=[CallerKind.PRINCIPAL], permissions=[ContainerImagePerms.READ])
    async def get_container_image(
        workspace: str,
        name: str,
        entity_client: NemoEntitiesClient = Depends(get_entity_client),
    ) -> ContainerImage:
        """Read one image. This is what a caller polls until `status` leaves `pending`."""
        try:
            return await entity_client.get(ContainerImage, name=name, workspace=workspace)
        except NemoEntityNotFoundError as exc:
            raise HTTPException(status_code=404, detail=f"Container image '{name}' not found.") from exc

    @router.post("/container-images/{name}/push-credentials", response_model=PushCredentials, tags=["Builder"])
    @scope.write
    @path_rule(callers=[CallerKind.PRINCIPAL], permissions=[ContainerImagePerms.COMPLETE])
    async def get_push_credentials(
        workspace: str,
        name: str,
        entity_client: NemoEntitiesClient = Depends(get_entity_client),
        broker: Broker = Depends(get_broker),
        caller: Caller = Depends(current_caller),
    ) -> PushCredentials:
        """A registry token for one `pending` image's repository: what the build's push step pushes with.

        403 unless the caller is a job step acting for the image's submitter; 409 once the image has settled.
        """
        row = await _get_row(entity_client, workspace, name)
        refusal = broker.refusal(row, caller)
        if refusal is not None:
            broker.refused(row, caller, "credentials", refusal)
            raise HTTPException(status_code=403, detail=refusal)
        if row.status != "pending":
            raise HTTPException(status_code=409, detail=f"{name} is {row.status}; there is nothing left to publish.")
        try:
            return await asyncio.to_thread(broker.credentials, row, caller)
        except RegistryAuthError as exc:
            logger.error(
                "credentials for %s/%s failed: %s",
                sanitize_for_log(workspace),
                sanitize_for_log(name),
                sanitize_for_log(exc),
            )
            raise HTTPException(status_code=502, detail="The registry's token service failed or refused.") from exc
        except AuditUnavailable as exc:
            logger.exception(
                "credentials for %s/%s withheld: no audit line", sanitize_for_log(workspace), sanitize_for_log(name)
            )
            raise HTTPException(status_code=503, detail="The audit log is unavailable.") from exc

    @router.post("/container-images/{name}/complete", response_model=ContainerImage, tags=["Builder"])
    @scope.write
    @path_rule(callers=[CallerKind.PRINCIPAL], permissions=[ContainerImagePerms.COMPLETE])
    async def complete_container_image(
        workspace: str,
        name: str,
        body: CompleteRequest,
        entity_client: NemoEntitiesClient = Depends(get_entity_client),
        broker: Broker = Depends(get_broker),
        caller: Caller = Depends(current_caller),
    ) -> ContainerImage:
        """Sign the digest the push step pushed, if the image's system tag still holds it, and make the image `ready`.

        Completing an image already `ready` at that digest returns it; 409 if the tag moved or it settled otherwise.
        """
        row = await _get_row(entity_client, workspace, name)
        refusal = broker.refusal(row, caller)
        if refusal is not None:
            broker.refused(row, caller, "sign", refusal)
            raise HTTPException(status_code=403, detail=refusal)
        try:
            if settled(row, body.digest):
                return row
            signature = await asyncio.to_thread(broker.sign, row, body.digest, caller)
            ready = await complete(
                entity_client, workspace=workspace, name=name, digest=body.digest, signature=signature
            )
        except NemoEntityNotFoundError as exc:
            raise HTTPException(status_code=404, detail=f"Container image '{name}' not found.") from exc
        except (TagMoved, CompletionConflict) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except SigningFailed as exc:
            logger.error(
                "signing %s/%s failed: %s", sanitize_for_log(workspace), sanitize_for_log(name), sanitize_for_log(exc)
            )
            raise HTTPException(status_code=502, detail="Signing failed.") from exc
        except AuditUnavailable as exc:
            logger.exception(
                "signature for %s/%s withheld: no audit line", sanitize_for_log(workspace), sanitize_for_log(name)
            )
            raise HTTPException(status_code=503, detail="The audit log is unavailable.") from exc
        logger.info(
            "image %s/%s ready: %s",
            sanitize_for_log(workspace),
            sanitize_for_log(name),
            sanitize_for_log(ready.image_ref),
        )
        return ready

    return router
