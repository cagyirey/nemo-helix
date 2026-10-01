# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""``nhx-build push``: the last step. It publishes each image, then has the builder sign and complete it.

Each OCI layout was written by caller code, so it is validated as hostile before anything is uploaded.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import tempfile
import time
from collections.abc import Callable, Mapping
from pathlib import Path, PurePosixPath
from typing import Protocol, TypeVar

from nemo_builder_plugin.broker import CompleteRequest
from nemo_builder_plugin.client import BuilderClient
from nemo_builder_plugin.entities import ContainerImage
from nemo_builder_plugin.run.context import job_identity, read_step_config, work_mount
from nemo_builder_plugin.run.tools import run_tool
from nemo_builder_plugin.steps import PushImage, PushStepConfig, WorkLayout
from nemo_helix_plugin.client.adapter import client_from_platform
from nemo_helix_plugin.client.errors import NemoHTTPError, NemoTransportError
from nemo_helix_plugin.client_provider import get_task_nemo_client
from nemo_helix_plugin.log_utils import sanitize_for_log

logger = logging.getLogger(__name__)

#: Blobs are hashed in chunks: a caller's layer can be larger than this step's memory.
_CHUNK = 1024 * 1024

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")

_ATTEMPTS = 5

_T = TypeVar("_T")


class Refused(Exception):
    """The builder would not publish or complete an image, or completed it as something else."""


class _Builder(Protocol):
    """What publishing needs from the builder."""

    def credentials(self, image: str) -> dict[str, object]: ...

    def complete(self, image: str, digest: str) -> ContainerImage: ...

    def status(self, image: str) -> str: ...


def write_docker_config(directory: Path, config: Mapping[str, object]) -> None:
    """Where crane looks for credentials: ``$DOCKER_CONFIG/config.json``."""
    path = directory / "config.json"
    path.write_text(json.dumps(config))
    path.chmod(0o600)


class LayoutRejected(Exception):
    """The OCI layout failed validation and will not be published."""


def _verify_no_escape(root: Path) -> list[Path]:
    """Every regular file under ``root``, refusing any symlink: a later read would follow it."""
    root = root.resolve(strict=True)
    files: list[Path] = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise LayoutRejected(f"layout contains a symlink: {path.relative_to(root)}")
        resolved = path.resolve()
        if root not in resolved.parents and resolved != root:
            raise LayoutRejected(f"layout path escapes its directory: {path}")
        if path.is_file():
            files.append(path)
        elif not path.is_dir():
            # A FIFO named as a blob, if skipped here, would block crane's `open()` forever.
            raise LayoutRejected(f"layout contains something that is not a file: {path.relative_to(root)}")
    return files


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def validate_layout(layout: Path) -> str:
    """Return the digest of the layout's one manifest, or raise :class:`LayoutRejected`."""
    if layout.is_symlink():
        # Checked before resolving, which would follow it.
        raise LayoutRejected(f"layout {layout} is a symlink")
    if not layout.is_dir():
        raise LayoutRejected(f"no layout at {layout}")

    # The work volume is mounted under `/var/run`, usually a symlink to `/run`, and
    # `_verify_no_escape` returns resolved paths: everything below uses the resolved layout.
    layout = layout.resolve(strict=True)
    files = _verify_no_escape(layout)

    marker = layout / "oci-layout"
    index_path = layout / "index.json"
    for required in (marker, index_path):
        if not required.is_file():
            raise LayoutRejected(f"layout is missing {required.name}")

    blobs_dir = layout / "blobs" / "sha256"
    for path in files:
        if blobs_dir not in path.parents:
            if path not in (marker, index_path):
                raise LayoutRejected(f"unexpected file in layout: {path.relative_to(layout)}")
            continue
        actual = _sha256_file(path)
        if actual != path.name:
            raise LayoutRejected(f"blob {path.name} hashes to {actual}: the layout misdescribes its contents")

    try:
        index = json.loads(index_path.read_text())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LayoutRejected("index.json is not JSON") from exc
    manifests = index.get("manifests") if isinstance(index, dict) else None
    if not isinstance(manifests, list) or len(manifests) != 1 or not isinstance(manifests[0], dict):
        raise LayoutRejected("expected exactly one manifest in index.json")

    digest = manifests[0].get("digest")
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        raise LayoutRejected(f"index.json names something other than a sha256 digest: {digest!r}")
    if not (blobs_dir / digest.removeprefix("sha256:")).is_file():
        raise LayoutRejected(f"index.json names a manifest that is not in the layout: {digest}")

    logger.info(
        "layout %s validated: %d blob(s), manifest %s",
        sanitize_for_log(layout.name),
        len(files),
        sanitize_for_log(digest),
    )
    return digest


class Builder:
    """This step's calls to the builder's routes, as the submitter, retrying what may be transient.

    Both are safe to repeat: completing an image already ``ready`` at the same digest returns it.
    """

    def __init__(self, client: BuilderClient, *, workspace: str, sleep: Callable[[float], None] = time.sleep) -> None:
        self._client = client
        self._workspace = workspace
        self._sleep = sleep

    def _call(self, what: str, call: Callable[[], _T]) -> _T:
        for attempt in range(_ATTEMPTS):
            try:
                return call()
            except NemoTransportError as exc:
                failure: Exception = exc
            except NemoHTTPError as exc:
                if exc.status_code != 429 and exc.status_code < 500:
                    raise
                failure = exc
            if attempt + 1 < _ATTEMPTS:
                logger.warning("%s failed (%s); retrying", what, sanitize_for_log(failure))
                self._sleep(2.0**attempt)
        raise failure

    def credentials(self, image: str) -> dict[str, object]:
        """A Docker config for ``image``'s repository: ``{"auths": {<registry>: {"registrytoken": ...}}}``."""
        issued = self._call(
            f"credentials for {image}",
            lambda: self._client.get_push_credentials(workspace=self._workspace, name=image).data(),
        )
        if not issued.auths:
            raise Refused(f"the builder returned no credential for {image}")
        logger.info(
            "the builder granted %s (expires in %ss; narrowed by the registry: %s)",
            sanitize_for_log(issued.repository),
            issued.expires_in,
            issued.narrowed,
        )
        return {"auths": issued.auths}

    def complete(self, image: str, digest: str) -> ContainerImage:
        return self._call(
            f"completing {image}",
            lambda: self._client.complete_container_image(
                workspace=self._workspace, name=image, body=CompleteRequest(digest=digest)
            ).data(),
        )

    def status(self, image: str) -> str:
        return self._client.get_container_image(workspace=self._workspace, name=image).data().status


def _push_one(image: PushImage, layout: Path, *, builder: _Builder, docker_config: Path, plain_http: bool) -> None:
    digest = validate_layout(layout)

    # A token per image: a registry's token lives minutes, and publishing a set can take longer.
    write_docker_config(docker_config, builder.credentials(image.image))
    # Destinations come from the compiler: nothing read off the volume reaches this list.
    for ref in image.refs:
        run_tool(["crane", "push", str(layout), ref, *(["--insecure"] if plain_http else [])])

    # The builder signs only if the system tag still holds what this step pushed.
    row = builder.complete(image.image, digest)
    if row.status != "ready" or row.digest != digest:
        raise Refused(f"the builder completed {image.image} as {row.status} at {row.digest}, not ready at {digest}")
    logger.info(
        "published, signed and completed %s@%s",
        sanitize_for_log(image.system_ref.rsplit(":", 1)[0]),
        sanitize_for_log(digest),
    )


def _publish_all(config: PushStepConfig, *, builder: _Builder, docker_config: Path) -> int:
    work = WorkLayout(PurePosixPath(work_mount()))
    published = 0
    failures = 0
    for image in config.images:
        try:
            status = builder.status(image.image)
        except (NemoHTTPError, NemoTransportError):
            logger.exception("cannot read %s; not publishing it", sanitize_for_log(image.image))
            failures += 1
            continue
        if status != "pending":
            logger.info("%s is already %s; nothing to publish", sanitize_for_log(image.image), sanitize_for_log(status))
            if status == "ready":
                published += 1
            else:
                failures += 1
            continue
        layout = Path(work.output(image.image))
        if not layout.exists():
            logger.warning("no layout for %s; skipping (its build failed)", sanitize_for_log(image.image))
            failures += 1
            continue
        try:
            _push_one(image, layout, builder=builder, docker_config=docker_config, plain_http=config.plain_http)
            published += 1
        except Exception:
            # Any error, anticipated or not: one image must not cost the rest of the set.
            logger.exception("refusing to publish %s", sanitize_for_log(image.image))
            failures += 1

    logger.info("published %d image(s), %d failure(s)", published, failures)
    return 1 if failures else 0


def main() -> int:
    config = PushStepConfig.model_validate(read_step_config())
    workspace, _ = job_identity()
    # As the submitter, through the job's delegation: this step has no platform identity of its own.
    builder = Builder(client_from_platform(get_task_nemo_client("builder"), BuilderClient), workspace=workspace)
    directory = Path(tempfile.mkdtemp(prefix="nhx-docker-"))
    os.environ["DOCKER_CONFIG"] = str(directory)
    try:
        return _publish_all(config, builder=builder, docker_config=directory)
    finally:
        shutil.rmtree(directory, ignore_errors=True)
