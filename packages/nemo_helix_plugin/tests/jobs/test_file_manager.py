# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path
from typing import cast

import httpx
import pytest
from filesets import AsyncFilesetFileSystem, FilesetFileSystem
from nemo_helix_plugin.client.errors import NemoTransportError
from nemo_helix_plugin.jobs import file_manager
from nemo_helix_plugin.jobs.file_manager import AsyncFilesetFileManager, FilesetFileManager


class _FakeFilesetFileSystem:
    def __init__(self) -> None:
        self.downloads: list[tuple[str, str, bool]] = []

    def info(self, path: str) -> object:
        raise AssertionError(f"info should not be called for trailing-slash refs: {path}")

    def get(self, rpath: str, lpath: str, recursive: bool = True) -> None:
        self.downloads.append((rpath, lpath, recursive))
        local_path = Path(lpath)
        local_path.mkdir(parents=True, exist_ok=True)
        (local_path / "context.txt").write_text("downloaded")


class _FakeAsyncFilesetFileSystem:
    def __init__(self) -> None:
        self.downloads: list[tuple[str, str, bool]] = []

    async def _info(self, path: str) -> object:
        raise AssertionError(f"_info should not be called for trailing-slash refs: {path}")

    async def _get(self, rpath: str, lpath: str, recursive: bool = True) -> None:
        self.downloads.append((rpath, lpath, recursive))
        local_path = Path(lpath)
        local_path.mkdir(parents=True, exist_ok=True)
        (local_path / "context.txt").write_text("downloaded")


def test_fileset_manager_downloads_trailing_slash_ref_without_info(tmp_path: Path) -> None:
    fs = _FakeFilesetFileSystem()
    manager = FilesetFileManager(
        workspace="default",
        fileset_name="inputs",
        filesystem=cast(FilesetFileSystem, fs),
        ensure_fileset_exists=False,
    )

    result = manager.download_from_url("default/inputs#project/", local_dir=tmp_path)

    assert fs.downloads == [("default/inputs#project/", str(tmp_path), True)]
    assert result.path == tmp_path
    assert result.tmp_dir == tmp_path
    assert (tmp_path / "context.txt").read_text() == "downloaded"


@pytest.mark.asyncio
async def test_async_fileset_manager_downloads_trailing_slash_ref_without_info(tmp_path: Path) -> None:
    fs = _FakeAsyncFilesetFileSystem()
    manager = AsyncFilesetFileManager(
        workspace="default",
        fileset_name="inputs",
        filesystem=cast(AsyncFilesetFileSystem, fs),
        ensure_fileset_exists=False,
    )

    result = await manager.download_from_url("default/inputs#project/", local_dir=tmp_path)

    assert fs.downloads == [("default/inputs#project/", str(tmp_path), True)]
    assert result.path == tmp_path
    assert result.tmp_dir == tmp_path
    assert (tmp_path / "context.txt").read_text() == "downloaded"


def _timed_out() -> NemoTransportError:
    return NemoTransportError(httpx.ReadTimeout("timed out"))


class _FlakyUploadFileSystem:
    """Fails the first `failures` uploads the way the typed client does when a streamed body times out."""

    def __init__(self, failures: int, error: Exception | None = None) -> None:
        self.failures = failures
        self.error = error
        self.attempts: list[tuple[str, str]] = []
        self.uploaded: dict[str, bytes] = {}

    def _attempt(self, lpath: str, rpath: str) -> None:
        self.attempts.append((lpath, rpath))
        if len(self.attempts) <= self.failures:
            raise self.error or _timed_out()
        self.uploaded[rpath] = Path(lpath).read_bytes()

    def put_file(self, lpath: str, rpath: str) -> None:
        self._attempt(lpath, rpath)

    async def _put_file(self, lpath: str, rpath: str) -> None:
        self._attempt(lpath, rpath)


@pytest.fixture
def no_upload_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(file_manager, "UPLOAD_BACKOFF_SECONDS", 0.0, raising=False)


def _sync_manager(fs: _FlakyUploadFileSystem) -> FilesetFileManager:
    return FilesetFileManager(
        workspace="default",
        fileset_name="results",
        filesystem=cast(FilesetFileSystem, fs),
        ensure_fileset_exists=False,
    )


def _async_manager(fs: _FlakyUploadFileSystem) -> AsyncFilesetFileManager:
    return AsyncFilesetFileManager(
        workspace="default",
        fileset_name="results",
        filesystem=cast(AsyncFilesetFileSystem, fs),
        ensure_fileset_exists=False,
    )


def test_fileset_manager_retries_an_upload_that_timed_out(tmp_path: Path, no_upload_backoff: None) -> None:
    source = tmp_path / "bundle.json"
    source.write_text('{"scores": [1]}')
    fs = _FlakyUploadFileSystem(failures=1)

    _sync_manager(fs).upload(source, "results/bundle.json")

    assert len(fs.attempts) == 2
    assert fs.uploaded == {"default/results#results/bundle.json": b'{"scores": [1]}'}


async def test_async_fileset_manager_retries_an_upload_that_timed_out(tmp_path: Path, no_upload_backoff: None) -> None:
    source = tmp_path / "bundle.json"
    source.write_text('{"scores": [1]}')
    fs = _FlakyUploadFileSystem(failures=1)

    await _async_manager(fs).upload(source, "results/bundle.json")

    assert len(fs.attempts) == 2
    assert fs.uploaded == {"default/results#results/bundle.json": b'{"scores": [1]}'}


def test_fileset_manager_gives_up_after_the_last_attempt(tmp_path: Path, no_upload_backoff: None) -> None:
    source = tmp_path / "bundle.json"
    source.write_text("{}")
    fs = _FlakyUploadFileSystem(failures=file_manager.UPLOAD_ATTEMPTS)

    with pytest.raises(NemoTransportError):
        _sync_manager(fs).upload(source, "results/bundle.json")

    assert len(fs.attempts) == file_manager.UPLOAD_ATTEMPTS


def test_fileset_manager_does_not_retry_a_permanent_failure(tmp_path: Path, no_upload_backoff: None) -> None:
    source = tmp_path / "bundle.json"
    source.write_text("{}")
    fs = _FlakyUploadFileSystem(failures=1, error=ValueError("File path required for upload"))

    with pytest.raises(ValueError):
        _sync_manager(fs).upload(source, "results/bundle.json")

    assert len(fs.attempts) == 1
