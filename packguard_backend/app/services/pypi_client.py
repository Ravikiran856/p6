"""Async PyPI metadata fetch and source download."""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from typing import List, Optional

import httpx

from app.core.config import Settings

logger = logging.getLogger(__name__)

PACKAGE_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")


class PyPIError(Exception):
    """Base PyPI client error."""


class PackageNotFoundError(PyPIError):
    """Package does not exist on PyPI."""


class PyPITimeoutError(PyPIError):
    """PyPI request timed out."""


@dataclass
class PackageMetadata:
    name: str
    version: str
    requires_dist: List[str]
    summary: Optional[str] = None


@dataclass
class DownloadedPackage:
    metadata: PackageMetadata
    extract_dir: str
    temp_root: str


def normalize_package_name(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def parse_dependency_name(requires_dist_entry: str) -> Optional[str]:
    """Extract bare package name from 'requests (>=2.0)' style specifier."""
    match = re.match(r"^([A-Za-z0-9_.\-]+)", requires_dist_entry.strip())
    if not match:
        return None
    return normalize_package_name(match.group(1))


class PyPIClient:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._timeout = httpx.Timeout(settings.pypi_timeout_seconds)

    async def _get_json(self, url: str) -> dict:
        last_exc: Optional[Exception] = None
        for attempt in range(self._settings.pypi_max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    response = await client.get(url, follow_redirects=True)
                if response.status_code == 404:
                    raise PackageNotFoundError(f"Package not found at {url}")
                response.raise_for_status()
                return response.json()
            except httpx.TimeoutException as exc:
                last_exc = exc
                logger.warning("PyPI timeout (attempt %d): %s", attempt + 1, url)
                await asyncio.sleep(0.5 * (attempt + 1))
            except httpx.HTTPError as exc:
                last_exc = exc
                if attempt < self._settings.pypi_max_retries:
                    await asyncio.sleep(0.5 * (attempt + 1))
                else:
                    raise PyPIError(f"PyPI HTTP error: {exc}") from exc
        raise PyPITimeoutError(f"PyPI request timed out after retries: {url}") from last_exc

    async def fetch_metadata(
        self,
        package_name: str,
        version: Optional[str] = None,
    ) -> PackageMetadata:
        normalized = normalize_package_name(package_name)
        if not PACKAGE_NAME_RE.match(normalized):
            raise PyPIError(f"Invalid package name: {package_name}")

        if version:
            url = f"{self._settings.pypi_base_url}/{normalized}/{version}/json"
        else:
            url = f"{self._settings.pypi_base_url}/{normalized}/json"

        data = await self._get_json(url)
        info = data.get("info", {})
        resolved_version = version or info.get("version", "")
        requires_dist = info.get("requires_dist") or []

        return PackageMetadata(
            name=info.get("name", normalized),
            version=resolved_version,
            requires_dist=list(requires_dist),
            summary=info.get("summary"),
        )

    async def download_and_extract(
        self,
        package_name: str,
        version: Optional[str] = None,
    ) -> DownloadedPackage:
        normalized = normalize_package_name(package_name)
        metadata = await self.fetch_metadata(normalized, version)

        data = await self._get_json(
            f"{self._settings.pypi_base_url}/{normalized}/{metadata.version}/json"
        )
        urls = data.get("urls", [])

        download_url: Optional[str] = None
        for pack_type in ("sdist", "bdist_wheel"):
            for entry in urls:
                if entry.get("packagetype") == pack_type and entry.get("url"):
                    download_url = entry["url"]
                    break
            if download_url:
                break

        if not download_url:
            raise PyPIError(
                f"No downloadable artifact found for {normalized}=={metadata.version}"
            )

        temp_root = tempfile.mkdtemp(prefix="packguard_")
        if download_url.endswith(".tar.gz"):
            ext = ".tar.gz"
        elif download_url.endswith(".whl"):
            ext = ".whl"
        elif download_url.endswith(".zip"):
            ext = ".zip"
        else:
            ext = ".tar.gz"
        archive_path = os.path.join(temp_root, f"package_archive{ext}")

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                async with client.stream("GET", download_url, follow_redirects=True) as resp:
                    resp.raise_for_status()
                    with open(archive_path, "wb") as fh:
                        async for chunk in resp.aiter_bytes():
                            fh.write(chunk)

            extract_dir = os.path.join(temp_root, "src")
            os.makedirs(extract_dir, exist_ok=True)

            if archive_path.endswith(".tar.gz"):
                with tarfile.open(archive_path, "r:gz") as tar:
                    # data filter avoids path traversal when extracting untrusted PyPI sdists
                    tar.extractall(extract_dir, filter="data")
            elif archive_path.endswith((".whl", ".zip")):
                with zipfile.ZipFile(archive_path, "r") as zf:
                    zf.extractall(extract_dir)
            else:
                raise PyPIError(f"Unsupported archive format: {download_url}")

            # Flatten single top-level directory (common in sdists)
            entries = os.listdir(extract_dir)
            if len(entries) == 1:
                sole = os.path.join(extract_dir, entries[0])
                if os.path.isdir(sole):
                    inner = os.path.join(temp_root, "src_flat")
                    shutil.move(sole, inner)
                    shutil.rmtree(extract_dir, ignore_errors=True)
                    extract_dir = inner

            return DownloadedPackage(
                metadata=metadata,
                extract_dir=extract_dir,
                temp_root=temp_root,
            )
        except Exception:
            shutil.rmtree(temp_root, ignore_errors=True)
            raise

    @staticmethod
    def cleanup(downloaded: DownloadedPackage) -> None:
        shutil.rmtree(downloaded.temp_root, ignore_errors=True)
