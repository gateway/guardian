"""Shared stdlib HTTP client with pacing, retries, and conditional caching."""

from __future__ import annotations

import email.utils
import hashlib
import json
import os
import random
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from .config import GuardianConfig


_PACE_LOCK = threading.Lock()
_LAST_REQUEST_BY_HOST: dict[str, float] = {}


class HttpRequestError(RuntimeError):
    """Raised when a caller requires a response that could not be obtained."""


@dataclass(frozen=True)
class HttpResult:
    """Structured response state used by source clients and source contracts."""

    status: int | None
    body: bytes
    headers: dict[str, str]
    from_cache: bool
    revalidated: bool
    attempts: int
    bytes_downloaded: int
    error: str | None = None

    def json(self) -> Any:
        if self.error:
            raise HttpRequestError(self.error)
        try:
            return json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HttpRequestError(f"invalid JSON response: {exc}") from exc


class GuardianHttp:
    """Perform bounded requests while sharing cache and host pacing policy."""

    def __init__(self, config: GuardianConfig):
        self.config = config
        self.cache_dir = Path(config.threat_intel_cache_dir) / "http_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.requests = 0
        self.cache_hits = 0
        self.revalidations = 0
        self.bytes_downloaded = 0

    def get(self, url: str, *, headers: dict[str, str] | None = None, cache: bool = True) -> HttpResult:
        return self.request("GET", url, headers=headers, cache=cache)

    def post(
        self,
        url: str,
        *,
        data: bytes,
        headers: dict[str, str] | None = None,
    ) -> HttpResult:
        return self.request("POST", url, headers=headers, data=data, cache=False)

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
        cache: bool | None = None,
    ) -> HttpResult:
        method = method.upper()
        use_cache = method == "GET" if cache is None else bool(cache and method == "GET")
        cache_entry = self._load_cache(url) if use_cache else None
        if cache_entry and self._cache_fresh(cache_entry[0]):
            self.cache_hits += 1
            return self._cached_result(cache_entry, revalidated=False, attempts=0)

        request_headers = {"User-Agent": self.config.user_agent, **(headers or {})}
        if cache_entry:
            metadata = cache_entry[0]
            if metadata.get("etag"):
                request_headers["If-None-Match"] = metadata["etag"]
            if metadata.get("last_modified"):
                request_headers["If-Modified-Since"] = metadata["last_modified"]

        max_attempts = max(1, int(self.config.http_max_retries) + 1)
        last_error: str | None = None
        attempts_used = 0
        for attempt in range(1, max_attempts + 1):
            attempts_used = attempt
            self._pace(url)
            self.requests += 1
            request = Request(url, data=data, headers=request_headers, method=method)
            try:
                with urlopen(request, timeout=self.config.request_timeout_seconds) as response:
                    body = response.read()
                    response_headers = {key.lower(): value for key, value in response.headers.items()}
                    status = int(getattr(response, "status", 200))
                self.bytes_downloaded += len(body)
                result = HttpResult(
                    status=status,
                    body=body,
                    headers=response_headers,
                    from_cache=False,
                    revalidated=False,
                    attempts=attempt,
                    bytes_downloaded=len(body),
                )
                if use_cache and status == 200:
                    self._write_cache(url, result)
                return result
            except HTTPError as exc:
                if exc.code == 304 and cache_entry:
                    self._touch_cache(url, cache_entry[0])
                    self.cache_hits += 1
                    self.revalidations += 1
                    return self._cached_result(cache_entry, revalidated=True, attempts=attempt)
                last_error = f"HTTP {exc.code} for {url}"
                if exc.code not in {429, 500, 502, 503, 504} or attempt >= max_attempts:
                    break
                self._backoff(attempt, exc.headers.get("Retry-After") if exc.headers else None)
            except (URLError, TimeoutError, OSError) as exc:
                last_error = f"request failed for {url}: {exc}"
                if attempt >= max_attempts:
                    break
                self._backoff(attempt, None)

        return HttpResult(
            status=None,
            body=b"",
            headers={},
            from_cache=False,
            revalidated=False,
            attempts=attempts_used,
            bytes_downloaded=0,
            error=last_error or f"request failed for {url}",
        )

    def stats(self) -> dict[str, int | bool]:
        return {
            "requests": self.requests,
            "cache_hits": self.cache_hits,
            "revalidations": self.revalidations,
            "bytes_downloaded": self.bytes_downloaded,
            "from_cache": self.cache_hits > 0,
        }

    def _pace(self, url: str) -> None:
        interval = max(0.0, float(self.config.api_request_min_interval_seconds))
        if interval <= 0:
            return
        host = urlsplit(url).netloc.lower()
        with _PACE_LOCK:
            elapsed = time.monotonic() - _LAST_REQUEST_BY_HOST.get(host, 0.0)
            if elapsed < interval:
                time.sleep(interval - elapsed)
            _LAST_REQUEST_BY_HOST[host] = time.monotonic()

    def _backoff(self, attempt: int, retry_after: str | None) -> None:
        delay = _retry_after_seconds(retry_after)
        if delay is None:
            delay = min(4.0, (0.25 * (2 ** (attempt - 1))) + random.uniform(0.0, 0.1))
        time.sleep(max(0.0, min(delay, float(self.config.request_timeout_seconds))))

    def _cache_paths(self, url: str) -> tuple[Path, Path]:
        key = hashlib.sha256(url.encode("utf-8")).hexdigest()
        return self.cache_dir / f"{key}.json", self.cache_dir / f"{key}.body"

    def _load_cache(self, url: str) -> tuple[dict, bytes] | None:
        metadata_path, body_path = self._cache_paths(url)
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            body = body_path.read_bytes()
        except (OSError, json.JSONDecodeError):
            return None
        if metadata.get("url") != url:
            return None
        if metadata.get("body_sha256") != hashlib.sha256(body).hexdigest():
            return None
        return metadata, body

    def _cache_fresh(self, metadata: dict) -> bool:
        ttl = max(0, int(self.config.http_cache_ttl_seconds))
        return ttl > 0 and time.time() - float(metadata.get("fetched_at_epoch", 0)) < ttl

    def _write_cache(self, url: str, result: HttpResult) -> None:
        metadata_path, body_path = self._cache_paths(url)
        metadata = {
            "url": url,
            "etag": result.headers.get("etag"),
            "last_modified": result.headers.get("last-modified"),
            "fetched_at_epoch": time.time(),
            "body_sha256": hashlib.sha256(result.body).hexdigest(),
        }
        _atomic_write(body_path, result.body)
        _atomic_write(metadata_path, json.dumps(metadata, sort_keys=True).encode("utf-8"))

    def _touch_cache(self, url: str, metadata: dict) -> None:
        metadata_path, _body_path = self._cache_paths(url)
        updated = {**metadata, "fetched_at_epoch": time.time()}
        _atomic_write(metadata_path, json.dumps(updated, sort_keys=True).encode("utf-8"))

    @staticmethod
    def _cached_result(entry: tuple[dict, bytes], *, revalidated: bool, attempts: int) -> HttpResult:
        metadata, body = entry
        return HttpResult(
            status=304 if revalidated else 200,
            body=body,
            headers={
                "etag": metadata.get("etag") or "",
                "last-modified": metadata.get("last_modified") or "",
            },
            from_cache=True,
            revalidated=revalidated,
            attempts=attempts,
            bytes_downloaded=0,
        )


def _retry_after_seconds(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        try:
            parsed = email.utils.parsedate_to_datetime(value)
            return max(0.0, parsed.timestamp() - time.time())
        except (TypeError, ValueError, OverflowError):
            return None


def _atomic_write(path: Path, data: bytes) -> None:
    """Replace one cache file atomically so interrupted writes are ignored."""

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
