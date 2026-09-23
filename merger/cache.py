"""V5 Incremental cache layer — HTTP ETag / Last-Modified / content hash.

Implements the Phase 1 incremental update mechanism:
  - Each source's response is cached with its ETag, Last-Modified, and
    a SHA-256 content hash.
  - On subsequent fetches, conditional headers (If-None-Match /
    If-Modified-Since) are sent; a 304 response means the cached copy
    is still valid and is reused directly.
  - Even when the server doesn't support conditional requests, the content
    hash is compared — identical content skips re-parsing.
  - Cache TTL and max size are configurable.

Cache layout (under cache_dir):
  cache/
    index.json              # metadata for all sources
    content/<sha256>.txt   # cached response bodies
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)


# ── cache entry ───────────────────────────────────────────────────


@dataclass
class CacheEntry:
    """Metadata for one cached source."""

    url: str
    etag: Optional[str] = None
    last_modified: Optional[str] = None
    content_hash: Optional[str] = None  # SHA-256 hex
    content_path: Optional[str] = None   # relative path within cache_dir
    fetched_at: float = 0.0               # Unix timestamp
    size_bytes: int = 0
    rule_count: int = 0  # populated after parse

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "CacheEntry":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


# ── cache manager ──────────────────────────────────────────────────


class SourceCache:
    """File-backed cache for source responses with conditional-request support.

    Args:
        cache_dir:    Directory for cache storage.
        ttl_seconds:  Maximum age of a cache entry before it's considered
                      stale (0 = never expire based on time).
        max_size_mb:  Maximum total cache size in MB; oldest entries are
                      evicted when exceeded (0 = unlimited).
    """

    INDEX_FILENAME = "index.json"
    CONTENT_SUBDIR = "content"

    def __init__(
        self,
        cache_dir: str = "cache",
        ttl_seconds: int = 0,
        max_size_mb: int = 0,
    ) -> None:
        self.cache_dir = Path(cache_dir)
        self.ttl_seconds = ttl_seconds
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self._entries: Dict[str, CacheEntry] = {}
        self._loaded = False

    # ── persistence ─────────────────────────────────────────────

    def _index_path(self) -> Path:
        return self.cache_dir / self.INDEX_FILENAME

    def _content_dir(self) -> Path:
        return self.cache_dir / self.CONTENT_SUBDIR

    def load(self) -> None:
        """Load cache index from disk (idempotent)."""
        if self._loaded:
            return
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._content_dir().mkdir(parents=True, exist_ok=True)

        idx = self._index_path()
        if idx.exists():
            try:
                data = json.loads(idx.read_text(encoding="utf-8"))
                for url, entry_dict in data.get("entries", {}).items():
                    self._entries[url] = CacheEntry.from_dict(entry_dict)
                logger.debug("Loaded %d cache entries", len(self._entries))
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("Cache index corrupted, starting fresh: %s", e)
                self._entries = {}
        self._loaded = True

    def save(self) -> None:
        """Persist cache index to disk."""
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        data = {
            "version": 5,
            "updated_at": time.time(),
            "entries": {url: e.to_dict() for url, e in self._entries.items()},
        }
        tmp = self._index_path().with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self._index_path())

    # ── lookup ──────────────────────────────────────────────────

    def get(self, url: str) -> Optional[CacheEntry]:
        """Get cache entry for a URL, or None if not cached / expired."""
        self.load()
        entry = self._entries.get(url)
        if entry is None:
            return None
        # TTL check
        if self.ttl_seconds > 0:
            age = time.time() - entry.fetched_at
            if age > self.ttl_seconds:
                logger.debug("Cache expired for %s (age %.0fs)", url, age)
                return None
        # content file existence check
        if entry.content_path:
            full = self.cache_dir / entry.content_path
            if not full.exists():
                logger.debug("Cache content missing for %s", url)
                return None
        return entry

    def get_content(self, url: str) -> Optional[str]:
        """Get cached response body text, or None."""
        entry = self.get(url)
        if entry is None or not entry.content_path:
            return None
        full = self.cache_dir / entry.content_path
        try:
            return full.read_text(encoding="utf-8")
        except OSError as e:
            logger.warning("Failed to read cache content for %s: %s", url, e)
            return None

    # ── conditional request headers ──────────────────────────────

    def conditional_headers(self, url: str) -> Dict[str, str]:
        """Return HTTP headers for a conditional GET, or empty dict."""
        entry = self.get(url)
        if entry is None:
            return {}
        headers: Dict[str, str] = {}
        if entry.etag:
            headers["If-None-Match"] = entry.etag
        if entry.last_modified:
            headers["If-Modified-Since"] = entry.last_modified
        return headers

    # ── store ───────────────────────────────────────────────────

    def store(
        self,
        url: str,
        content: str,
        etag: Optional[str] = None,
        last_modified: Optional[str] = None,
        rule_count: int = 0,
    ) -> CacheEntry:
        """Store a response in the cache and return the new entry."""
        self.load()

        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        rel_path = f"{self.CONTENT_SUBDIR}/{content_hash}.txt"
        full_path = self.cache_dir / rel_path

        # write content (only if not already present)
        if not full_path.exists():
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text(content, encoding="utf-8")

        entry = CacheEntry(
            url=url,
            etag=etag,
            last_modified=last_modified,
            content_hash=content_hash,
            content_path=rel_path,
            fetched_at=time.time(),
            size_bytes=len(content.encode("utf-8")),
            rule_count=rule_count,
        )
        self._entries[url] = entry

        # evict if over size limit
        if self.max_size_bytes > 0:
            self._evict_if_needed()

        return entry

    def store_not_modified(self, url: str) -> Optional[CacheEntry]:
        """Update the fetched_at timestamp for a 304 response.

        Returns the refreshed entry, or None if no existing entry.
        """
        entry = self._entries.get(url)
        if entry is None:
            return None
        entry.fetched_at = time.time()
        return entry

    # ── content hash comparison ──────────────────────────────────

    def content_changed(self, url: str, content: str) -> bool:
        """Check if content differs from the cached version by hash."""
        entry = self._entries.get(url)
        if entry is None or not entry.content_hash:
            return True
        new_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        return new_hash != entry.content_hash

    # ── eviction ─────────────────────────────────────────────────

    def _evict_if_needed(self) -> None:
        """Evict oldest entries when total cache size exceeds limit."""
        total = sum(e.size_bytes for e in self._entries.values())
        if total <= self.max_size_bytes:
            return

        # sort by fetched_at ascending (oldest first)
        sorted_entries = sorted(self._entries.values(), key=lambda e: e.fetched_at)
        for entry in sorted_entries:
            if total <= self.max_size_bytes:
                break
            # remove content file if no other entry references it
            if entry.content_path:
                full = self.cache_dir / entry.content_path
                # check hash uniqueness
                hash_in_use = any(
                    e.content_hash == entry.content_hash and e.url != entry.url
                    for e in self._entries.values()
                )
                if not hash_in_use and full.exists():
                    full.unlink()
            total -= entry.size_bytes
            del self._entries[entry.url]
            logger.debug("Evicted cache entry for %s", entry.url)

    # ── stats ────────────────────────────────────────────────────

    def stats(self) -> dict:
        """Return cache statistics."""
        self.load()
        total_size = sum(e.size_bytes for e in self._entries.values())
        return {
            "entry_count": len(self._entries),
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "ttl_seconds": self.ttl_seconds,
            "max_size_mb": self.max_size_bytes // (1024 * 1024),
        }

    def clear(self) -> None:
        """Remove all cache entries and content files."""
        self._entries = {}
        idx = self._index_path()
        if idx.exists():
            idx.unlink()
        content_dir = self._content_dir()
        if content_dir.exists():
            for f in content_dir.glob("*.txt"):
                f.unlink()
        logger.info("Cache cleared")
