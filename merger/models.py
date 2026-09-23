"""V5 Data models for AdGuard DNS filter rules.

V5 improvements over V4:
  - Category priority on merge (malware > phishing > mining > tracking > ads > other).
  - Pre-computed integer sort key (faster sorting of multi-million rule sets).
  - Source URL -> integer ID mapping to cut per-rule tuple memory.
  - ``__slots__`` + ``sys.intern`` retained from V4.
  - Dedup key is ``(normalized_domain, rule_type, wildcard)`` explicitly.
"""

from __future__ import annotations

import sys
from functools import total_ordering
from typing import Optional


# ── categories ─────────────────────────────────────────────────────
CATEGORY_ADS = "ads"
CATEGORY_MALWARE = "malware"
CATEGORY_TRACKING = "tracking"
CATEGORY_PHISHING = "phishing"
CATEGORY_MINING = "mining"
CATEGORY_OTHER = "other"
CATEGORY_COMMENT = "comment"

ALL_CATEGORIES = frozenset({
    CATEGORY_ADS, CATEGORY_MALWARE, CATEGORY_TRACKING,
    CATEGORY_PHISHING, CATEGORY_MINING, CATEGORY_OTHER, CATEGORY_COMMENT,
})

TIERED_CATEGORIES = (
    CATEGORY_ADS, CATEGORY_MALWARE, CATEGORY_TRACKING,
    CATEGORY_PHISHING, CATEGORY_MINING, CATEGORY_OTHER,
)

# When the same domain appears in sources with different categories, the
# category with the *lower* number wins (security categories outrank ads).
CATEGORY_PRIORITY = {
    CATEGORY_MALWARE: 0,
    CATEGORY_PHISHING: 1,
    CATEGORY_MINING: 2,
    CATEGORY_TRACKING: 3,
    CATEGORY_ADS: 4,
    CATEGORY_OTHER: 99,
}


def merge_category(existing: str, incoming: str) -> str:
    """Return the higher-priority category (security beats ads)."""
    if existing == incoming:
        return existing
    return existing if CATEGORY_PRIORITY.get(existing, 99) <= CATEGORY_PRIORITY.get(incoming, 99) else incoming


def normalize_domain(domain: str, strip_www: bool = False) -> str:
    """Lowercase, strip ``*.`` prefix, strip trailing/leading dot, optionally strip www.

    Lowercasing and trailing-dot removal are *always* applied (they are not
    configurable in V5 — the V4 config knobs were dead).  ``strip_www`` is the
    only optional normalization.
    """
    d = domain.lower().strip()
    if d.startswith("*."):
        d = d[2:]
    if d.endswith("."):
        d = d[:-1]
    if d.startswith("."):
        d = d[1:]
    if strip_www and d.startswith("www."):
        d = d[4:]
    return d


# ── sort helpers ────────────────────────────────────────────────────
_TYPE_ORDER = {"block": 0, "allow": 1, "comment": 2}


@total_ordering
class Rule:
    """A single DNS-layer filter rule with provenance.

    Stored slots: ``raw``, ``rule_type``, ``wildcard``, ``modifiers``,
    ``source_ids``, ``category``, ``_norm``, ``_sort_type``.

    ``modifiers`` holds the part after ``$`` (e.g. ``important``,
    ``badfilter``) normalised to lowercase with spaces removed.  It is part
    of the dedup key because ``||x.com^`` and ``||x.com^$important`` have
    different semantics and must NOT be merged.
    """

    __slots__ = ("raw", "rule_type", "wildcard", "modifiers",
                 "source_ids", "category", "_norm", "_sort_type")

    def __init__(
        self,
        raw: str,
        domain: str,
        rule_type: str,
        wildcard: bool,
        sources=None,
        source_ids=None,
        category: str = CATEGORY_OTHER,
        strip_www: bool = False,
        modifiers: str = "",
    ) -> None:
        self.raw = raw
        self.rule_type = rule_type
        self.wildcard = bool(wildcard)
        self.modifiers = modifiers.strip().lower() if modifiers else ""
        # V5: prefer integer source IDs; fall back to URL tuple for compatibility
        if source_ids is not None:
            self.source_ids = tuple(source_ids) if not isinstance(source_ids, tuple) else source_ids
        elif sources is not None:
            if isinstance(sources, str):
                self.source_ids = (sources,)
            else:
                self.source_ids = tuple(sources)
        else:
            self.source_ids = ()
        self.category = category
        self._norm = sys.intern(normalize_domain(domain, strip_www=strip_www))
        self._sort_type = _TYPE_ORDER.get(rule_type, 9)

    # ── backwards-compatible accessors ────────────────────────────

    @property
    def sources(self):
        """Alias for source_ids (may hold URLs during parsing or IDs later)."""
        return self.source_ids

    @sources.setter
    def sources(self, value):
        self.source_ids = tuple(value) if not isinstance(value, tuple) else value

    # ── properties ────────────────────────────────────────────────

    @property
    def domain(self) -> str:
        return f"*.{self._norm}" if self.wildcard else self._norm

    @property
    def normalized_domain(self) -> str:
        return self._norm

    @property
    def is_regex(self) -> bool:
        return self._norm == "" and self.raw.startswith("/") or (
            self._norm == "" and self.raw.startswith("@@/")
        )

    @property
    def output_raw(self) -> str:
        """Canonical AdGuard line for output (preserves $ modifiers)."""
        if self.rule_type == "comment":
            return self.raw
        if self._norm == "":
            return self.raw  # regex rules keep original form
        prefix = "@@||" if self.rule_type == "allow" else "||"
        suffix = f"${self.modifiers}" if self.modifiers else ""
        return f"{prefix}{self.domain}^{suffix}"

    # ── equality / hashing (explicit 4-tuple key incl. modifiers) ──

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Rule):
            return NotImplemented
        return (self._norm == other._norm
                and self.rule_type == other.rule_type
                and self.wildcard == other.wildcard
                and self.modifiers == other.modifiers)

    def __hash__(self) -> int:
        return hash((self._norm, self.rule_type, self.wildcard, self.modifiers))

    # ── total ordering (pre-computed integer key) ─────────────────

    def __lt__(self, other: "Rule") -> bool:
        if not isinstance(other, Rule):
            return NotImplemented
        if self._sort_type != other._sort_type:
            return self._sort_type < other._sort_type
        if self._norm != other._norm:
            return self._norm < other._norm
        if self.wildcard != other.wildcard:
            return self.wildcard and not other.wildcard
        if self.modifiers != other.modifiers:
            # no-modifier rules sort before modified ones
            return (self.modifiers or "") < (other.modifiers or "")
        return False

    def __str__(self) -> str:
        return self.output_raw

    def __repr__(self) -> str:
        return f"Rule({self.rule_type} {self.domain!r} cat={self.category})"


class SourceMeta:
    """Metadata for a rule source."""

    __slots__ = ("name", "url", "category", "enabled", "reputation", "timeout", "id")

    def __init__(
        self,
        name: str,
        url: str,
        category: str = CATEGORY_OTHER,
        enabled: bool = True,
        reputation: float = 0.5,
        timeout: Optional[int] = None,
        id: Optional[int] = None,
    ) -> None:
        self.name = name
        self.url = url
        self.category = category
        self.enabled = enabled
        self.reputation = max(0.0, min(1.0, reputation))
        self.timeout = timeout
        self.id = id
