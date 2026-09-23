"""AdGuard Rules Merger V5 — DNS-layer rule compiler.

Pipeline: multi-source fetch -> parse -> dedup (exact/normalized/regex)
-> upward aggregation (exact + wildcard children + optional promotion)
-> whitelist split -> conflict resolution -> stable sort
-> multi-format export + tiered files + HTML report.
"""

from .cache import SourceCache, CacheEntry
from .core import AsyncRuleEngine, MergeOutcome
from .exporter import Exporter
from .models import (
    Rule, SourceMeta,
    CATEGORY_ADS, CATEGORY_MALWARE, CATEGORY_TRACKING,
    CATEGORY_PHISHING, CATEGORY_MINING, CATEGORY_OTHER, CATEGORY_COMMENT,
    merge_category,
)
from .parser import RuleParser

__version__ = "5.0.0"
__all__ = [
    "AsyncRuleEngine", "MergeOutcome", "Exporter",
    "Rule", "SourceMeta", "RuleParser", "SourceCache", "CacheEntry",
    "CATEGORY_ADS", "CATEGORY_MALWARE", "CATEGORY_TRACKING",
    "CATEGORY_PHISHING", "CATEGORY_MINING", "CATEGORY_OTHER", "CATEGORY_COMMENT",
    "merge_category",
    "__version__",
]
