"""V5 async rule engine — fetch, parse, dedup, aggregate, resolve conflicts.

Pipeline:
  1. Concurrent fetch + streaming parse (aiohttp, ETag/SHA256 cache).
  2. Dedup by key (normalized_domain, rule_type, wildcard); three counters:
       exact_merged       — identical raw rule seen again
       normalized_merged  — different raw, same normalized key (e.g. www strip)
       regex_merged       — identical regex seen again
  3. Upward aggregation:
       a. exact child  ||sub.x.com^  under ||*.x.com^ or ||x.com^   (V4 behavior)
       b. wildcard child ||*.sub.x.com^ under ||*.x.com^ or ||x.com^ (V5 new)
       c. optional wildcard promotion: N exact siblings -> ||*.parent^ (V5 new)
  4. Whitelist split + conflict resolution (allow overrides block; cascade
     is now genuinely controlled by the cascade_subdomains config flag).
  5. Category merge with security-first priority.
  6. Stable sort, per-source contribution stats, optional diff vs last run.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import aiohttp

from .cache import SourceCache
from .models import (
    Rule, SourceMeta, merge_category,
)
from .parser import RuleParser

logger = logging.getLogger(__name__)

_MIN_AGGREGATOR_LABELS = 2


def _parent_labels(norm: str) -> List[str]:
    """Strict parent domains, most-specific first."""
    parts = norm.split(".")
    return [".".join(parts[i:]) for i in range(1, len(parts))]


@dataclass
class SourceFailure:
    url: str
    name: str
    error: str


@dataclass
class SourceContribution:
    name: str
    url: str
    category: str
    raw_rules: int = 0
    unique_rules: int = 0       # rules this source contributes that no other source has
    shared_rules: int = 0       # rules also present in at least one other source


@dataclass
class MergeOutcome:
    blocks: List[Rule] = field(default_factory=list)
    allows: List[Rule] = field(default_factory=list)
    regex_blocks: List[Rule] = field(default_factory=list)
    regex_allows: List[Rule] = field(default_factory=list)
    raw_count: int = 0
    sources_ok: int = 0
    sources_total: int = 0
    sources_cached: int = 0
    # dedup counters
    exact_merged: int = 0
    normalized_merged: int = 0
    regex_merged: int = 0
    # aggregation counters
    aggregated: int = 0            # exact children folded into parents
    wildcard_aggregated: int = 0   # wildcard children folded into parent wildcards (V5)
    wildcard_promoted: int = 0     # N exact siblings promoted to one wildcard (V5)
    # conflict counters
    conflict_resolved: int = 0
    whitelist_blocked: int = 0
    # drop counters
    pattern_dropped: int = 0
    quality_dropped: int = 0
    css_dropped: int = 0
    badfilter_removed: int = 0       # V5: $badfilter rules + targets cancelled
    # diagnostics
    conflicts: List[Dict[str, Any]] = field(default_factory=list)
    failed_sources: List[Dict[str, str]] = field(default_factory=list)
    contributions: List[Dict[str, Any]] = field(default_factory=list)
    source_overlap: Dict[str, Any] = field(default_factory=dict)   # V5: pairwise source overlap matrix
    modifier_stats: Dict[str, int] = field(default_factory=dict)   # V5: $ modifier distribution
    whitelist_audit: Dict[str, Any] = field(default_factory=dict)  # V5: threat-intel audit of allows
    added: List[str] = field(default_factory=list)
    removed: List[str] = field(default_factory=list)
    elapsed: float = 0.0


class AsyncRuleEngine:
    """Fetch + merge AdGuard DNS rules (async)."""

    def __init__(
        self,
        timeout: int = 60,
        max_concurrency: int = 50,
        cache_dir: Optional[str] = None,
        cache_ttl: int = 0,
        cache_max_size_mb: int = 0,
        strip_www: bool = False,
        quality_filter_enabled: bool = True,
        min_domain_length: int = 4,
        max_domain_length: int = 253,
        filter_localhost: bool = True,
        filter_ip_rules: bool = False,
        aggregation_enabled: bool = True,
        min_aggregator_labels: int = 2,
        wildcard_child_aggregation: bool = True,
        wildcard_promotion_threshold: int = 0,
        conflict_resolution_enabled: bool = True,
        cascade_subdomains: bool = True,
        whitelist_audit_enabled: bool = False,
        whitelist_audit_concurrency: int = 10,
        whitelist_audit_use_dns: bool = True,
        whitelist_audit_use_urlhaus: bool = True,
        whitelist_audit_use_threatfox: bool = True,
        whitelist_audit_use_rdap: bool = True,
        whitelist_audit_use_scam_check: bool = True,
        whitelist_audit_use_virustotal: bool = False,
        whitelist_audit_vt_api_key: str = "",
        whitelist_audit_use_ai: bool = False,
        whitelist_audit_ai_api_key: str = "",
        whitelist_audit_ai_base_url: str = "https://api.openai.com/v1",
        whitelist_audit_ai_model: str = "gpt-4o-mini",
        whitelist_audit_ai_min_confidence: float = 0.6,
        whitelist_audit_new_domain_days: int = 30,
        whitelist_audit_urlhaus_delay: float = 1.0,
        fail_threshold: float = 0.5,
        diff_against: Optional[str] = None,
        user_agent: str = "AdGuard-Rules-Merger/5.0",
        retry_count: int = 2,
        retry_delay: float = 1.5,
    ) -> None:
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        self.strip_www = strip_www
        self.aggregation_enabled = aggregation_enabled
        self.conflict_resolution_enabled = conflict_resolution_enabled
        self.cascade_subdomains = cascade_subdomains  # V5: now actually used
        self.whitelist_audit_enabled = whitelist_audit_enabled
        self.whitelist_audit_concurrency = whitelist_audit_concurrency
        self.whitelist_audit_use_dns = whitelist_audit_use_dns
        self.whitelist_audit_use_urlhaus = whitelist_audit_use_urlhaus
        self.whitelist_audit_use_threatfox = whitelist_audit_use_threatfox
        self.whitelist_audit_use_rdap = whitelist_audit_use_rdap
        self.whitelist_audit_use_scam_check = whitelist_audit_use_scam_check
        self.whitelist_audit_use_virustotal = whitelist_audit_use_virustotal
        self.whitelist_audit_vt_api_key = whitelist_audit_vt_api_key
        self.whitelist_audit_use_ai = whitelist_audit_use_ai
        self.whitelist_audit_ai_api_key = whitelist_audit_ai_api_key
        self.whitelist_audit_ai_base_url = whitelist_audit_ai_base_url
        self.whitelist_audit_ai_model = whitelist_audit_ai_model
        self.whitelist_audit_ai_min_confidence = whitelist_audit_ai_min_confidence
        self.whitelist_audit_new_domain_days = whitelist_audit_new_domain_days
        self.whitelist_audit_urlhaus_delay = whitelist_audit_urlhaus_delay
        self.min_aggregator_labels = min_aggregator_labels
        self.wildcard_child_aggregation = wildcard_child_aggregation
        self.wildcard_promotion_threshold = wildcard_promotion_threshold
        self.fail_threshold = fail_threshold
        self.diff_against = diff_against
        self.user_agent = user_agent
        self.retry_count = retry_count
        self.retry_delay = retry_delay
        self.parser = RuleParser(
            strip_www=strip_www,
            quality_filter=quality_filter_enabled,
            min_domain_length=min_domain_length,
            max_domain_length=max_domain_length,
            filter_localhost=filter_localhost,
            filter_ip_rules=filter_ip_rules,
        )
        self.cache: Optional[SourceCache] = None
        if cache_dir is not None:
            self.cache = SourceCache(cache_dir=cache_dir, ttl_seconds=cache_ttl,
                                     max_size_mb=cache_max_size_mb)
            self.cache.load()
        self._session: Optional[aiohttp.ClientSession] = None

    # ── async context ───────────────────────────────────────────

    async def __aenter__(self) -> "AsyncRuleEngine":
        await self._ensure_session()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def _ensure_session(self) -> None:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(
                total=self.timeout, sock_connect=30, sock_read=self.timeout)
            connector = aiohttp.TCPConnector(limit=self.max_concurrency,
                                             ttl_dns_cache=300,
                                             force_close=False)
            self._session = aiohttp.ClientSession(
                timeout=timeout, connector=connector,
                headers={"User-Agent": self.user_agent},
            )

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
        if self.cache:
            self.cache.save()

    # ── fetch ────────────────────────────────────────────────────

    async def _fetch_text(self, source: str, retries: int = 2
                          ) -> Tuple[str, bool, Optional[str]]:
        """Return (text, from_cache, error)."""
        p = Path(source)
        if p.exists() and p.is_file():
            return p.read_text(encoding="utf-8", errors="replace"), False, None

        cond_headers: Dict[str, str] = {}
        if self.cache:
            cond_headers = self.cache.conditional_headers(source)

        await self._ensure_session()
        assert self._session is not None
        last_exc: Optional[Exception] = None
        for attempt in range(retries + 1):
            try:
                async with self._session.get(source, headers=cond_headers) as resp:
                    if resp.status == 404:
                        return "", False, f"HTTP 404 Not Found: {source}"
                    if resp.status == 304 and self.cache:
                        cached = self.cache.get_content(source)
                        if cached is not None:
                            self.cache.store_not_modified(source)
                            return cached, True, None
                    resp.raise_for_status()
                    text = await resp.text(encoding="utf-8", errors="replace")
                    if self.cache:
                        changed = self.cache.content_changed(source, text)
                        self.cache.store(
                            url=source, content=text,
                            etag=resp.headers.get("ETag"),
                            last_modified=resp.headers.get("Last-Modified"),
                        )
                        # V5: persist index incrementally so a killed/interrupted
                        # run keeps every source already fetched.
                        self.cache.save()
                        if not changed:
                            return text, True, None
                    return text, False, None
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
                last_exc = e
                if attempt < retries:
                    await asyncio.sleep(self.retry_delay * (attempt + 1))
                    continue
        # retries exhausted — try stale cache as fallback
        if self.cache:
            cached = self.cache.get_content(source)
            if cached is not None:
                logger.warning("fetch %s failed (%s); using stale cache", source, last_exc)
                return cached, True, None
        return "", False, f"{type(last_exc).__name__}: {last_exc}" if last_exc else "unknown error"

    async def _fetch_one(self, meta: SourceMeta
                         ) -> Tuple[List[Rule], bool, bool, int, Optional[str]]:
        """Return (rules, success, from_cache, raw_line_count, error)."""
        t0 = time.time()
        text, from_cache, err = await self._fetch_text(meta.url, retries=self.retry_count)
        if err:
            logger.warning("source failed %s: %s", meta.url, err)
            return [], False, False, 0, err
        rules = self.parser.parse_text(text, source=meta.url, category=meta.category)
        logger.info("parsed %6d rules from %-40s (%s, %.2fs)",
                    len(rules), meta.url.split("/")[-1],
                    "cache" if from_cache else "net", time.time() - t0)
        return rules, True, from_cache, len(rules), None

    async def fetch_all(self, sources: List[SourceMeta]):
        sem = asyncio.Semaphore(self.max_concurrency)
        block_map: Dict[Tuple[str, bool], Rule] = {}
        allow_map: Dict[Tuple[str, bool], Rule] = {}
        regex_blocks: Dict[str, Rule] = {}
        regex_allows: Dict[str, Rule] = {}
        raw_count = ok = cached = 0
        exact_merged = normalized_merged = regex_merged = 0
        failures: List[SourceFailure] = []
        # per-source raw counts for contribution stats
        source_raw_counts: Dict[str, int] = {}
        source_names: Dict[str, str] = {}

        async def bounded(meta: SourceMeta):
            async with sem:
                return meta, await self._fetch_one(meta)

        for fut in asyncio.as_completed([bounded(s) for s in sources]):
            meta, (rules, success, from_cache, n, err) = await fut
            source_names[meta.url] = meta.name
            if not success:
                failures.append(SourceFailure(url=meta.url, name=meta.name, error=err or "unknown"))
                continue
            ok += 1
            raw_count += n
            source_raw_counts[meta.url] = n
            if from_cache:
                cached += 1

            for r in rules:
                if r.rule_type == "comment":
                    continue
                # regex rules dedup by normalized raw string
                if r.normalized_domain == "":
                    m = regex_blocks if r.rule_type == "block" else regex_allows
                    key = r.raw
                    if key not in m:
                        m[key] = r
                    else:
                        existing = m[key]
                        existing.source_ids = tuple(sorted(set(existing.source_ids) | set(r.source_ids)))
                        existing.category = merge_category(existing.category, r.category)
                        regex_merged += 1
                    continue
                m = block_map if r.rule_type == "block" else allow_map
                # V5: modifiers are part of the identity — ||x.com^ and
                # ||x.com^$important are different rules and must not merge.
                key = (r.normalized_domain, r.wildcard, r.modifiers)
                existing = m.get(key)
                if existing is None:
                    m[key] = r
                else:
                    # V5: distinguish exact vs normalized merges
                    if existing.raw and r.raw and existing.raw != r.raw:
                        normalized_merged += 1
                    else:
                        exact_merged += 1
                    existing.source_ids = tuple(sorted(set(existing.source_ids) | set(r.source_ids)))
                    existing.category = merge_category(existing.category, r.category)
            del rules

        return (block_map, allow_map,
                list(regex_blocks.values()), list(regex_allows.values()),
                raw_count, ok, cached,
                exact_merged, normalized_merged, regex_merged,
                failures, source_raw_counts, source_names)

    # ── badfilter cancellation ───────────────────────────────────

    def _apply_badfilter(self, block_map: Dict, allow_map: Dict) -> int:
        """Cancel $badfilter rules and their targets.

        A $badfilter rule negates the rule with the same domain/wildcard but
        without the badfilter modifier. Both the badfilter rule and its
        target are removed from output.

        Returns the number of rules removed (badfilter + targets).
        """
        def _modset(mods: str) -> set:
            return {m.strip() for m in mods.split(",") if m.strip()}

        removed = 0
        for m in (block_map, allow_map):
            bad_keys = [k for k, r in m.items()
                        if r.modifiers and "badfilter" in _modset(r.modifiers)]
            for bk in bad_keys:
                bf = m.pop(bk)  # badfilter itself is not output
                removed += 1
                # Target key: same domain/wildcard, modifiers minus badfilter
                remaining = sorted(_modset(bf.modifiers) - {"badfilter"})
                tgt_mods = ",".join(remaining)
                tgt_key = (bf.normalized_domain, bf.wildcard, tgt_mods)
                if tgt_key in m:
                    m.pop(tgt_key)
                    removed += 1
        return removed

    # ── upward aggregation ──────────────────────────────────────

    def _aggregate(self, block_map: Dict[Tuple[str, bool], Rule]
                   ) -> Tuple[List[Rule], int, int, int]:
        """Aggregate child rules under surviving parents.

        Returns (survivors, exact_aggregated, wildcard_aggregated, promoted).
        """
        wild_map: Dict[str, Rule] = {}
        exact_map: Dict[str, Rule] = {}
        for r in block_map.values():
            # Rules with $ modifiers (important, badfilter, ...) have special
            # semantics and must NOT be folded into a parent rule.
            if r.modifiers:
                continue
            if r.wildcard:
                wild_map[r.normalized_domain] = r
            else:
                exact_map[r.normalized_domain] = r

        min_labels = self.min_aggregator_labels
        removed: Set[int] = set()  # use id() for fast membership
        exact_agg = 0
        wild_agg = 0
        promoted = 0

        # ── V5 optional: wildcard promotion (N exact siblings -> *.parent) ──
        if self.wildcard_promotion_threshold > 0:
            # group exact rules by their immediate parent
            sibling_groups: Dict[str, List[str]] = {}
            for norm in exact_map:
                parts = norm.split(".")
                if len(parts) >= min_labels + 1:
                    parent = ".".join(parts[1:])
                    sibling_groups.setdefault(parent, []).append(norm)
            for parent, children in sibling_groups.items():
                if parent.count(".") + 1 < min_labels:
                    continue
                # If a wildcard (or exact) parent already exists, these children
                # are folded by the regular exact-child pass below — don't double
                # count them as promotions.
                if parent in wild_map or parent in exact_map:
                    continue
                if len(children) >= self.wildcard_promotion_threshold:
                    # create a new wildcard rule for parent
                    template = exact_map[children[0]]
                    wc = Rule(raw=f"||*.{parent}^", domain=parent, rule_type="block",
                              wildcard=True, sources=template.source_ids,
                              category=template.category)
                    wild_map[parent] = wc
                    block_map[(parent, True)] = wc
                    keeper = wc
                    for child_norm in children:
                        child = exact_map.get(child_norm)
                        if child is not None and id(child) not in removed:
                            keeper.source_ids = tuple(sorted(set(keeper.source_ids) | set(child.source_ids)))
                            keeper.category = merge_category(keeper.category, child.category)
                            removed.add(id(child))
                            promoted += 1

        # ── exact children under surviving parents (V4 behavior) ──
        exact_children = sorted(
            (r for r in block_map.values()
             if not r.wildcard and not r.modifiers and id(r) not in removed),
            key=lambda r: (-r.normalized_domain.count(".") - 1, r.normalized_domain),
        )
        for child in exact_children:
            for parent in _parent_labels(child.normalized_domain):
                if parent.count(".") + 1 < min_labels:
                    continue
                keeper = wild_map.get(parent) or exact_map.get(parent)
                if keeper is not None and id(keeper) != id(child):
                    keeper.source_ids = tuple(sorted(set(keeper.source_ids) | set(child.source_ids)))
                    keeper.category = merge_category(keeper.category, child.category)
                    removed.add(id(child))
                    exact_agg += 1
                    break

        # ── V5 new: wildcard children under wildcard/exact parents ──
        if self.wildcard_child_aggregation:
            wild_children = sorted(
                (r for r in block_map.values()
                 if r.wildcard and not r.modifiers and id(r) not in removed),
                key=lambda r: (-r.normalized_domain.count(".") - 1, r.normalized_domain),
            )
            for child in wild_children:
                child_norm = child.normalized_domain
                # Same-domain exact rule strictly covers the wildcard:
                # ||x.com^ matches x.com + all subdomains; ||*.x.com^ only subs.
                same_exact = exact_map.get(child_norm)
                if same_exact is not None and id(same_exact) not in removed:
                    same_exact.source_ids = tuple(
                        sorted(set(same_exact.source_ids) | set(child.source_ids)))
                    same_exact.category = merge_category(same_exact.category, child.category)
                    removed.add(id(child))
                    wild_agg += 1
                    continue
                for parent in _parent_labels(child_norm):
                    if parent.count(".") + 1 < min_labels:
                        continue
                    # ||*.sub.x.com^ is covered by ||*.x.com^ OR ||x.com^
                    keeper = wild_map.get(parent) or exact_map.get(parent)
                    if keeper is not None and id(keeper) != id(child):
                        keeper.source_ids = tuple(sorted(set(keeper.source_ids) | set(child.source_ids)))
                        keeper.category = merge_category(keeper.category, child.category)
                        removed.add(id(child))
                        wild_agg += 1
                        break

        survivors = [r for r in block_map.values() if id(r) not in removed]
        return survivors, exact_agg, wild_agg, promoted

    # ── conflict resolution ─────────────────────────────────────

    def _resolve_conflicts(
        self,
        blocks: List[Rule],
        allows: List[Rule],
        source_names: Optional[Dict[str, str]] = None,
    ) -> Tuple[List[Rule], int, List[Dict[str, Any]]]:
        source_names = source_names or {}

        def _src_names(rule: Rule) -> List[str]:
            return [source_names.get(s, s) for s in rule.source_ids]

        exact_allow: Dict[str, Rule] = {}
        wild_allow: Dict[str, Rule] = {}    # @@||*.x^: covers strict subdomains, not root
        suffix_allow: Dict[str, Rule] = {}  # cascade=True: exact allow cascades to subdomains
        for a in allows:
            n = a.normalized_domain
            if not n:
                continue  # regex allows don't participate
            if a.wildcard:
                wild_allow[n] = a
            else:
                exact_allow[n] = a
            if self.cascade_subdomains:
                suffix_allow[n] = a

        removed: Set[int] = set()
        conflicts: List[Dict[str, Any]] = []

        for b in blocks:
            n = b.normalized_domain
            if not n:
                continue  # regex blocks skip conflict resolution
            if b.modifiers and "important" in {m.strip() for m in b.modifiers.split(",")}:
                continue  # $important rules outrank whitelists at AGH runtime
            by = None
            conflict_type = "exact"
            if n in exact_allow:
                by = exact_allow[n]
            else:
                parts = n.split(".")
                for i in range(1, len(parts)):
                    parent = ".".join(parts[i:])
                    # Wildcard allow ALWAYS covers strict subdomains,
                    # even when cascade_subdomains=False.
                    if parent in wild_allow:
                        by = wild_allow[parent]
                        conflict_type = "wildcard"
                        break
                    # Cascade: exact allow covers subdomains only when enabled.
                    if self.cascade_subdomains and parent in suffix_allow:
                        by = suffix_allow[parent]
                        conflict_type = "cascade"
                        break
            if by is not None:
                removed.add(id(b))
                conflicts.append({
                    "domain": n,
                    "blocked_rule": b.output_raw,
                    "blocked_category": b.category,
                    "blocked_sources": _src_names(b),
                    "whitelist_rule": by.output_raw,
                    "whitelist_sources": _src_names(by),
                    "conflict_type": conflict_type,
                })

        survivors = [b for b in blocks if id(b) not in removed]
        return survivors, len(removed), conflicts

    # ── per-source contribution stats ───────────────────────────

    @staticmethod
    def _compute_contributions(
        blocks: List[Rule], allows: List[Rule],
        source_names: Dict[str, str], source_raw_counts: Dict[str, int],
    ) -> List[Dict[str, Any]]:
        # count how many sources cover each domain
        coverage: Dict[str, int] = {}
        for r in blocks + allows:
            if r.normalized_domain:
                coverage[r.normalized_domain] = len(r.source_ids)

        # unique/shared per source
        unique_count: Dict[str, int] = {}
        shared_count: Dict[str, int] = {}
        for r in blocks + allows:
            if not r.normalized_domain:
                continue
            for src in r.source_ids:
                if coverage.get(r.normalized_domain, 1) == 1:
                    unique_count[src] = unique_count.get(src, 0) + 1
                else:
                    shared_count[src] = shared_count.get(src, 0) + 1

        contributions = []
        for url, name in source_names.items():
            contributions.append({
                "name": name,
                "url": url,
                "raw_rules": source_raw_counts.get(url, 0),
                "unique_rules": unique_count.get(url, 0),
                "shared_rules": shared_count.get(url, 0),
            })
        contributions.sort(key=lambda c: -c["unique_rules"])
        return contributions

    # ── V5: pairwise source overlap matrix ──────────────────────

    @staticmethod
    def _compute_source_overlap(
        blocks: List[Rule], allows: List[Rule],
        source_names: Dict[str, str],
    ) -> Dict[str, Any]:
        """Compute pairwise rule overlap between every two sources.

        For each final rule, its source_ids tells which sources contributed it.
        Every pair of sources that share a rule increments their overlap count.
        Also computes each source's effective rule count (rules it covers after
        dedup) so overlap rates are meaningful.
        """
        from collections import Counter
        effective: Counter = Counter()
        pair_overlap: Counter = Counter()

        for r in blocks + allows:
            if not r.normalized_domain:
                continue
            srcs = r.source_ids
            if not srcs:
                continue
            for s in srcs:
                effective[s] += 1
            # pairwise combinations (C(n,2))
            n = len(srcs)
            for i in range(n):
                for j in range(i + 1, n):
                    pair_overlap[frozenset({srcs[i], srcs[j]})] += 1

        pairs = []
        for pair, count in pair_overlap.most_common():
            src_list = sorted(pair)
            a, b = src_list[0], src_list[1]
            ea, eb = effective[a], effective[b]
            pairs.append({
                "source_a": source_names.get(a, a),
                "source_b": source_names.get(b, b),
                "overlap": count,
                "rate_a": round(count / ea * 100, 1) if ea else 0.0,
                "rate_b": round(count / eb * 100, 1) if eb else 0.0,
            })

        source_effective = {
            source_names.get(k, k): v for k, v in effective.most_common()
        }
        return {"pairs": pairs, "source_effective": source_effective}

    # ── V5: $ modifier distribution ─────────────────────────────

    @staticmethod
    def _compute_modifier_stats(blocks: List[Rule], allows: List[Rule]) -> Dict[str, int]:
        """Count rules carrying each $ modifier (important, badfilter, ...)."""
        from collections import Counter
        c: Counter = Counter()
        for r in blocks + allows:
            if r.modifiers:
                # modifiers may be comma-separated: "important,third-party"
                for m in r.modifiers.split(","):
                    m = m.strip()
                    if m:
                        c[m] += 1
        return dict(c.most_common())

    # ── diff vs last run ────────────────────────────────────────

    @staticmethod
    def _load_previous_domains(path: str) -> Set[str]:
        p = Path(path)
        if not p.exists():
            return set()
        try:
            return {
                line.strip() for line in p.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.strip().startswith("#") and not line.strip().startswith("!")
            }
        except OSError:
            return set()

    # ── high-level run ──────────────────────────────────────────

    async def run(self, sources: List[SourceMeta]) -> MergeOutcome:
        sources = [s for s in sources if s.enabled]
        if not sources:
            raise ValueError("No enabled sources")

        t0 = time.time()
        (block_map, allow_map,
         regex_blocks, regex_allows,
         raw_count, ok, cached,
         exact_merged, normalized_merged, regex_merged,
         failures, source_raw_counts, source_names) = await self.fetch_all(sources)

        # fail-fast threshold
        total = len(sources)
        if ok == 0:
            raise RuntimeError("All sources failed to download")
        fail_rate = len(failures) / total
        if fail_rate > self.fail_threshold:
            raise RuntimeError(
                f"Source failure rate {fail_rate:.0%} exceeds threshold "
                f"{self.fail_threshold:.0%}: {[f.name for f in failures]}")

        logger.info("raw rules: %d from %d/%d sources (%d cached); "
                    "block_keys=%d allow_keys=%d regex=%d",
                    raw_count, ok, total, cached,
                    len(block_map), len(allow_map),
                    len(regex_blocks) + len(regex_allows))

        # free raw strings on domain rules (regex rules keep raw for output)
        for r in list(block_map.values()) + list(allow_map.values()):
            r.raw = ""

        # $badfilter cancellation: remove badfilter rules and their targets
        badfilter_removed = self._apply_badfilter(block_map, allow_map)
        if badfilter_removed:
            logger.info("badfilter cancellation: removed %d rules", badfilter_removed)

        # aggregation
        aggregated_n = wild_agg_n = promoted_n = 0
        if self.aggregation_enabled:
            aggregated_blocks, aggregated_n, wild_agg_n, promoted_n = self._aggregate(block_map)
            logger.info("aggregation: exact=%d wildcard=%d promoted=%d",
                        aggregated_n, wild_agg_n, promoted_n)
        else:
            aggregated_blocks = list(block_map.values())

        # conflict resolution
        if self.conflict_resolution_enabled:
            final_blocks, removed_n, conflicts = self._resolve_conflicts(
                aggregated_blocks, list(allow_map.values()), source_names)
        else:
            final_blocks, removed_n, conflicts = aggregated_blocks, 0, []

        # stable sort
        final_blocks.sort()
        final_allows = sorted(allow_map.values())
        final_blocks = sorted(final_blocks + regex_blocks)
        final_allows = sorted(final_allows + regex_allows)

        # per-source contributions
        contributions = self._compute_contributions(
            final_blocks, final_allows, source_names, source_raw_counts)

        # V5: pairwise source overlap matrix
        source_overlap = self._compute_source_overlap(
            final_blocks, final_allows, source_names)

        # V5: $ modifier distribution
        modifier_stats = self._compute_modifier_stats(final_blocks, final_allows)

        # V5: optional whitelist multi-layer audit
        whitelist_audit: Dict[str, Any] = {}
        if self.whitelist_audit_enabled:
            from .whitelist_audit import audit_whitelist, AuditConfig
            logger.info("running whitelist multi-layer audit...")
            audit_cfg = AuditConfig(
                use_dns=self.whitelist_audit_use_dns,
                use_urlhaus=self.whitelist_audit_use_urlhaus,
                use_threatfox=self.whitelist_audit_use_threatfox,
                use_rdap=getattr(self, "whitelist_audit_use_rdap", True),
                use_scam_check=getattr(self, "whitelist_audit_use_scam_check", True),
                use_virustotal=getattr(self, "whitelist_audit_use_virustotal", False),
                virustotal_api_key=getattr(self, "whitelist_audit_vt_api_key", ""),
                use_ai=getattr(self, "whitelist_audit_use_ai", False),
                ai_api_key=getattr(self, "whitelist_audit_ai_api_key", ""),
                ai_base_url=getattr(self, "whitelist_audit_ai_base_url", "https://api.openai.com/v1"),
                ai_model=getattr(self, "whitelist_audit_ai_model", "gpt-4o-mini"),
                ai_min_confidence=getattr(self, "whitelist_audit_ai_min_confidence", 0.6),
                concurrency=self.whitelist_audit_concurrency,
                urlhaus_delay=self.whitelist_audit_urlhaus_delay,
                new_domain_threshold_days=getattr(self, "whitelist_audit_new_domain_days", 30),
            )
            whitelist_audit = await audit_whitelist(
                final_allows, source_names, config=audit_cfg,
            )
            s = whitelist_audit.get("summary", {})
            logger.info("whitelist audit: %s", s)

        # diff vs previous output
        added, removed = [], []
        if self.diff_against:
            new_domains = {b.normalized_domain for b in final_blocks if b.normalized_domain}
            old_domains = self._load_previous_domains(self.diff_against)
            added = sorted(new_domains - old_domains)
            removed = sorted(old_domains - new_domains)
            logger.info("diff: +%d -%d", len(added), len(removed))

        outcome = MergeOutcome(
            blocks=final_blocks,
            allows=final_allows,
            regex_blocks=regex_blocks,
            regex_allows=regex_allows,
            raw_count=raw_count,
            sources_ok=ok,
            sources_total=total,
            sources_cached=cached,
            exact_merged=exact_merged,
            normalized_merged=normalized_merged,
            regex_merged=regex_merged,
            aggregated=aggregated_n,
            wildcard_aggregated=wild_agg_n,
            wildcard_promoted=promoted_n,
            conflict_resolved=removed_n,
            whitelist_blocked=removed_n,
            pattern_dropped=self.parser.pattern_dropped,
            quality_dropped=self.parser.quality_dropped,
            css_dropped=self.parser.css_dropped,
            badfilter_removed=badfilter_removed,
            conflicts=conflicts,
            failed_sources=[{"name": f.name, "url": f.url, "error": f.error} for f in failures],
            contributions=contributions,
            source_overlap=source_overlap,
            modifier_stats=modifier_stats,
            whitelist_audit=whitelist_audit,
            added=added,
            removed=removed,
            elapsed=time.time() - t0,
        )
        return outcome

    def run_sync(self, sources: List[SourceMeta]) -> MergeOutcome:
        async def _go():
            async with self:
                return await self.run(sources)
        return asyncio.run(_go())
