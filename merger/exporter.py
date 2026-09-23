"""V5 streaming multi-format exporter.

Outputs:
  merged_rules.txt   AdGuard block rules (||domain^ + /regex/)
  whitelist.txt      AdGuard allow rules (@@||domain^)
  hosts.txt          0.0.0.0 domain
  domains.txt        one plain domain per line
  clash.yaml         DOMAIN-SUFFIX,domain
  surge.list         DOMAIN-SUFFIX,domain
  smartdns.conf      address /domain/#
  merged_ads.txt / merged_malware.txt / merged_tracking.txt /
  merged_phishing.txt / merged_mining.txt   tiered subsets by category
  stats.json         machine-readable optimisation report
  conflicts.json     block rules removed by whitelist overrides
  contributions.json per-source unique/shared rule counts
  added.txt / removed.txt  diff vs previous run (optional)
  report.html        interactive analysis dashboard
  report.md          Markdown analysis report (GitHub-friendly)
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

from .models import (
    Rule, CATEGORY_ADS, CATEGORY_MALWARE, CATEGORY_TRACKING,
    CATEGORY_PHISHING, CATEGORY_MINING, CATEGORY_OTHER, TIERED_CATEGORIES,
)
from .report import analyze_rules, generate_html_report, generate_markdown_report

HOMEPAGE = "https://github.com/kekai2020/adguard-rules-merger-v5"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _version_stamp(dt: datetime) -> str:
    return dt.strftime("%Y%m%d%H%M")


def _content_hash(blocks: List[Rule], allows: List[Rule]) -> str:
    """SHA-256 hash of all rule bodies (excluding headers).

    Used as the Version field so that unchanged rules produce a byte-identical
    merged_rules.txt — critical for CI "commit only when changed" logic.
    """
    import hashlib
    h = hashlib.sha256()
    for r in blocks + allows:
        h.update(r.output_raw.encode("utf-8", errors="replace"))
        h.update(b"\n")
    return h.hexdigest()[:12]


class Exporter:
    """Stream all output formats to disk."""

    def __init__(
        self,
        out_dir: str | Path,
        formats: List[str] | None = None,
        tiered: bool = True,
        report: bool = True,
        write_diff: bool = False,
        whitelist_output: Any = None,
    ) -> None:
        self.out = Path(out_dir)
        self.out.mkdir(parents=True, exist_ok=True)
        self.formats = formats or [
            "adguard", "whitelist", "hosts", "domains",
            "clash", "surge", "smartdns",
        ]
        self.tiered = tiered
        self.report = report
        self.write_diff_enabled = write_diff
        self.whitelist_output = whitelist_output

    # ── header helpers ────────────────────────────────────────────

    def _main_header(self, blocks: List[Rule], allows: List[Rule],
                     outcome: Any, cat_counts: Counter) -> List[str]:
        now = _now()
        src_ok = outcome.sources_ok
        src_tot = outcome.sources_total
        cached = outcome.sources_cached
        before = outcome.raw_count
        after = len(blocks) + len(allows)
        dedup_rate = (1 - after / before) * 100 if before else 0.0
        content_ver = _content_hash(blocks, allows)
        cats = " ".join(f"{k}={cat_counts.get(k, 0)}" for k in
                        ("ads", "malware", "tracking", "phishing", "mining", "other"))
        lines = [
            "! Title: Merged AdGuard Home Filter Rules (V5)",
            f"! Description: Auto-merged from {src_tot} sources (dedup + aggregation + conflict resolution)",
            f"! Version: {content_ver}",
            f"! Generated: {now.isoformat()}",
            f"! Homepage: {HOMEPAGE}",
            f"! Total block rules: {len(blocks)}",
            f"! Total whitelist rules: {len(allows)}",
            f"! Sources: {src_ok}/{src_tot} ({cached} cached)",
            f"! Dedup rate: {dedup_rate:.1f}%",
            f"! Exact dedup: {outcome.exact_merged} | Normalized dedup: {outcome.normalized_merged} | Regex dedup: {outcome.regex_merged}",
            f"! Aggregated: exact={outcome.aggregated} wildcard={outcome.wildcard_aggregated} promoted={outcome.wildcard_promoted}",
            f"! Conflicts resolved: {outcome.conflict_resolved}",
            f"! Dropped: pattern={outcome.pattern_dropped} quality={outcome.quality_dropped} css={outcome.css_dropped} badfilter={getattr(outcome, 'badfilter_removed', 0)}",
            f"! Categories: {cats}",
        ]
        if outcome.failed_sources:
            lines.append(f"! WARNING: {len(outcome.failed_sources)} source(s) failed:")
            for fs in outcome.failed_sources:
                lines.append(f"!   FAILED: {fs['name']} — {fs['error']}")
        lines.append("!")
        return lines

    def _whitelist_header(self, allows: List[Rule]) -> List[str]:
        now = _now()
        content_ver = _content_hash([], allows)
        return [
            "! Title: Whitelist for Merged Rules (V5)",
            "! Description: Allow rules separated from main filter",
            f"! Version: {content_ver}",
            f"! Generated: {now.isoformat()}",
            f"! Total allow rules: {len(allows)}",
            "!",
        ]

    # ── writers (all streaming) ─────────────────────────────────

    def _write_lines(self, path: Path, header: List[str],
                      body: Iterable[str]) -> None:
        with open(path, "w", encoding="utf-8", buffering=1024 * 64) as f:
            for line in header:
                f.write(line + "\n")
            for line in body:
                f.write(line + "\n")

    def _domain_rules(self, blocks: List[Rule]):
        """Yield only domain rules (skip regex AND skip modifier rules) for
        hosts/domains/clash/surge/smartdns formats.

        These plain-domain formats cannot express $ modifiers. A rule like
        ||pl.ua^$badfilter means "cancel blocking" — writing it as
        0.0.0.0 pl.ua would invert its semantics. So modifier-bearing rules
        are skipped here and counted in self.modifier_skipped.
        """
        seen = set()
        self.modifier_skipped = 0
        for b in blocks:
            if b.modifiers:
                self.modifier_skipped += 1
                continue
            d = b.normalized_domain
            if d and d not in seen:
                seen.add(d)
                yield b, d

    def write_adguard(self, blocks, allows, outcome, cat_counts):
        header = self._main_header(blocks, allows, outcome, cat_counts)
        self._write_lines(self.out / "merged_rules.txt", header,
                          (b.output_raw for b in blocks))

    def write_whitelist(self, allows):
        header = self._whitelist_header(allows)
        self._write_lines(self.out / "whitelist.txt", header,
                          (a.output_raw for a in allows))

    def write_hosts(self, blocks):
        def body():
            for _, d in self._domain_rules(blocks):
                yield f"0.0.0.0 {d}"
        self._write_lines(self.out / "hosts.txt",
                          ["# Hosts format — AdGuard Rules Merger V5", "#"], body())

    def write_domains(self, blocks):
        def body():
            for _, d in self._domain_rules(blocks):
                yield d
        self._write_lines(self.out / "domains.txt", [], body())

    def write_clash(self, blocks):
        def body():
            for _, d in self._domain_rules(blocks):
                yield f"  - DOMAIN-SUFFIX,{d}"
        self._write_lines(self.out / "clash.yaml",
                          ["# Clash rule-set — AdGuard Rules Merger V5", "payload:"], body())

    def write_surge(self, blocks):
        def body():
            for _, d in self._domain_rules(blocks):
                yield f"DOMAIN-SUFFIX,{d}"
        self._write_lines(self.out / "surge.list",
                          ["# Surge rule-set — AdGuard Rules Merger V5",
                           "# DOMAIN-SUFFIX,<domain>"], body())

    def write_smartdns(self, blocks):
        def body():
            for _, d in self._domain_rules(blocks):
                yield f"address /{d}/#"
        self._write_lines(self.out / "smartdns.conf",
                          ["# SmartDNS blocking config — AdGuard Rules Merger V5",
                           "# address /domain/#  (blocks domain + subdomains)"], body())

    def write_tiered(self, blocks):
        buckets: Dict[str, List[Rule]] = {c: [] for c in TIERED_CATEGORIES}
        for b in blocks:
            if b.category in buckets:
                buckets[b.category].append(b)
        filenames = {
            CATEGORY_ADS: "merged_ads.txt",
            CATEGORY_MALWARE: "merged_malware.txt",
            CATEGORY_TRACKING: "merged_tracking.txt",
            CATEGORY_PHISHING: "merged_phishing.txt",
            CATEGORY_MINING: "merged_mining.txt",
            CATEGORY_OTHER: "merged_other.txt",
        }
        for cat, rules in buckets.items():
            content_ver = _content_hash(rules, [])
            header = [
                f"! Title: Merged {cat} filter (V5)",
                f"! Category: {cat}",
                f"! Version: {content_ver}",
                f"! Rules: {len(rules)}",
                "!",
            ]
            self._write_lines(self.out / filenames[cat], header,
                              (r.output_raw for r in rules))

    def write_stats(self, blocks, allows, outcome):
        now = _now()
        cat_counts = Counter(b.category for b in blocks)
        before = outcome.raw_count
        after = len(blocks) + len(allows)
        total_agg = outcome.aggregated + outcome.wildcard_aggregated + outcome.wildcard_promoted
        stats = {
            "version": "5.0",
            "generated_at": now.isoformat(),
            "sources": {
                "total": outcome.sources_total,
                "ok": outcome.sources_ok,
                "cached": outcome.sources_cached,
                "failed": outcome.failed_sources,
            },
            "rules": {
                "before": before,
                "after": after,
                "block": len(blocks),
                "allow": len(allows),
                "dedup_rate": round((1 - after / before) * 100, 1) if before else 0.0,
            },
            "dedup": {
                "exact_merged": outcome.exact_merged,
                "normalized_merged": outcome.normalized_merged,
                "regex_merged": outcome.regex_merged,
            },
            "optimization": {
                "exact_aggregated": outcome.aggregated,
                "wildcard_aggregated": outcome.wildcard_aggregated,
                "wildcard_promoted": outcome.wildcard_promoted,
                "total_aggregated": total_agg,
                "conflict_resolved": outcome.conflict_resolved,
                "whitelist_blocked": outcome.whitelist_blocked,
            },
            "dropped": {
                "pattern_dropped": outcome.pattern_dropped,
                "quality_dropped": outcome.quality_dropped,
                "css_dropped": outcome.css_dropped,
                "badfilter_removed": getattr(outcome, "badfilter_removed", 0),
                "modifier_rules_skipped": getattr(self, "modifier_skipped", 0),
            },
            "categories": {
                "ads": cat_counts.get(CATEGORY_ADS, 0),
                "malware": cat_counts.get(CATEGORY_MALWARE, 0),
                "tracking": cat_counts.get(CATEGORY_TRACKING, 0),
                "phishing": cat_counts.get(CATEGORY_PHISHING, 0),
                "mining": cat_counts.get(CATEGORY_MINING, 0),
                "other": cat_counts.get("other", 0),
            },
            "modifier_stats": getattr(outcome, "modifier_stats", {}) or {},
            "source_overlap": getattr(outcome, "source_overlap", {}) or {},
            "diff": {
                "added": len(outcome.added),
                "removed": len(outcome.removed),
            },
            "elapsed_seconds": round(outcome.elapsed, 3),
        }
        self._write_json(self.out / "stats.json", stats)

    def write_conflicts(self, conflicts):
        self._write_json(self.out / "conflicts.json", conflicts)

    def write_contributions(self, contributions):
        self._write_json(self.out / "contributions.json", contributions)

    def write_whitelist_audit(self, outcome):
        """V5: write whitelist threat-intel audit results (if enabled)."""
        audit = getattr(outcome, "whitelist_audit", {}) or {}
        if not audit:
            return
        self._write_json(self.out / "whitelist_audit.json", audit)

    def write_whitelist_graded(self, outcome):
        """V5: split whitelist into graded sub-files by rating + category.

        Requires whitelist_audit to have run (outcome.whitelist_audit non-empty).
        Controlled by self.whitelist_output config.
        """
        from .domain_classifier import CATEGORY_ORDER, CATEGORY_LABELS
        audit = getattr(outcome, "whitelist_audit", {}) or {}
        rules = audit.get("rules", [])
        cfg = self.whitelist_output
        if not rules or cfg is None or not getattr(cfg, "enabled", True):
            return

        ratings = ("safe", "suspicious", "malicious", "unknown")
        cat_filter = set(getattr(cfg, "categories", []) or [])
        include_all = getattr(cfg, "include_all_ratings", False)

        # ── by rating ──
        if getattr(cfg, "by_rating", True):
            by_rating: Dict[str, List[str]] = {r: [] for r in ratings}
            for r in rules:
                by_rating[r["rating"]].append(r["rule"])
            for rating in ratings:
                if not by_rating[rating]:
                    continue
                header = [
                    f"! Title: AdGuard Rules Merger — Whitelist ({rating})",
                    f"! Count: {len(by_rating[rating])}",
                    f"! Generated: {_now().isoformat()}",
                ]
                self._write_lines(self.out / f"whitelist_{rating}.txt",
                                  header, by_rating[rating])

        # ── by category (within each rating) ──
        if getattr(cfg, "by_category", True):
            cat_dir = self.out / "whitelist_by_category"
            cat_dir.mkdir(parents=True, exist_ok=True)
            active_ratings = ratings if include_all else ("safe",)
            for rating in active_ratings:
                by_cat: Dict[str, List[str]] = {c: [] for c in CATEGORY_ORDER}
                for r in rules:
                    if r["rating"] != rating:
                        continue
                    cat = r.get("category", "other")
                    if cat_filter and cat not in cat_filter:
                        cat = "other"
                    by_cat[cat].append(r["rule"])
                for cat in CATEGORY_ORDER:
                    if not by_cat[cat]:
                        continue
                    label = CATEGORY_LABELS.get(cat, cat)
                    header = [
                        f"! Title: AdGuard Rules Merger — Whitelist ({rating} / {label})",
                        f"! Count: {len(by_cat[cat])}",
                        f"! Generated: {_now().isoformat()}",
                    ]
                    fname = f"{rating}_{cat}.txt"
                    self._write_lines(cat_dir / fname, header, by_cat[cat])

    def write_diff_files(self, outcome):
        if not self.write_diff_enabled:
            return
        self._write_lines(self.out / "added.txt",
                          [f"# New domains this run ({len(outcome.added)})"],
                          outcome.added)
        self._write_lines(self.out / "removed.txt",
                          [f"# Domains removed this run ({len(outcome.removed)})"],
                          outcome.removed)

    def write_report(self, blocks, allows, outcome):
        analysis = analyze_rules(blocks, allows)
        html = generate_html_report(blocks, allows, outcome, analysis)
        tmp = self.out / "report.html.tmp"
        tmp.write_text(html, encoding="utf-8")
        tmp.replace(self.out / "report.html")
        # V5: Markdown report (no external deps, GitHub-friendly)
        md = generate_markdown_report(blocks, allows, outcome, analysis)
        tmp_md = self.out / "report.md.tmp"
        tmp_md.write_text(md, encoding="utf-8")
        tmp_md.replace(self.out / "report.md")

    @staticmethod
    def _write_json(path: Path, data):
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)

    # ── orchestration ────────────────────────────────────────────

    def export_all(self, blocks: List[Rule], allows: List[Rule],
                   outcome: Any) -> Counter:
        cat_counts = Counter(b.category for b in blocks)

        if "adguard" in self.formats:
            self.write_adguard(blocks, allows, outcome, cat_counts)
        if "whitelist" in self.formats:
            self.write_whitelist(allows)
        if "hosts" in self.formats:
            self.write_hosts(blocks)
        if "domains" in self.formats:
            self.write_domains(blocks)
        if "clash" in self.formats:
            self.write_clash(blocks)
        if "surge" in self.formats:
            self.write_surge(blocks)
        if "smartdns" in self.formats:
            self.write_smartdns(blocks)

        if self.tiered:
            self.write_tiered(blocks)

        self.write_stats(blocks, allows, outcome)
        self.write_conflicts(outcome.conflicts)
        self.write_contributions(outcome.contributions)
        self.write_whitelist_audit(outcome)
        self.write_whitelist_graded(outcome)
        self.write_diff_files(outcome)

        if self.report:
            self.write_report(blocks, allows, outcome)

        # V5 memory optimization: stats/conflicts/contributions already written,
        # provenance tuples are no longer needed — release them.
        for r in blocks + allows:
            r.source_ids = ()

        return cat_counts
