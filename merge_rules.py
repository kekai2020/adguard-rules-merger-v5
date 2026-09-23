#!/usr/bin/env python3
"""AdGuard Rules Merger V5 — CLI entrypoint.

Usage:
  python merge_rules.py merge    --config config/sources.yaml
  python merge_rules.py validate config/sources.yaml
  python merge_rules.py merge    --config config/sources.yaml --no-cache
  python merge_rules.py version
"""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

sys.path.insert(0, str(Path(__file__).parent))

from merger import AsyncRuleEngine, Exporter, __version__  # noqa: E402
from config_loader import load_config, load_source_metas, validate_config  # noqa: E402

app = typer.Typer(
    name="adguard-rules-merger-v5",
    help="V5: merge AdGuard DNS rules with dedup + aggregation + conflict resolution.",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()


def _setup_logging(verbose: bool, quiet: bool) -> None:
    level = logging.DEBUG if verbose else (logging.WARNING if quiet else logging.INFO)
    logging.basicConfig(
        level=level, format="%(message)s", datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
    )


def _peak_rss_mb() -> float:
    """Peak resident set size in MB. Works on Linux, macOS, and Windows."""
    if sys.platform.startswith("linux") or sys.platform == "darwin":
        import resource
        val = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        # ru_maxrss is KB on Linux, bytes on macOS
        return val / 1024.0 if sys.platform.startswith("linux") else val / (1024 * 1024)
    # Windows: use psutil if available, else ctypes
    try:
        import psutil
        return psutil.Process().memory_info().peak_wset / (1024 * 1024)
    except ImportError:
        try:
            import ctypes
            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("cb", ctypes.c_ulong),
                    ("PageFaultCount", ctypes.c_ulong),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]
            pmc = PROCESS_MEMORY_COUNTERS()
            pmc.cb = ctypes.sizeof(pmc)
            ctypes.windll.psapi.GetProcessMemoryInfo(
                ctypes.windll.kernel32.GetCurrentProcess(),
                ctypes.byref(pmc), ctypes.sizeof(pmc))
            return pmc.PeakWorkingSetSize / (1024 * 1024)
        except Exception:
            return 0.0


@app.command()
def merge(
    config: str = typer.Option("config/sources.yaml", "--config", "-c"),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", "-o"),
    no_cache: bool = typer.Option(False, "--no-cache"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
):
    """Fetch, merge, optimise and export all rule formats."""
    _setup_logging(verbose, quiet)

    try:
        cfg = load_config(config)
        sources = load_source_metas(config)
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]Config error: {e}[/red]")
        raise typer.Exit(1)

    out_dir = output_dir or cfg.output.directory
    cache_dir = None if (no_cache or not cfg.cache.enabled) else cfg.cache.directory

    console.print(f"\n[bold cyan]AdGuard Rules Merger v{__version__}[/bold cyan]")
    console.print(f"  Sources: {len(sources)} | Concurrency: {cfg.max_concurrency}")
    console.print(f"  Cache: {'disabled' if cache_dir is None else cache_dir}")
    console.print()

    engine = AsyncRuleEngine(
        timeout=cfg.timeout,
        max_concurrency=cfg.max_concurrency,
        cache_dir=cache_dir,
        cache_ttl=cfg.cache.ttl_seconds,
        cache_max_size_mb=cfg.cache.max_size_mb,
        strip_www=cfg.dedup.strip_www,
        quality_filter_enabled=cfg.quality_filter.enabled,
        min_domain_length=cfg.quality_filter.min_domain_length,
        max_domain_length=cfg.quality_filter.max_domain_length,
        filter_localhost=cfg.quality_filter.filter_localhost,
        filter_ip_rules=cfg.quality_filter.filter_ip_rules,
        aggregation_enabled=cfg.aggregation.enabled,
        min_aggregator_labels=cfg.aggregation.min_aggregator_labels,
        wildcard_child_aggregation=cfg.aggregation.wildcard_child_aggregation,
        wildcard_promotion_threshold=cfg.aggregation.wildcard_promotion_threshold,
        conflict_resolution_enabled=cfg.conflict_resolution.enabled,
        cascade_subdomains=cfg.conflict_resolution.cascade_subdomains,
        whitelist_audit_enabled=cfg.whitelist_audit.enabled,
        whitelist_audit_concurrency=cfg.whitelist_audit.concurrency,
        whitelist_audit_use_dns=cfg.whitelist_audit.use_dns,
        whitelist_audit_use_urlhaus=cfg.whitelist_audit.use_urlhaus,
        whitelist_audit_use_threatfox=cfg.whitelist_audit.use_threatfox,
        whitelist_audit_use_rdap=cfg.whitelist_audit.use_rdap,
        whitelist_audit_use_scam_check=cfg.whitelist_audit.use_scam_check,
        whitelist_audit_use_virustotal=cfg.whitelist_audit.use_virustotal,
        whitelist_audit_vt_api_key=cfg.whitelist_audit.virustotal_api_key,
        whitelist_audit_use_ai=cfg.whitelist_audit.ai.enabled,
        whitelist_audit_ai_api_key=cfg.whitelist_audit.ai.api_key,
        whitelist_audit_ai_base_url=cfg.whitelist_audit.ai.base_url,
        whitelist_audit_ai_model=cfg.whitelist_audit.ai.model,
        whitelist_audit_ai_min_confidence=cfg.whitelist_audit.ai.min_confidence,
        whitelist_audit_new_domain_days=cfg.whitelist_audit.new_domain_threshold_days,
        whitelist_audit_urlhaus_delay=cfg.whitelist_audit.urlhaus_delay,
        fail_threshold=cfg.fail_threshold,
        diff_against=cfg.diff_against,
        user_agent=cfg.download.user_agent,
        retry_count=cfg.download.retry_count,
        retry_delay=cfg.download.retry_delay,
    )

    t0 = time.time()
    try:
        outcome = engine.run_sync(sources)
    except Exception as e:  # noqa: BLE001
        console.print(f"[red bold]✗ Merge failed: {e}[/red bold]")
        import traceback
        traceback.print_exc()
        raise typer.Exit(1)

    wall = time.time() - t0
    exporter = Exporter(
        out_dir,
        formats=cfg.output.formats,
        tiered=cfg.output.tiered,
        report=cfg.output.report,
        write_diff=cfg.output.write_diff,
        whitelist_output=cfg.whitelist_output,
    )
    exporter.export_all(outcome.blocks, outcome.allows, outcome)

    # results table
    table = Table(title="Merge Results (V5)", show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="dim")
    table.add_column("Value", justify="right")
    table.add_row("Raw rules (before)", f"{outcome.raw_count:,}")
    table.add_row("Block rules", f"{len(outcome.blocks):,}")
    table.add_row("Whitelist rules", f"{len(outcome.allows):,}")
    table.add_row("Sources (ok/cached/total)",
                  f"{outcome.sources_ok} / {outcome.sources_cached} / {outcome.sources_total}")
    table.add_row("Exact dedup", f"{outcome.exact_merged:,}")
    table.add_row("Normalized dedup", f"{outcome.normalized_merged:,}")
    table.add_row("Regex dedup", f"{outcome.regex_merged:,}")
    table.add_row("Exact aggregated", f"{outcome.aggregated:,}")
    table.add_row("Wildcard aggregated", f"{outcome.wildcard_aggregated:,}")
    table.add_row("Wildcard promoted", f"{outcome.wildcard_promoted:,}")
    table.add_row("Conflicts resolved", f"{outcome.conflict_resolved:,}")
    if outcome.failed_sources:
        table.add_row("Failed sources", f"[red]{len(outcome.failed_sources)}[/red]")
    table.add_row("Wall time", f"{wall:.2f}s")
    table.add_row("Peak RSS", f"{_peak_rss_mb():.1f} MB")
    console.print(table)

    if outcome.failed_sources:
        console.print("\n[yellow]⚠ Failed sources:[/yellow]")
        for fs in outcome.failed_sources:
            console.print(f"  - {fs['name']}: {fs['error']}")

    console.print(f"\n[green]✓ Output written to {Path(out_dir).resolve()}[/green]")
    for fn in ("merged_rules.txt", "whitelist.txt", "hosts.txt", "domains.txt",
               "clash.yaml", "surge.list", "smartdns.conf",
               "merged_ads.txt", "merged_malware.txt",
               "merged_tracking.txt", "merged_phishing.txt", "merged_mining.txt",
               "stats.json", "conflicts.json", "contributions.json",
               "whitelist_audit.json",
               "added.txt", "removed.txt", "report.html", "report.md"):
        p = Path(out_dir) / fn
        if p.exists():
            console.print(f"    {fn}  ({p.stat().st_size/1024:.0f} KB)")
    # graded whitelist files
    for fn in ("whitelist_safe.txt", "whitelist_suspicious.txt",
               "whitelist_malicious.txt", "whitelist_unknown.txt"):
        p = Path(out_dir) / fn
        if p.exists():
            console.print(f"    {fn}  ({p.stat().st_size/1024:.1f} KB)")
    cat_dir = Path(out_dir) / "whitelist_by_category"
    if cat_dir.exists():
        for p in sorted(cat_dir.glob("*.txt")):
            console.print(f"    whitelist_by_category/{p.name}  ({p.stat().st_size/1024:.1f} KB)")
    console.print()


@app.command()
def validate(config_path: str = typer.Argument(..., help="YAML config to validate")):
    """Validate a sources.yaml config file."""
    issues = validate_config(config_path)
    if issues:
        console.print(f"[red]✗ {len(issues)} issue(s):[/red]")
        for i in issues:
            console.print(f"  - {i}")
        raise typer.Exit(1)
    cfg = load_config(config_path)
    console.print("[green]✓ Valid config[/green]")
    console.print(f"  Sources: {len(cfg.sources)} "
                  f"({sum(1 for s in cfg.sources if s.enabled)} enabled)")
    cats = {}
    for s in cfg.sources:
        if s.enabled:
            cats[s.category] = cats.get(s.category, 0) + 1
    console.print(f"  Categories: {cats}")


@app.command()
def version():
    """Show version."""
    console.print(f"AdGuard Rules Merger v{__version__}")


if __name__ == "__main__":
    app()
