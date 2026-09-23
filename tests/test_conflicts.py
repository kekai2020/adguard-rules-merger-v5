"""Tests for V5 conflict resolution (allow overrides block)."""

from merger.core import AsyncRuleEngine
from merger.models import Rule


def block(domain, wildcard=False, modifiers=""):
    return Rule(raw=f"||{'*.' if wildcard else ''}{domain}^{'$'+modifiers if modifiers else ''}",
                domain=domain, rule_type="block", wildcard=wildcard,
                sources="block-src", modifiers=modifiers)


def allow(domain, wildcard=False):
    return Rule(raw=f"@@||{'*.' if wildcard else ''}{domain}^", domain=domain,
                rule_type="allow", wildcard=wildcard, sources="allow-src")


def engine(**kwargs):
    defaults = dict(conflict_resolution_enabled=True, cascade_subdomains=True)
    defaults.update(kwargs)
    return AsyncRuleEngine(cache_dir=None, **defaults)


def test_exact_allow_removes_exact_block():
    blocks = [block("example.com")]
    allows = [allow("example.com")]
    survivors, removed, conflicts = engine()._resolve_conflicts(blocks, allows)
    assert survivors == []
    assert removed == 1
    assert len(conflicts) == 1


def test_allow_cascades_to_subdomains():
    # @@||example.com^ removes ||ads.example.com^ when cascade enabled
    blocks = [block("ads.example.com"), block("track.example.com")]
    allows = [allow("example.com")]
    survivors, removed, _ = engine(cascade_subdomains=True)._resolve_conflicts(blocks, allows)
    assert survivors == []
    assert removed == 2


def test_cascade_disabled_keeps_subdomains():
    blocks = [block("ads.example.com")]
    allows = [allow("example.com")]
    survivors, removed, _ = engine(cascade_subdomains=False)._resolve_conflicts(blocks, allows)
    # exact allow only removes the exact domain itself; subdomain survives
    assert len(survivors) == 1
    assert removed == 0


def test_wildcard_allow_removes_subdomain_not_root():
    # @@||*.example.com^ removes subdomains but NOT ||example.com^ itself
    blocks = [block("example.com"), block("ads.example.com")]
    allows = [allow("example.com", wildcard=True)]
    survivors, removed, _ = engine()._resolve_conflicts(blocks, allows)
    norms = sorted(r.normalized_domain for r in survivors)
    assert norms == ["example.com"]
    assert removed == 1


def test_unrelated_allow_keeps_block():
    blocks = [block("evil.com")]
    allows = [allow("example.com")]
    survivors, removed, _ = engine()._resolve_conflicts(blocks, allows)
    assert len(survivors) == 1
    assert removed == 0


def test_regex_blocks_skip_conflict_resolution():
    regex = Rule(raw="/^192\\.168\\./", domain="", rule_type="block", wildcard=False)
    allows = [allow("168.com")]
    survivors, removed, _ = engine()._resolve_conflicts([regex], allows)
    assert len(survivors) == 1


def test_important_block_not_overridden_by_allow():
    # $important rules outrank whitelists at AGH runtime — must survive.
    blocks = [block("pixel.wp.pl", modifiers="important")]
    allows = [allow("pixel.wp.pl")]
    survivors, removed, _ = engine()._resolve_conflicts(blocks, allows)
    assert len(survivors) == 1
    assert removed == 0
    assert survivors[0].modifiers == "important"


def test_conflict_record_has_multi_source_info():
    """V5: conflict records include both sides' sources, domain, type."""
    b = block("ads.example.com")
    b.source_ids = ("src-a", "src-b")
    a = allow("example.com")
    a.source_ids = ("src-c",)
    source_names = {"src-a": "ListA", "src-b": "ListB", "src-c": "ListC"}
    _, _, conflicts = engine()._resolve_conflicts([b], [a], source_names)
    assert len(conflicts) == 1
    c = conflicts[0]
    assert c["domain"] == "ads.example.com"
    assert c["blocked_sources"] == ["ListA", "ListB"]
    assert c["whitelist_sources"] == ["ListC"]
    assert c["conflict_type"] == "cascade"
    assert "blocked_rule" in c
    assert "whitelist_rule" in c
