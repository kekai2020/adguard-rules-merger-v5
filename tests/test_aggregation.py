"""Tests for V5 upward aggregation (including new wildcard aggregation)."""

from merger.core import AsyncRuleEngine
from merger.models import Rule


def make_block(domain, wildcard=False, modifiers=""):
    raw = f"||{'*.' if wildcard else ''}{domain}^{'$'+modifiers if modifiers else ''}"
    return Rule(raw=raw, domain=domain, rule_type="block", wildcard=wildcard,
                sources="test", modifiers=modifiers)


def build_map(rules):
    return {(r.normalized_domain, r.wildcard, r.modifiers): r for r in rules}


def engine(**kwargs):
    defaults = dict(
        aggregation_enabled=True,
        min_aggregator_labels=2,
        wildcard_child_aggregation=True,
        wildcard_promotion_threshold=0,
    )
    defaults.update(kwargs)
    return AsyncRuleEngine(cache_dir=None, **defaults)


def domains_of(survivors):
    return sorted((r.normalized_domain, r.wildcard) for r in survivors)


# ── V4-compatible behavior ─────────────────────────────────────────

def test_exact_child_under_wildcard_parent():
    rules = [
        make_block("example.com", wildcard=True),   # ||*.example.com^
        make_block("ads.example.com"),              # ||ads.example.com^
    ]
    survivors, exact_agg, wild_agg, promoted = engine()._aggregate(build_map(rules))
    norms = [r.normalized_domain for r in survivors]
    assert "example.com" in norms
    assert "ads.example.com" not in norms
    assert exact_agg == 1


def test_exact_child_under_exact_parent():
    # DNS layer: ||example.com^ covers subdomains too
    rules = [
        make_block("example.com"),
        make_block("ads.example.com"),
    ]
    survivors, exact_agg, _, _ = engine()._aggregate(build_map(rules))
    norms = [r.normalized_domain for r in survivors]
    assert norms == ["example.com"]
    assert exact_agg == 1


def test_root_exact_not_removed_by_wildcard():
    # The exact root rule ||example.com^ must survive ||*.example.com^
    # (wildcard only covers subdomains, not the root itself). V5 additionally
    # drops the now-redundant wildcard because exact strictly covers it.
    rules = [
        make_block("example.com", wildcard=True),
        make_block("example.com"),
    ]
    survivors, exact_agg, wild_agg, _ = engine()._aggregate(build_map(rules))
    exact_norms = [r.normalized_domain for r in survivors if not r.wildcard]
    assert "example.com" in exact_norms  # root exact survives
    assert exact_agg == 0               # exact was NOT folded by wildcard
    assert wild_agg == 1                # redundant wildcard removed by exact


def test_min_labels_protection():
    # no aggregation up to a bare TLD parent
    rules = [
        make_block("com"),
        make_block("example.com"),
    ]
    survivors, exact_agg, _, _ = engine(min_aggregator_labels=2)._aggregate(build_map(rules))
    # example.com's parent "com" has 1 label -> protected
    assert exact_agg == 0


# ── V5 new: wildcard child aggregation ─────────────────────────────

def test_wildcard_child_under_wildcard_parent():
    # ||*.sub.example.com^ covered by ||*.example.com^
    rules = [
        make_block("example.com", wildcard=True),
        make_block("sub.example.com", wildcard=True),
    ]
    survivors, _, wild_agg, _ = engine()._aggregate(build_map(rules))
    norms = [r.normalized_domain for r in survivors if r.wildcard]
    assert norms == ["example.com"]
    assert wild_agg == 1


def test_wildcard_child_under_exact_parent():
    # ||*.sub.example.com^ covered by ||example.com^ (DNS layer exact covers subs)
    rules = [
        make_block("example.com", wildcard=False),
        make_block("sub.example.com", wildcard=True),
    ]
    survivors, _, wild_agg, _ = engine()._aggregate(build_map(rules))
    wild_norms = [r.normalized_domain for r in survivors if r.wildcard]
    assert wild_norms == []
    assert wild_agg == 1


def test_same_domain_wildcard_covered_by_exact():
    # ||example.com^ strictly covers ||*.example.com^ -> wildcard is redundant
    rules = [
        make_block("example.com", wildcard=False),
        make_block("example.com", wildcard=True),
    ]
    survivors, _, wild_agg, _ = engine()._aggregate(build_map(rules))
    wild = [r for r in survivors if r.wildcard]
    assert wild == []
    assert wild_agg == 1


def test_wildcard_aggregation_disabled():
    rules = [
        make_block("example.com", wildcard=True),
        make_block("sub.example.com", wildcard=True),
    ]
    survivors, _, wild_agg, _ = engine(wildcard_child_aggregation=False)._aggregate(build_map(rules))
    assert wild_agg == 0
    assert len(survivors) == 2


# ── V5 new: wildcard promotion ─────────────────────────────────────

def test_wildcard_promotion():
    # 3 exact siblings with threshold 3 -> promote to ||*.example.com^
    rules = [make_block(f"{n}.example.com") for n in ("a", "b", "c")]
    eng = engine(wildcard_promotion_threshold=3)
    survivors, _, _, promoted = eng._aggregate(build_map(rules))
    assert promoted == 3
    wild = [r for r in survivors if r.wildcard and r.normalized_domain == "example.com"]
    assert len(wild) == 1


def test_wildcard_promotion_below_threshold():
    rules = [make_block(f"{n}.example.com") for n in ("a", "b")]
    eng = engine(wildcard_promotion_threshold=3)
    survivors, _, _, promoted = eng._aggregate(build_map(rules))
    assert promoted == 0
    assert len(survivors) == 2


# ── V5: rules with $ modifiers skip aggregation ────────────────────

def test_modified_child_not_aggregated():
    # ||ads.example.com^$important must NOT be folded into ||*.example.com^
    rules = [
        make_block("example.com", wildcard=True),
        make_block("ads.example.com", modifiers="important"),
    ]
    survivors, exact_agg, _, _ = engine()._aggregate(build_map(rules))
    norms = [r.normalized_domain for r in survivors]
    assert "ads.example.com" in norms
    assert exact_agg == 0


def test_modified_and_plain_coexist():
    # ||x.com^ and ||x.com^$badfilter are different rules — both survive
    rules = [
        make_block("example.com"),
        make_block("example.com", modifiers="badfilter"),
    ]
    survivors, _, _, _ = engine()._aggregate(build_map(rules))
    assert len(survivors) == 2
