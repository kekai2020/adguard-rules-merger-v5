"""Tests for V5 streaming parser."""

from merger.parser import RuleParser
from merger.models import CATEGORY_ADS


def parse_one(text, **kwargs):
    p = RuleParser(**kwargs)
    rules = p.parse_text(text, source="test", category=CATEGORY_ADS)
    return [r for r in rules if r.rule_type != "comment"], p


def test_adguard_block():
    rules, _ = parse_one("||example.com^")
    assert len(rules) == 1
    r = rules[0]
    assert r.rule_type == "block"
    assert r.normalized_domain == "example.com"
    assert r.wildcard is False
    assert r.output_raw == "||example.com^"


def test_adguard_allow():
    rules, _ = parse_one("@@||example.com^")
    assert len(rules) == 1
    assert rules[0].rule_type == "allow"
    assert rules[0].output_raw == "@@||example.com^"


def test_wildcard():
    rules, _ = parse_one("||*.example.com^")
    assert len(rules) == 1
    assert rules[0].wildcard is True
    assert rules[0].normalized_domain == "example.com"


def test_hosts_format():
    rules, _ = parse_one("0.0.0.0 ads.example.com")
    assert len(rules) == 1
    assert rules[0].normalized_domain == "ads.example.com"
    assert rules[0].output_raw == "||ads.example.com^"


def test_hosts_127_format():
    rules, _ = parse_one("127.0.0.1 ads.example.com")
    assert len(rules) == 1
    assert rules[0].normalized_domain == "ads.example.com"


def test_plain_domain():
    rules, _ = parse_one("ads.example.com")
    assert len(rules) == 1
    assert rules[0].normalized_domain == "ads.example.com"


def test_modifier_preserved_important():
    """V5: $ modifiers are preserved (these lists are AGH-curated)."""
    rules, _ = parse_one("||example.com^$important")
    assert len(rules) == 1
    assert rules[0].normalized_domain == "example.com"
    assert rules[0].modifiers == "important"
    assert rules[0].output_raw == "||example.com^$important"


def test_modifier_preserved_badfilter():
    """$badfilter must NOT be truncated — truncating would invert its semantics."""
    rules, _ = parse_one("||pl.ua^$badfilter")
    assert len(rules) == 1
    assert rules[0].modifiers == "badfilter"
    assert rules[0].output_raw == "||pl.ua^$badfilter"


def test_plain_domain_with_modifier():
    rules, _ = parse_one("wykop.pl$badfilter")
    assert len(rules) == 1
    assert rules[0].normalized_domain == "wykop.pl"
    assert rules[0].modifiers == "badfilter"
    assert rules[0].output_raw == "||wykop.pl^$badfilter"


def test_modifier_normalized_lowercase():
    rules, _ = parse_one("||example.com^$Important")
    assert rules[0].modifiers == "important"


def test_modifier_without_caret():
    """||domain$modifier (omitted ^) is valid AdGuard syntax — must parse."""
    rules, _ = parse_one("||deloton.com$important")
    assert len(rules) == 1
    assert rules[0].normalized_domain == "deloton.com"
    assert rules[0].modifiers == "important"
    assert rules[0].output_raw == "||deloton.com^$important"


def test_css_dropped():
    rules, p = parse_one("example.com##.ad-banner")
    assert len(rules) == 0
    assert p.css_dropped == 1


def test_embedded_wildcard_dropped():
    rules, p = parse_one("||*-ads.example.com^")
    assert len(rules) == 0
    assert p.pattern_dropped == 1


def test_regex_kept():
    rules, _ = parse_one("/^192\\.168\\.\\d+\\.\\d+$/")
    assert len(rules) == 1
    assert rules[0].normalized_domain == ""
    assert rules[0].output_raw.startswith("/")


def test_lowercase_and_trailing_dot():
    rules, _ = parse_one("||EXAMPLE.COM.^")
    assert rules[0].normalized_domain == "example.com"


def test_leading_dot_normalized():
    rules, _ = parse_one("||.example.com^")
    # leading dot stripped -> example.com
    assert rules[0].normalized_domain == "example.com"


def test_strip_www():
    rules, _ = parse_one("||www.example.com^", strip_www=True)
    assert rules[0].normalized_domain == "example.com"


def test_no_strip_www_by_default():
    rules, _ = parse_one("||www.example.com^")
    assert rules[0].normalized_domain == "www.example.com"


def test_localhost_filtered():
    rules, p = parse_one("||localhost^")
    assert len(rules) == 0
    assert p.quality_dropped == 1


def test_short_domain_filtered():
    # min_domain_length defaults to 4; "a.co" is 4 chars -> passes; "a.b" is 3 -> drops
    rules, p = parse_one("||a.b^")
    assert len(rules) == 0
