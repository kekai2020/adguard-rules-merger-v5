"""V5 streaming parser for DNS-layer AdGuard / Hosts / plain-domain lists.

Parsing rules (strict DNS-layer only):
  - AdGuard block:  ``||domain^``            -> block
  - AdGuard allow:  ``@@||domain^``         -> allow
  - Wildcard:       ``||*.domain^``         -> block, wildcard=True
  - Hosts:          ``0.0.0.0 domain``      -> block
  - Plain domain:  ``example.com``          -> block
  - Comment:        ``! ...`` / ``# ...``   -> comment
  - Regex:          ``/regex/``             -> kept as-is (AGH supports it)
  - ``$ modifiers`` (``important``, ``badfilter``, ...) are PRESERVED — these
    lists are AGH-curated and modifiers are DNS-meaningful.  Dropping
    ``$badfilter`` would invert its semantics (unblock -> block).
  - Drop:           CSS/JS selectors (``##``, ``#@#``), embedded wildcards
                    (``||*-x.com^``), URL-bar rules.

V5 improvements over V4:
  - Light regex normalization (strip surrounding whitespace, normalize flags).
  - Leading-dot domains normalized (``.example.com`` -> ``example.com``).
  - Accurate per-category drop counters.
  - ``$`` modifiers preserved instead of truncated.
"""

from __future__ import annotations

import re
from typing import Iterator, List, Optional, Set

from .models import Rule, CATEGORY_OTHER, CATEGORY_COMMENT


class RuleParser:
    """High-performance streaming parser with drop counters."""

    # ── pre-compiled patterns ──────────────────────────────────
    # ^ is optional when $ modifiers follow directly: ||domain$important
    RE_BLOCK = re.compile(r"^\|\|([^/^\s$]+)\^?")
    RE_ALLOW = re.compile(r"^@@\|\|([^/^\s$]+)\^?")
    RE_WILD_PREFIX = re.compile(r"^\*\.")
    RE_HOSTS = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}\s+(\S+)")
    RE_DOMAIN = re.compile(r"^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$")
    RE_WILD_DOMAIN = re.compile(r"^\*\.([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$")
    RE_CSS = re.compile(r"#@?#|#%#")  # CSS/JS: ##, #@#, #%# (may be domain-prefixed)
    RE_REGEX = re.compile(r"^(?:@@)?/.+/\$?[a-z,]*$")
    RE_URLBAR = re.compile(r"^\|?https?://")
    RE_COMMENT_HASH = re.compile(r"^#(?!#|@#|%)")

    LOCALHOST: Set[str] = frozenset({
        "localhost", "localhost.localdomain",
        "localhost6", "localhost6.localdomain6",
        "local", "localdomain",
    })

    def __init__(
        self,
        strip_www: bool = False,
        quality_filter: bool = True,
        min_domain_length: int = 4,
        max_domain_length: int = 253,
        filter_localhost: bool = True,
        filter_ip_rules: bool = False,
    ) -> None:
        self.pattern_dropped = 0
        self.quality_dropped = 0
        self.css_dropped = 0
        self.strip_www = strip_www
        self.quality_filter_enabled = quality_filter
        self.min_domain_length = min_domain_length
        self.max_domain_length = max_domain_length
        self.filter_localhost = filter_localhost
        self.filter_ip_rules = filter_ip_rules

    # ── helpers ────────────────────────────────────────────────

    @staticmethod
    def _clean(domain: str) -> str:
        d = domain.lower().strip()
        if d.endswith("."):
            d = d[:-1]
        if d.startswith("."):
            d = d[1:]
        return d

    @staticmethod
    def _is_ip(text: str) -> bool:
        parts = text.split(".")
        if len(parts) == 4:
            try:
                return all(0 <= int(p) <= 255 for p in parts)
            except ValueError:
                return False
        return False

    @staticmethod
    def _split_modifiers(s: str):
        """Return (line_without_$section, modifiers_str).

        The first ``$`` starts the modifier section in AdGuard syntax.
        Regex rules are handled before this is called, so a ``$`` here is
        always a modifier separator.
        """
        i = s.find("$")
        if i == -1:
            return s, ""
        return s[:i].strip(), s[i + 1:].strip()

    @staticmethod
    def _normalize_regex(raw: str) -> str:
        """Light normalization for regex rules: strip whitespace only."""
        return raw.strip()

    def _valid_dns_domain(self, d: str) -> bool:
        if "*" not in d:
            return True
        return d.startswith("*.") and "*" not in d[2:]

    def _quality_check(self, d: str) -> bool:
        if not self.quality_filter_enabled:
            return True
        check_d = d[2:] if d.startswith("*.") else d
        if len(check_d) < self.min_domain_length:
            return False
        if len(check_d) > self.max_domain_length:
            return False
        if self.filter_localhost:
            if check_d in self.LOCALHOST or check_d.endswith(".localhost") or check_d.endswith(".local"):
                return False
        if self.filter_ip_rules:
            if self._is_ip(check_d):
                return False
        if "." not in check_d:
            return False
        parts = check_d.split(".")
        if any(not p for p in parts):
            return False
        return True

    def _make_rule(self, raw_line: str, d: str, rule_type: str,
                   wildcard: bool, source: str, category: str,
                   modifiers: str = "") -> Optional[Rule]:
        if not d or not self._valid_dns_domain(d):
            if d and "*" in d:
                self.pattern_dropped += 1
            return None
        if not self._quality_check(d):
            self.quality_dropped += 1
            return None
        mod = f"${modifiers}" if modifiers else ""
        if rule_type == "allow":
            raw = f"@@||{d}^{mod}"
        else:
            raw = f"||{d}^{mod}"
        return Rule(raw=raw, domain=d, rule_type=rule_type,
                    wildcard=wildcard, sources=source, category=category,
                    strip_www=self.strip_www, modifiers=modifiers)

    # ── streaming parse ─────────────────────────────────────────

    def parse_stream(
        self,
        lines: Iterator[str],
        source: str = "",
        category: str = CATEGORY_OTHER,
    ) -> Iterator[Rule]:
        re_block = self.RE_BLOCK.match
        re_allow = self.RE_ALLOW.match
        re_hosts = self.RE_HOSTS.match
        re_plain = self.RE_DOMAIN.match
        re_wild_plain = self.RE_WILD_DOMAIN.match
        re_css = self.RE_CSS.search
        re_regex = self.RE_REGEX.match
        re_urlbar = self.RE_URLBAR.match
        re_hash_comment = self.RE_COMMENT_HASH.match
        re_wild = self.RE_WILD_PREFIX.match
        clean = self._clean
        is_ip = self._is_ip
        localhost = self.LOCALHOST
        split_mod = self._split_modifiers
        norm_regex = self._normalize_regex
        RuleCls = Rule
        cat_comment = CATEGORY_COMMENT
        strip_www = self.strip_www

        for line in lines:
            if not line:
                continue
            s = line.strip()
            if not s:
                continue

            # comments: ! or # (but not ## / #@#)
            if s.startswith("!") or re_hash_comment(s):
                yield RuleCls(raw=s, domain="", rule_type="comment",
                              wildcard=False, sources=source,
                              category=cat_comment, strip_www=strip_www)
                continue

            if re_css(s) or re_urlbar(s):
                if re_css(s):
                    self.css_dropped += 1
                continue

            # regex rules — kept as-is (light whitespace normalization)
            if re_regex(s):
                s = norm_regex(s)
                rule_type = "allow" if s.startswith("@@") else "block"
                yield RuleCls(raw=s, domain="", rule_type=rule_type,
                              wildcard=False, sources=source,
                              category=category, strip_www=strip_www)
                continue

            s2, modifiers = split_mod(s)
            if not s2:
                continue

            # allow: @@||domain^
            m = re_allow(s2)
            if m:
                d = clean(m.group(1))
                r = self._make_rule(s2, d, "allow", re_wild(d) is not None,
                                    source, category, modifiers=modifiers)
                if r:
                    yield r
                continue

            # block: ||domain^
            m = re_block(s2)
            if m:
                d = clean(m.group(1))
                r = self._make_rule(s2, d, "block", re_wild(d) is not None,
                                    source, category, modifiers=modifiers)
                if r:
                    yield r
                continue

            # hosts: IP hostname
            m = re_hosts(s2)
            if m:
                d = clean(m.group(1))
                if d in localhost or "*" in d:
                    if "*" in d:
                        self.pattern_dropped += 1
                    continue
                r = self._make_rule(s2, d, "block", False, source, category,
                                    modifiers=modifiers)
                if r:
                    yield r
                continue

            # plain wildcard domain: *.example.com
            if re_wild_plain(s2) and not is_ip(s2):
                d = clean(s2)
                r = self._make_rule(s2, d, "block", True, source, category,
                                    modifiers=modifiers)
                if r:
                    yield r
                continue

            # plain domain
            if re_plain(s2) and not is_ip(s2):
                d = clean(s2)
                r = self._make_rule(s2, d, "block", False, source, category,
                                    modifiers=modifiers)
                if r:
                    yield r
                continue

    # ── bulk ────────────────────────────────────────────────────

    def parse_text(
        self,
        text: str,
        source: str = "",
        category: str = CATEGORY_OTHER,
    ) -> List[Rule]:
        return list(self.parse_stream(iter(text.splitlines()), source, category))
