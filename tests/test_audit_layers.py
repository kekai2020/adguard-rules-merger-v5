"""Tests for V5 multi-layer whitelist audit: RDAP, VirusTotal, AI, decision engine."""

from datetime import datetime, timezone, timedelta

import pytest

from merger.whitelist_audit import (
    AuditConfig, audit_whitelist, _is_private_ip,
    RATING_SAFE, RATING_SUSPICIOUS, RATING_UNKNOWN,
)
from merger.whois_audit import (
    parse_rdap_response, NEW_DOMAIN_THRESHOLD_DAYS,
)
from merger.virustotal_audit import query_virustotal, MALICIOUS_THRESHOLD
from merger.scam_check import (
    query_scam_check, SCORE_SUSPICIOUS, SCORE_HIGH, SCAM_CHECK_API,
)
from merger.ai_classifier import AI_CATEGORIES, _build_user_prompt
from merger.models import Rule


# ── RDAP / whois_audit ──

class TestRDAPParser:
    def test_parse_valid_registration(self):
        now = datetime.now(timezone.utc)
        reg_date = (now - timedelta(days=365)).isoformat()
        data = {
            "events": [
                {"eventAction": "registration", "eventDate": reg_date},
                {"eventAction": "expiration",
                 "eventDate": (now + timedelta(days=365)).isoformat()},
            ],
            "entities": [
                {"roles": ["registrar"], "handle": "ExampleReg"},
            ],
        }
        result = parse_rdap_response(data)
        assert result["domain_age_days"] >= 364
        assert result["is_new_domain"] is False
        assert result["registrar"] == "ExampleReg"
        assert result["error"] is None

    def test_parse_new_domain(self):
        now = datetime.now(timezone.utc)
        reg_date = (now - timedelta(days=5)).isoformat()
        data = {"events": [{"eventAction": "registration", "eventDate": reg_date}]}
        result = parse_rdap_response(data)
        assert result["is_new_domain"] is True
        assert result["domain_age_days"] < NEW_DOMAIN_THRESHOLD_DAYS

    def test_parse_not_found(self):
        result = parse_rdap_response({"errorCode": 404, "title": "Not Found"})
        assert result["error"] is not None
        assert result["is_new_domain"] is False

    def test_parse_empty(self):
        result = parse_rdap_response({})
        assert result["error"] is not None

    def test_parse_vcard_registrar(self):
        data = {
            "events": [{"eventAction": "registration",
                        "eventDate": "2020-01-01T00:00:00Z"}],
            "entities": [{
                "roles": ["registrar"],
                "vcardArray": ["vcard", [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "Cloudflare, Inc."],
                ]],
            }],
        }
        result = parse_rdap_response(data)
        assert result["registrar"] == "Cloudflare, Inc."


# ── VirusTotal ──

class TestVirusTotal:
    @pytest.mark.asyncio
    async def test_no_api_key(self):
        result = await query_virustotal("example.com", "", None)
        assert result["error"] == "no API key configured"
        assert result["malicious"] is False

    def test_threshold_constant(self):
        assert 0 < MALICIOUS_THRESHOLD < 1


# ── MarketNow scam check ──

class TestScamCheck:
    def test_constants(self):
        assert 0 < SCORE_SUSPICIOUS < SCORE_HIGH <= 100
        assert SCAM_CHECK_API.startswith("https://")

    @pytest.mark.asyncio
    async def test_safe_domain_not_flagged(self):
        import aiohttp
        try:
            async with aiohttp.ClientSession() as s:
                result = await query_scam_check("google.com", s)
        except Exception:
            pytest.skip("network unavailable")
        if result.get("error"):
            pytest.skip(f"API error: {result['error']}")
        assert result["is_suspicious"] is False
        assert result["decision"] == "TRUSTED"

    @pytest.mark.asyncio
    async def test_typosquat_flagged(self):
        import aiohttp
        try:
            async with aiohttp.ClientSession() as s:
                result = await query_scam_check("micros0ft-login.net", s)
        except Exception:
            pytest.skip("network unavailable")
        if result.get("error"):
            pytest.skip(f"API error: {result['error']}")
        assert result["is_suspicious"] is True
        assert result["risk_score"] >= SCORE_SUSPICIOUS


# ── AI classifier ──

class TestAIClassifier:
    def test_categories_complete(self):
        expected = {"advertising", "analytics", "cdn", "microsoft_telemetry",
                    "affiliate", "social", "ecommerce_payment",
                    "privacy_security", "other"}
        assert set(AI_CATEGORIES) == expected

    def test_prompt_contains_domain(self):
        prompt = _build_user_prompt("evil.com")
        assert "evil.com" in prompt


# ── Private IP detection ──

class TestPrivateIP:
    @pytest.mark.parametrize("ip,expected", [
        ("10.0.0.1", True),
        ("192.168.1.1", True),
        ("172.16.0.1", True),
        ("127.0.0.1", True),
        ("169.254.1.1", True),
        ("8.8.8.8", False),
        ("1.1.1.1", False),
        ("::1", True),
        ("fc00::1", True),
        ("2001:4860:4860::8888", False),
        ("not-an-ip", False),
    ])
    def test_private_ip(self, ip, expected):
        assert _is_private_ip(ip) is expected


# ── Multi-layer decision engine (offline layers only) ──

class TestDecisionEngine:
    @pytest.mark.asyncio
    async def test_empty_allows(self):
        result = await audit_whitelist([], config=AuditConfig())
        assert result["summary"]["total"] == 0

    @pytest.mark.asyncio
    async def test_dns_only_disabled_ti(self):
        # Use a known-good domain, disable all network layers except DNS
        rule = Rule(raw="@@||example.com^", domain="example.com",
                     rule_type="allow", wildcard=False, modifiers=(),
                     source_ids=("src1",))
        cfg = AuditConfig(
            use_dns=True, use_urlhaus=False, use_threatfox=False,
            use_rdap=False, use_virustotal=False, use_ai=False,
        )
        result = await audit_whitelist([rule], source_names={"src1": "Test"},
                                       config=cfg)
        assert result["summary"]["total"] == 1
        # example.com resolves to a public IP → safe
        assert result["rules"][0]["rating"] in (RATING_SAFE, RATING_UNKNOWN)
        assert result["rules"][0]["sources"] == ["Test"]

    @pytest.mark.asyncio
    async def test_nxdomain_suspicious(self):
        # A domain that definitely doesn't exist
        rule = Rule(raw="@@||this-domain-definitely-does-not-exist-xyz123.invalid^",
                     domain="this-domain-definitely-does-not-exist-xyz123.invalid",
                     rule_type="allow", wildcard=False, modifiers=(),
                     source_ids=("src1",))
        cfg = AuditConfig(
            use_dns=True, use_urlhaus=False, use_threatfox=False,
            use_rdap=False, use_virustotal=False, use_ai=False,
        )
        result = await audit_whitelist([rule], config=cfg)
        assert result["rules"][0]["rating"] == RATING_SUSPICIOUS
        assert result["rules"][0]["dns_nxdomain"] is True

    @pytest.mark.asyncio
    async def test_layers_enabled_tracking(self):
        rule = Rule(raw="@@||example.com^", domain="example.com",
                     rule_type="allow", wildcard=False, modifiers=(),
                     source_ids=("src1",))
        cfg = AuditConfig(use_dns=True, use_urlhaus=False, use_threatfox=False,
                          use_rdap=False, use_virustotal=False, use_ai=False)
        result = await audit_whitelist([rule], config=cfg)
        layers = result["summary"]["layers_enabled"]
        assert layers["dns"] is True
        assert layers["urlhaus"] is False
        assert layers["rdap"] is False
        assert layers["virustotal"] is False
        assert layers["ai"] is False

    @pytest.mark.asyncio
    async def test_category_confidence_in_output(self):
        rule = Rule(raw="@@||doubleclick.net^", domain="doubleclick.net",
                     rule_type="allow", wildcard=False, modifiers=(),
                     source_ids=("src1",))
        cfg = AuditConfig(use_dns=False, use_urlhaus=False, use_threatfox=False,
                          use_rdap=False, use_virustotal=False, use_ai=False)
        result = await audit_whitelist([rule], config=cfg)
        r = result["rules"][0]
        assert r["category"] == "advertising"
        assert r["category_confidence"] >= 0.9

    @pytest.mark.asyncio
    async def test_legacy_kwargs_backcompat(self):
        """audit_whitelist should still accept legacy kwargs without config."""
        rule = Rule(raw="@@||example.com^", domain="example.com",
                     rule_type="allow", wildcard=False, modifiers=(),
                     source_ids=("src1",))
        result = await audit_whitelist(
            [rule], concurrency=5, use_dns=False, use_urlhaus=False,
            use_threatfox=False,
        )
        assert result["summary"]["total"] == 1
