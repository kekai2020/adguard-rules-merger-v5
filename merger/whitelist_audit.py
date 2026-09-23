"""V5 whitelist auditor — multi-layer defense-in-depth decision engine.

Layers (all network layers execute in PARALLEL per domain via asyncio.gather):
  1. DNS resolution     — NXDOMAIN=expired, private-IP=suspicious (free, keyless)
  2. Threat intelligence — URLhaus + ThreatFox (free, keyless, rate-limited)
  3. RDAP registration   — domain age, new domains <30d flagged (free, keyless)
  4. MarketNow scam check— typosquatting / suspicious TLD / unregistered (free)
  5. VirusTotal          — vendor reputation (optional, needs API key)
  6. Offline classifier  — tldextract + PSL registered-domain matching (free, sync)
  7. AI classification   — LLM semantic fallback for low-confidence domains
                           (optional, needs API key, only called for conf<0.6)

Parallel execution:
  - All independent network layers (DNS, threat-intel, RDAP, scam, VirusTotal)
    run concurrently via asyncio.gather — total latency ≈ max(layer latency)
    instead of sum(layer latencies).
  - The offline PSL classifier is synchronous and microsecond-fast.
  - The AI layer runs after the gather because it depends on the offline
    confidence score (only low-confidence domains trigger it).
  - A shared aiohttp.ClientSession is used across all domains/layers.

Ratings:
  malicious  🔴  any threat-intel source positive
  suspicious 🟡  DNS NXDOMAIN / private IP / new domain / scam check
  safe       🟢  DNS resolves normally, no threat hits
  unknown    ⚪  all checks failed

Results are cached in-memory with a 24h TTL.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .ai_classifier import classify_with_ai
from .domain_classifier import (
    classify_domain_with_confidence, category_counts,
)
from .models import Rule
from .scam_check import query_scam_check
from .virustotal_audit import query_virustotal
from .whois_audit import query_rdap

URLHAUS_HOST_API = "https://urlhaus-api.abuse.ch/v1/host/"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"

RATING_MALICIOUS = "malicious"
RATING_SUSPICIOUS = "suspicious"
RATING_SAFE = "safe"
RATING_UNKNOWN = "unknown"

CACHE_TTL = 86400  # 24 hours

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


@dataclass
class AuditConfig:
    """Configuration for the multi-layer audit engine."""
    use_dns: bool = True
    use_urlhaus: bool = True
    use_threatfox: bool = True
    use_rdap: bool = True
    use_scam_check: bool = True
    use_virustotal: bool = False
    virustotal_api_key: str = ""
    use_ai: bool = False
    ai_api_key: str = ""
    ai_base_url: str = "https://api.openai.com/v1"
    ai_model: str = "gpt-4o-mini"
    ai_min_confidence: float = 0.6
    ai_max_domains: int = 100
    concurrency: int = 20
    urlhaus_delay: float = 0.2
    new_domain_threshold_days: int = 30


@dataclass
class _CacheEntry:
    result: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)


_result_cache: Dict[str, _CacheEntry] = {}
# Semaphore for rate-limited threat-intel APIs (URLhaus / ThreatFox).
# Allows limited concurrency instead of serializing all requests.
_ti_sem = asyncio.Semaphore(3)


def _is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in _PRIVATE_NETS)


def _cache_get(key: str) -> Optional[Dict[str, Any]]:
    entry = _result_cache.get(key)
    if entry and (time.time() - entry.timestamp) < CACHE_TTL:
        return entry.result
    return None


def _cache_set(key: str, result: Dict[str, Any]) -> None:
    _result_cache[key] = _CacheEntry(result=result)


async def _dns_check(domain: str, timeout: int = 5) -> Dict[str, Any]:
    """Async DNS resolution (IPv4 + IPv6)."""
    try:
        loop = asyncio.get_running_loop()
        infos = await asyncio.wait_for(
            loop.getaddrinfo(domain, None, family=socket.AF_UNSPEC),
            timeout=timeout,
        )
        ips = list({info[4][0] for info in infos})
        return {"nxdomain": False, "ips": ips, "error": None}
    except asyncio.TimeoutError:
        return {"nxdomain": False, "ips": [], "error": "timeout"}
    except Exception as e:
        msg = str(e).lower()
        if "name or service not known" in msg or "nodename nor servname" in msg:
            return {"nxdomain": True, "ips": [], "error": None}
        return {"nxdomain": False, "ips": [], "error": str(e)}


async def _query_urlhaus(domain: str, session, timeout: int = 8) -> Dict[str, Any]:
    try:
        data = {"host": domain}
        headers = {"User-Agent": "AdGuard-Rules-Merger/5.0"}
        async with session.post(URLHAUS_HOST_API, data=data,
                                headers=headers, timeout=timeout) as resp:
            if resp.status != 200:
                return {"malicious": False, "error": f"HTTP {resp.status}"}
            result = await resp.json(content_type=None)
            if result.get("query_status") == "ok":
                return {"malicious": True, "error": None}
            return {"malicious": False, "error": None}
    except Exception as e:
        return {"malicious": False, "error": str(e)}


async def _query_threatfox(domain: str, session, timeout: int = 8) -> Dict[str, Any]:
    try:
        data = {"query": "search_ioc", "search_term": domain}
        headers = {"User-Agent": "AdGuard-Rules-Merger/5.0"}
        async with session.post(THREATFOX_API, json=data,
                                headers=headers, timeout=timeout) as resp:
            if resp.status != 200:
                return {"malicious": False, "error": f"HTTP {resp.status}"}
            result = await resp.json(content_type=None)
            if result.get("query_status") == "ok" and result.get("data"):
                return {"malicious": True, "error": None}
            return {"malicious": False, "error": None}
    except Exception as e:
        return {"malicious": False, "error": str(e)}


async def _query_threat_intel(domain: str, session, idx: int,
                               config: AuditConfig) -> Tuple[Dict, Dict]:
    """Query URLhaus + ThreatFox with rate-limit semaphore.

    Uses a semaphore (default 3 concurrent) instead of a global lock,
    and a fixed small delay rather than idx-proportional sleep.
    Returns (urlhaus_result, threatfox_result).
    """
    urlhaus = {"malicious": False, "error": "disabled"}
    threatfox = {"malicious": False, "error": "disabled"}

    if not (config.use_urlhaus or config.use_threatfox):
        return urlhaus, threatfox

    async with _ti_sem:
        # Fixed small delay to avoid burst; NOT idx-proportional.
        if config.urlhaus_delay > 0:
            await asyncio.sleep(config.urlhaus_delay)
        if config.use_urlhaus:
            urlhaus = await _query_urlhaus(domain, session)
        if config.use_threatfox:
            threatfox = await _query_threatfox(domain, session)

    return urlhaus, threatfox


async def _query_rdap_wrapper(domain: str, session, config: AuditConfig) -> Dict[str, Any]:
    """RDAP query using registered domain (eTLD+1)."""
    try:
        from .domain_classifier import _registered_domain
        reg_domain = _registered_domain(domain)
        return await query_rdap(reg_domain, session,
                                threshold_days=config.new_domain_threshold_days)
    except Exception as e:
        return {"is_new_domain": False, "domain_age_days": None,
                "registrar": None, "error": str(e)}


def _fuse_rating(dns, urlhaus, threatfox, rdap, scam, vt, config) -> Tuple[str, List[str]]:
    """Multi-layer fusion: decide final rating from all layer results."""
    reasons = []

    # Threat intelligence: any positive → malicious
    ti_malicious = (urlhaus.get("malicious") or threatfox.get("malicious")
                    or vt.get("malicious"))
    ti_sources = []
    if urlhaus.get("malicious"):
        ti_sources.append("URLhaus")
    if threatfox.get("malicious"):
        ti_sources.append("ThreatFox")
    if vt.get("malicious"):
        ti_sources.append("VirusTotal")

    if ti_malicious:
        return RATING_MALICIOUS, [f"威胁情报命中 ({'+'.join(ti_sources)})"]

    # DNS: expired or private IP → suspicious
    if dns.get("nxdomain"):
        reasons.append("DNS NXDOMAIN（域名已过期，白名单可能无效）")
        return RATING_SUSPICIOUS, reasons
    if dns.get("ips") and any(_is_private_ip(ip) for ip in dns["ips"]):
        reasons.append(f"解析到私有/回环 IP: {dns['ips']}")
        return RATING_SUSPICIOUS, reasons

    # RDAP: newly registered → suspicious
    if rdap.get("is_new_domain"):
        age = rdap.get("domain_age_days", "?")
        reasons.append(f"新注册域名（{age}天，<{config.new_domain_threshold_days}天阈值）")
        return RATING_SUSPICIOUS, reasons

    # MarketNow scam check → suspicious
    if scam.get("is_suspicious"):
        decision = scam.get("decision", "?")
        score = scam.get("risk_score", 0)
        scam_reasons = scam.get("reasons", [])
        detail = "; ".join(scam_reasons[:2]) if scam_reasons else ""
        reasons.append(
            f"诈骗/钓鱼检测 [{decision}, 风险分{score}]"
            + (f": {detail}" if detail else "")
        )
        return RATING_SUSPICIOUS, reasons

    # DNS failure: never claim "DNS normal"; return unknown if no TI hit.
    dns_error = dns.get("error")
    ti_disabled = (not config.use_urlhaus and not config.use_threatfox
                   and not config.use_virustotal)
    ti_all_errors = (
        (not config.use_urlhaus or urlhaus.get("error") not in (None, "disabled"))
        and (not config.use_threatfox or threatfox.get("error") not in (None, "disabled"))
        and (not config.use_virustotal or vt.get("error") not in (None, "disabled"))
    )
    if dns_error and (ti_disabled or ti_all_errors):
        reasons.append(f"检测不完整：DNS 查询失败 ({dns_error})，威胁情报无有效命中")
        return RATING_UNKNOWN, reasons

    if dns_error:
        reasons.append(f"DNS 查询失败 ({dns_error})，但威胁情报无命中")
        return RATING_UNKNOWN, reasons

    reasons.append("DNS 正常解析，无威胁情报标记")
    return RATING_SAFE, reasons


async def audit_whitelist(
    allows: List[Rule],
    source_names: Optional[Dict[str, str]] = None,
    config: Optional[AuditConfig] = None,
    # Backwards-compat kwargs (deprecated, use config instead)
    concurrency: int = 10,
    use_dns: bool = True,
    use_urlhaus: bool = True,
    use_threatfox: bool = True,
    urlhaus_delay: float = 1.0,
) -> Dict[str, Any]:
    """Audit all domain-based whitelist rules with parallel multi-layer fusion.

    All independent network layers execute concurrently per domain.
    """
    if config is None:
        config = AuditConfig(
            use_dns=use_dns, use_urlhaus=use_urlhaus,
            use_threatfox=use_threatfox, concurrency=concurrency,
            urlhaus_delay=urlhaus_delay,
        )

    source_names = source_names or {}
    targets = [a for a in allows if a.normalized_domain]
    if not targets:
        return {"summary": {"total": 0, "safe": 0, "suspicious": 0,
                            "malicious": 0, "unknown": 0}, "rules": []}

    # ── Shared HTTP session for all network layers ──
    import aiohttp
    sem = asyncio.Semaphore(config.concurrency)
    layer_hits = {"dns_nxdomain": 0, "dns_private_ip": 0, "urlhaus": 0,
                  "threatfox": 0, "rdap_new_domain": 0, "scam_check": 0,
                  "virustotal": 0, "ai_classified": 0}
    # AI budget: limit LLM calls to config.ai_max_domains (cost control)
    ai_budget = [config.ai_max_domains]  # list for nonlocal mutation in nested fn

    async with aiohttp.ClientSession() as session:

        async def _audit_one(rule: Rule, idx: int) -> Dict[str, Any]:
            domain = rule.normalized_domain
            cache_key = f"audit:{domain}"
            cached = _cache_get(cache_key)
            if cached:
                cached = dict(cached)
                cached["sources"] = [source_names.get(s, s) for s in rule.source_ids]
                cached["rule"] = rule.output_raw
                return cached

            async with sem:
                # Layer 6: Offline PSL classification (sync, microseconds)
                category, confidence, cat_reason = classify_domain_with_confidence(domain)

                # ── Layers 1-5: parallel network queries ──
                tasks = []
                task_names = []

                if config.use_dns:
                    tasks.append(_dns_check(domain))
                    task_names.append("dns")

                if config.use_urlhaus or config.use_threatfox:
                    tasks.append(_query_threat_intel(domain, session, idx, config))
                    task_names.append("ti")

                if config.use_rdap:
                    tasks.append(_query_rdap_wrapper(domain, session, config))
                    task_names.append("rdap")

                if config.use_scam_check:
                    tasks.append(query_scam_check(domain, session))
                    task_names.append("scam")

                if config.use_virustotal and config.virustotal_api_key:
                    tasks.append(query_virustotal(
                        domain, config.virustotal_api_key, session))
                    task_names.append("vt")

                # Execute all network layers concurrently
                gathered = await asyncio.gather(*tasks) if tasks else []
                layer_data = dict(zip(task_names, gathered))

                dns = layer_data.get("dns", {"nxdomain": False, "ips": [], "error": "disabled"})
                ti = layer_data.get("ti", ({"malicious": False, "error": "disabled"},
                                           {"malicious": False, "error": "disabled"}))
                urlhaus, threatfox = ti if isinstance(ti, tuple) else (
                    {"malicious": False, "error": "disabled"},
                    {"malicious": False, "error": "disabled"})
                rdap = layer_data.get("rdap", {"is_new_domain": False,
                                               "domain_age_days": None,
                                               "registrar": None, "error": "disabled"})
                scam = layer_data.get("scam", {"is_suspicious": False,
                                               "is_confirmed_scam": False,
                                               "decision": None, "risk_score": 0,
                                               "reasons": [], "error": "disabled"})
                vt = layer_data.get("vt", {"malicious": False, "error": "disabled",
                                           "reputation_score": 0.0,
                                           "malicious_votes": 0})

                # Layer 7: AI classification (only for low confidence, after gather)
                ai_result = {"category": None, "confidence": 0.0,
                             "reason": "", "error": "disabled"}
                if (config.use_ai and config.ai_api_key
                        and confidence < config.ai_min_confidence
                        and ai_budget[0] > 0):
                    ai_budget[0] -= 1
                    try:
                        ai_result = await classify_with_ai(
                            domain, config.ai_api_key, session,
                            base_url=config.ai_base_url,
                            model=config.ai_model,
                        )
                        if ai_result.get("category") and not ai_result.get("error"):
                            category = ai_result["category"]
                            confidence = max(confidence, ai_result["confidence"] * 0.7)
                            cat_reason = f"AI: {ai_result.get('reason', '')}"
                    except Exception as e:
                        ai_result["error"] = str(e)

            # ── Multi-layer fusion ──
            rating, reasons = _fuse_rating(
                dns, urlhaus, threatfox, rdap, scam, vt, config)

            # Track layer hits
            if dns.get("nxdomain"):
                layer_hits["dns_nxdomain"] += 1
            if dns.get("ips") and any(_is_private_ip(ip) for ip in dns["ips"]):
                layer_hits["dns_private_ip"] += 1
            if urlhaus.get("malicious"):
                layer_hits["urlhaus"] += 1
            if threatfox.get("malicious"):
                layer_hits["threatfox"] += 1
            if rdap.get("is_new_domain"):
                layer_hits["rdap_new_domain"] += 1
            if scam.get("is_suspicious"):
                layer_hits["scam_check"] += 1
            if vt.get("malicious"):
                layer_hits["virustotal"] += 1
            if ai_result.get("category") and not ai_result.get("error"):
                layer_hits["ai_classified"] += 1

            result = {
                "domain": domain,
                "rule": rule.output_raw,
                "sources": [source_names.get(s, s) for s in rule.source_ids],
                "rating": rating,
                "category": category,
                "category_confidence": round(confidence, 2),
                "category_reason": cat_reason,
                "reason": "; ".join(reasons),
                "dns_ips": dns.get("ips", []),
                "dns_nxdomain": dns.get("nxdomain", False),
                "urlhaus_malicious": urlhaus.get("malicious", False),
                "threatfox_malicious": threatfox.get("malicious", False),
                "rdap_new_domain": rdap.get("is_new_domain", False),
                "rdap_domain_age_days": rdap.get("domain_age_days"),
                "rdap_registrar": rdap.get("registrar"),
                "scam_suspicious": scam.get("is_suspicious", False),
                "scam_decision": scam.get("decision"),
                "scam_risk_score": scam.get("risk_score", 0),
                "virustotal_malicious": vt.get("malicious", False),
                "virustotal_reputation": vt.get("reputation_score", 0.0),
                "ai_classified": ai_result.get("category") is not None and not ai_result.get("error"),
            }
            _cache_set(cache_key, {k: v for k, v in result.items()
                                   if k not in ("sources", "rule")})
            return result

        tasks = [_audit_one(r, i) for i, r in enumerate(targets)]
        results = await asyncio.gather(*tasks)

    # ── summary ──
    summary = {"total": len(results), "safe": 0, "suspicious": 0,
               "malicious": 0, "unknown": 0}
    all_categories = []
    for r in results:
        summary[r["rating"]] += 1
        all_categories.append(r["category"])
    summary["category_counts"] = category_counts(all_categories)
    summary["by_rating"] = {}
    for rating in (RATING_SAFE, RATING_SUSPICIOUS, RATING_MALICIOUS, RATING_UNKNOWN):
        cats = [r["category"] for r in results if r["rating"] == rating]
        summary["by_rating"][rating] = category_counts(cats)
    conf_buckets = {"high(>=0.9)": 0, "medium(0.6-0.89)": 0, "low(<0.6)": 0}
    for r in results:
        c = r.get("category_confidence", 0)
        if c >= 0.9:
            conf_buckets["high(>=0.9)"] += 1
        elif c >= 0.6:
            conf_buckets["medium(0.6-0.89)"] += 1
        else:
            conf_buckets["low(<0.6)"] += 1
    summary["category_confidence"] = conf_buckets
    summary["layer_hits"] = layer_hits
    summary["layers_enabled"] = {
        "dns": config.use_dns,
        "urlhaus": config.use_urlhaus,
        "threatfox": config.use_threatfox,
        "rdap": config.use_rdap,
        "scam_check": config.use_scam_check,
        "virustotal": config.use_virustotal,
        "ai": config.use_ai,
    }
    summary["execution_mode"] = "parallel"

    order = {RATING_MALICIOUS: 0, RATING_SUSPICIOUS: 1,
             RATING_UNKNOWN: 2, RATING_SAFE: 3}
    results.sort(key=lambda r: (order.get(r["rating"], 9), r["domain"]))

    return {"summary": summary, "rules": results}
