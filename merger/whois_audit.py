"""V5 RDAP-based domain registration audit (free, no API key).

Uses the Registration Data Access Protocol (RDAP, RFC 7480) to fetch domain
registration information — the modern, RESTful replacement for WHOIS.
RDAP is free, keyless, and returns structured JSON.

Endpoint: https://rdap.org/domain/{registered_domain}

Key signals extracted:
  - registration_date: when the domain was first registered
  - domain_age_days: current age in days
  - registrar: registration service provider
  - is_new_domain: True if age < 30 days (higher phishing risk)
  - expires_at: expiry date (recently expired = suspicious)

Newly registered domains (< 30 days) are flagged as suspicious because
phishing domains are often short-lived.  This is an auxiliary signal, not
a definitive malicious indicator — it feeds into the multi-source fusion
engine in whitelist_audit.py.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

RDAP_BASE = "https://rdap.org/domain/"

# Domains younger than this are flagged as "new" (higher risk)
NEW_DOMAIN_THRESHOLD_DAYS = 30


def _parse_iso_date(date_str: str) -> Optional[datetime]:
    """Parse ISO 8601 date from RDAP (handles timezone offsets and 'Z')."""
    if not date_str:
        return None
    try:
        # RDAP dates look like "2020-01-15T00:00:00Z" or "...+00:00"
        s = date_str.replace("Z", "+00:00")
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None


def parse_rdap_response(data: Dict[str, Any],
                        threshold_days: int = NEW_DOMAIN_THRESHOLD_DAYS) -> Dict[str, Any]:
    """Extract registration signals from an RDAP JSON response.

    Returns dict with: registration_date, domain_age_days, registrar,
    is_new_domain, expires_at, error.
    """
    result = {
        "registration_date": None,
        "domain_age_days": None,
        "registrar": None,
        "is_new_domain": False,
        "expires_at": None,
        "error": None,
    }

    if not data or not isinstance(data, dict):
        result["error"] = "empty response"
        return result

    # RDAP error responses have notFound / errorCode
    if data.get("errorCode") or data.get("notFound"):
        result["error"] = f"RDAP error: {data.get('title', 'not found')}"
        return result

    # Events array contains registration / expiration dates
    events = data.get("events", [])
    reg_date = None
    exp_date = None
    for ev in events:
        action = ev.get("eventAction", "")
        date_str = ev.get("eventDate", "")
        if action == "registration":
            reg_date = _parse_iso_date(date_str)
        elif action in ("expiration", "expiry"):
            exp_date = _parse_iso_date(date_str)

    # Registrar info (may be in entities with vcardArray)
    registrar = None
    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        if "registrar" in roles:
            vcard = entity.get("vcardArray", [])
            if len(vcard) > 1:
                for item in vcard[1]:
                    if isinstance(item, list) and len(item) > 2 and item[0] == "fn":
                        registrar = item[3]
                        break
            if not registrar:
                registrar = entity.get("handle")
            break

    now = datetime.now(timezone.utc)
    if reg_date:
        age = (now - reg_date).days
        result["registration_date"] = reg_date.isoformat()
        result["domain_age_days"] = age
        result["is_new_domain"] = age < threshold_days
    if exp_date:
        result["expires_at"] = exp_date.isoformat()
    result["registrar"] = registrar

    return result


async def query_rdap(domain: str, session, timeout: int = 10,
                     threshold_days: int = NEW_DOMAIN_THRESHOLD_DAYS) -> Dict[str, Any]:
    """Query RDAP for a domain's registration data.

    Args:
        domain: registered domain (eTLD+1), e.g. "example.com"
        session: aiohttp.ClientSession
        timeout: request timeout in seconds

    Returns:
        Dict with registration signals (see parse_rdap_response).
    """
    url = f"{RDAP_BASE}{domain}"
    try:
        headers = {"User-Agent": "AdGuard-Rules-Merger/5.0 (rdap-audit)"}
        async with session.get(url, headers=headers, timeout=timeout) as resp:
            if resp.status == 404:
                return {"error": "domain not found in RDAP",
                        "is_new_domain": False, "domain_age_days": None}
            if resp.status != 200:
                return {"error": f"HTTP {resp.status}",
                        "is_new_domain": False, "domain_age_days": None}
            data = await resp.json(content_type=None)
            return parse_rdap_response(data, threshold_days)
    except Exception as e:
        return {"error": str(e), "is_new_domain": False, "domain_age_days": None}
