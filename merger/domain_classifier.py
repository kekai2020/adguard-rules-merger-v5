"""V5 domain classifier — categorize whitelist domains by purpose.

Uses tldextract (Public Suffix List) for precise registered-domain extraction,
then matches against:
  1. Exact registered-domain patterns (e.g. "doubleclick.net" → advertising)
  2. Subdomain label prefixes (e.g. "ads." → advertising, "cdn." → cdn)
  3. Known brand domains (e.g. "microsoft.com" → microsoft_telemetry)

This avoids the pitfalls of naive substring matching:
  - "apple-pay.com" will NOT match "apple" (we match registered domain, not FQDN)
  - "evil-company.com" is correctly parsed as registered="evil-company.com",
    not as a subdomain of "company.com"

Categories:
  advertising        — ad networks / demand-side platforms
  analytics          — site analytics / tracking / performance monitoring
  cdn                — content delivery / static asset hosting
  microsoft_telemetry — Windows / Office / Azure telemetry & connectivity
  affiliate          — affiliate marketing / link redirect / attribution
  social             — social media platforms & share widgets
  ecommerce_payment  — payment gateways / checkout / shopping
  privacy_security   — privacy tools / security / VPN / encrypted comms
  other              — unclassified

The classifier is conservative and offline (no API key required).  External
classification APIs (Web Filtering DB, VirusTotal, LLM) can be layered on top
by the caller — see whitelist_audit.py for the multi-source fusion logic.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

import tldextract

# ── tldextract instance (offline PSL, no network calls) ────────────
_extract = tldextract.TLDExtract(suffix_list_urls=())

# ── category definitions ───────────────────────────────────────────
# Each entry: (category, [registered-domain patterns])
# Patterns are matched against the registered domain (eTLD+1) exactly,
# OR as a suffix of the registered domain (e.g. "doubleclick.net" matches
# "doubleclick.net" but NOT "evildoubleclick.net").
REGISTERED_DOMAIN_RULES: List[Tuple[str, List[str]]] = [
    ("cdn", [
        "cloudfront.net", "akamai.net", "akamaiedge.net", "akamaized.net",
        "akamaitechnologies.com", "edgekey.net", "edgesuite.net",
        "cloudflare.com", "cdnjs.cloudflare.com", "jsdelivr.net",
        "unpkg.com", "bunny.net", "b-cdn.net", "cdn77.com", "keycdn.com",
        "stackpathdns.com", "maxcdn.com", "netdna.com", "netdna-cdn.com",
        "azureedge.net", "msecnd.net", "aspnetcdn.com", "ajaxcdn.com",
        "bootcdn.net", "staticfile.org", "statically.io", "fastly.net",
        "fastlylb.net", "360cdn.com", "bdstatic.com", "bdydns.com",
        "alicdn.com", "alipayobjects.com", "mmstat.com", "taobaocdn.com",
        "tbcache.com", "gtimg.com", "hotmailcdn.com", "qqcdn.com",
        "qpic.cn", "weibocdn.com", "sinaimg.cn", "sinaimg.com",
        "hdslb.com", "bilivideo.com", "acgvideo.com", "upaiyun.com",
        "qiniu.com", "qbox.me", "clouddn.com", "ufile.io",
        "myqcloud.com", "volccdn.com", "bytecdn.com", "bytedance.com",
        "pstatp.com", "ixigua.com", "snssdk.com", "toutiao.com",
    ]),
    ("advertising", [
        "doubleclick.net", "doubleclick.com", "googleadservices.com",
        "2mdn.net", "adnxs.com", "criteo.com", "pubmatic.com",
        "rubiconproject.com", "openx.net", "openx.org", "indexww.com",
        "zemanta.com", "adform.net", "adform.com", "advertising.com",
        "taboola.com", "outbrain.com", "adcolony.com", "applovin.com",
        "unityads.unity3d.com", "vungle.com", "ironsrc.com",
        "mopub.com", "mintegral.com", "chartboost.com", "inmobi.com",
        "smaato.com", "liftoff.io", "jampp.com", "kayzen.io",
        "adk2.co", "adwolf.ru", "adsrvmedia.com", "adserver.com",
        "adtech.de", "adzerk.net", "kevel.com", "preroll.com",
        "videoplaza.tv", "spotxchange.com", "spotx.tv", "freewheel.tv",
        "comscore.com", "scorecardresearch.com", "quantserve.com",
        "exelator.com", "ipredictive.com", "tribalfusion.com",
        "adblade.com", "contentad.net", "mgid.com", "revcontent.com",
        "nativo.com", "sharethrough.com", "districtm.io",
        "conversantmedia.com", "teads.tv", "readpeak.com",
        "myvisualiq.com", "simpli.fi", "mediamath.com",
        "thetradedesk.com", "liveramp.com", "acxiom.com",
        "equifax.com", "experian.com", "transunion.com",
    ]),
    ("analytics", [
        "google-analytics.com", "googletagmanager.com", "gtag.com",
        "amplitude.com", "mixpanel.com", "statcounter.com",
        "hotjar.com", "fullstory.com", "heap.io", "segment.com",
        "segment.io", "kissmetrics.com", "crazyegg.com",
        "mouseflow.com", "luckyorange.com", "inspectlet.com",
        "sessioncam.com", "chartbeat.com", "parse.ly",
        "newrelic.com", "datadoghq.com", "datadog.com",
        "sentry.io", "rollbar.com", "bugsnag.com", "raygun.com",
        "trackjs.com", "posthog.com", "logrocket.com",
        "smartlook.com", "plausible.io", "usefathom.com",
        "simpleanalytics.com", "goatcounter.com", "umami.is",
        "shynet.com", "matomo.org", "piwik.org", "clicky.com",
        "woopra.com", "gosquared.com", "foxmetrics.com",
        "decibel.com", "contentsquare.com", "adobedtm.com",
        "demdex.net", "omtrdc.net", "2o7.net", "ibm.com",
    ]),
    ("microsoft_telemetry", [
        "microsoft.com", "windows.com", "live.com", "office.com",
        "office365.com", "msecnd.net", "visualstudio.com",
        "azure.com", "azure.net", "bing.com", "msn.com",
        "skype.com", "xboxlive.com", "microsoftonline.com",
        "windows.net", "microsoftstore.com", "microsofttranslator.com",
        "microsoftedge.net", "msedge.net", "msftncsi.com",
        "msftconnecttest.com", "office.net", "sharepoint.com",
        "onenote.com", "outlook.com", "hotmail.com",
        "microsoft-todo.com", "microsoft365.com", "m365.com",
        "microsoftcloud.com", "microsoftapp.net", "vsassets.io",
        "core.windows.net", "blob.core.windows.net",
    ]),
    ("affiliate", [
        "awin1.com", "rakuten.com", "tradedoubler.com",
        "cj.com", "commissionjunction.com", "impactradius.com",
        "partnerize.com", "revenuewire.com", "clickbank.com",
        "shareasale.com", "flexoffers.com", "pepperjam.com",
        "webgains.com", "avantlink.com", "viglink.com",
        "skimlinks.com", "geni.us", "amzn.to", "amzn.com",
        "amazon-adsystem.com", "associates.amazon.com",
        "redirectingat.com", "link.awin.com", "linktr.ee",
        "linktree.com", "beacons.ai", "campsite.bio",
        "lnk.bio", "shor.by", "tap.bio", "msha.ke",
        "allmylinks.com", "disq.us", "bit.ly", "ow.ly",
        "buff.ly", "goo.gl", "tinyurl.com", "t.co",
        "fb.me", "lnkd.in", "pin.it", "redd.it", "youtu.be",
        "amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr",
        "amazon.co.jp", "amazon.ca", "amazon.com.au",
        "amazon.in", "amazon.es", "amazon.it", "amazon.com.mx",
        "amazon.com.br", "amazon.nl", "amazon.pl", "amazon.se",
        "amazon.sg", "amazon.ae", "amazon.sa", "amazon.eg",
    ]),
    ("social", [
        "facebook.com", "facebook.net", "fbcdn.net", "fb.com",
        "fb.me", "instagram.com", "cdninstagram.com",
        "twitter.com", "twimg.com", "x.com", "linkedin.com",
        "licdn.com", "pinterest.com", "pinimg.com",
        "tiktok.com", "tiktokcdn.com", "snapchat.com",
        "reddit.com", "redd.it", "tumblr.com", "weibo.com",
        "weibocdn.com", "sinaimg.cn", "qq.com", "qpic.cn",
        "weixin.qq.com", "wechat.com", "douyin.com",
        "kuaishou.com", "bilibili.com", "b23.tv", "acfun.cn",
        "zhihu.com", "zhimg.com", "xiaohongshu.com",
        "xhslink.com", "telegram.org", "t.me", "discord.com",
        "discordapp.com", "discord.gg", "slack.com",
        "slack-edge.com", "whatsapp.com", "wa.me",
        "signal.org", "threads.net", "mastodon.social",
        "misskey.io", "pleroma.site", "vk.com", "ok.ru",
        "mail.ru", "yandex.ru", "zen.yandex.ru", "habr.com",
        "pikabu.ru", "vimeo.com", "youtube.com", "ytimg.com",
        "googlevideo.com", "youtu.be", "twitch.tv", "ttvnw.net",
        "jtvnw.net", "kick.com", "rumble.com", "odysee.com",
        "lbry.com", "flickr.com", "imgur.com", "giphy.com",
        "tenor.com", "gfycat.com", "redgifs.com", "imgflip.com",
    ]),
    ("ecommerce_payment", [
        "paypal.com", "paypalobjects.com", "stripe.com",
        "stripe.network", "braintreepayments.com", "authorize.net",
        "adyen.com", "checkout.com", "worldpay.com", "sagepay.com",
        "opayo.com", "klarna.com", "afterpay.com", "affirm.com",
        "sezzle.com", "quadpay.com", "zip.co", "alipay.com",
        "alipayobjects.com", "tenpay.com",
        "unionpay.com", "95516.com", "jdpay.com",
        "shopify.com", "myshopify.com", "shopifycdn.com",
        "bigcommerce.com", "woocommerce.com", "magento.com",
        "ebay.com", "ebaystatic.com", "etsy.com",
        "aliexpress.com", "alibabausercontent.com",
        "taobao.com", "tmall.com", "jd.com", "jd.hk",
        "pinduoduo.com", "yangkeduo.com", "suning.com",
        "gome.com.cn", "vip.com", "meituan.com", "dianping.com",
        "ele.me", "costco.com", "walmart.com", "target.com",
        "bestbuy.com", "home-depot.com", "lowes.com",
        "macys.com", "nordstrom.com", "zara.com",
        "shein.com", "asos.com", "boohoo.com",
    ]),
    ("privacy_security", [
        "adguard.com", "adguard-dns.com", "privacy.com",
        "security.com", "encrypt.com", "vpn.com",
        "torproject.org", "protonmail.com", "proton.me",
        "protonvpn.com", "signal.org", "duckduckgo.com",
        "startpage.com", "brave.com", "ghostery.com",
        "ublock.org", "noscript.net", "eff.org",
        "letsencrypt.org", "mozilla.org", "thunderbird.net",
        "tails.net", "whonix.org", "qubes-os.org",
        "keepass.info", "bitwarden.com", "1password.com",
        "lastpass.com", "dashlane.com", "vaultwarden.net",
        "wireguard.com", "openvpn.net", "strongswan.org",
        "cloudflare.com", "cloudflaressl.com", "quad9.net",
        "opendns.com", "cleanbrowsing.org", "nextdns.io",
        "controld.com", "dnscrypt.info", "dns.watch",
        "libredns.gr", "digitale-gesellschaft.ch",
        "malwarebytes.com", "bitdefender.com", "kaspersky.com",
        "norton.com", "mcafee.com", "eset.com", "avast.com",
        "avg.com", "avira.com", "sophos.com", "trendmicro.com",
        "paloaltonetworks.com", "fortinet.com", "checkpoint.com",
        "virustotal.com", "urlhaus.abuse.ch", "abuse.ch",
        "spamhaus.org", "surbl.org", "uribl.com", "spamcop.net",
        "threatfox.abuse.ch", "malware-filter.gitlab.io",
    ]),
]

# ── subdomain label prefixes (first label of subdomain) ────────────
# e.g. "ads.example.com" → first label "ads" → advertising
# These are applied only when registered-domain matching fails.
SUBDOMAIN_PREFIX_RULES: List[Tuple[str, List[str]]] = [
    ("advertising", ["ads", "ad", "advert", "adv", "banner", "banners",
                     "creative", "creatives", "impression", "impressions",
                     "pixel", "pixels", "tracker", "trackers",
                     "serving", "ssp", "dsp", "exchange", "rtb", "bid",
                     "bidding", "tag", "tags"]),
    ("analytics", ["analytics", "analytic", "metrics", "metric", "stats",
                   "stat", "telemetry", "monitor", "monitoring", "logging",
                   "log", "logs", "events", "event", "collect", "collector",
                   "ingest", "ingestion", "trace", "tracing", "report",
                   "reports", "dashboard", "insights"]),
    ("cdn", ["cdn", "static", "assets", "asset", "img", "images", "image",
             "media", "files", "file", "content", "contents", "resource",
             "resources", "download", "downloads", "cache", "caching",
             "edge", "edges", "proxy", "proxies", "mirror", "mirrors"]),
    ("affiliate", ["affiliate", "aff", "partner", "partners", "ref",
                   "referral", "refer", "click", "clicks", "redirect",
                   "redirects", "go", "link", "links"]),
    ("ecommerce_payment", ["shop", "store", "cart", "checkout", "payment",
                           "pay", "order", "orders", "billing", "buy",
                           "purchase", "product", "products", "catalog",
                           "inventory", "price", "pricing"]),
    ("social", ["social", "share", "shares", "like", "likes", "follow",
                "follows", "comment", "comments", "post", "posts",
                "feed", "feeds", "timeline", "profile", "profiles"]),
]

CATEGORY_LABELS: Dict[str, str] = {
    "advertising": "广告/营销",
    "analytics": "分析/追踪",
    "cdn": "CDN/基础设施",
    "microsoft_telemetry": "微软/Windows 遥测",
    "affiliate": "联盟营销/跳转",
    "social": "社交/分享",
    "ecommerce_payment": "电商/支付",
    "privacy_security": "隐私/安全",
    "other": "其他",
}

CATEGORY_ORDER = [
    "advertising", "analytics", "cdn", "microsoft_telemetry",
    "affiliate", "social", "ecommerce_payment", "privacy_security", "other",
]

# Confidence levels for different match types
CONFIDENCE_REGISTERED = 0.9   # exact registered-domain match
CONFIDENCE_SUBDOMAIN = 0.6    # subdomain prefix match
CONFIDENCE_NONE = 0.0


def _registered_domain(domain: str) -> str:
    """Extract registered domain (eTLD+1) using PSL."""
    ext = _extract(domain)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return domain.lower().strip(".")


def _first_subdomain_label(domain: str) -> str:
    """Return the first label of the subdomain, or '' if none."""
    ext = _extract(domain)
    if ext.subdomain:
        return ext.subdomain.split(".")[0].lower()
    return ""


def classify_domain(domain: str,
                    cname_hints: Optional[List[str]] = None
                    ) -> str:
    """Classify a domain by purpose. Returns category string.

    Matching priority:
      1. Registered-domain exact/suffix match (high confidence)
      2. Subdomain first-label prefix match (medium confidence)
      3. CNAME hints (if provided)
      4. Fallback to "other"
    """
    return classify_domain_with_confidence(domain, cname_hints)[0]


def classify_domain_with_confidence(
    domain: str,
    cname_hints: Optional[List[str]] = None,
) -> Tuple[str, float, str]:
    """Classify with confidence score and match reason.

    Returns (category, confidence, reason).
    """
    domain = domain.lower().strip(".")
    if not domain:
        return "other", CONFIDENCE_NONE, "empty domain"

    registered = _registered_domain(domain)
    first_label = _first_subdomain_label(domain)

    # 1. Registered-domain match
    for category, patterns in REGISTERED_DOMAIN_RULES:
        for pat in patterns:
            # exact match or suffix match (registered domain ends with pattern)
            if registered == pat or registered.endswith("." + pat):
                return (category, CONFIDENCE_REGISTERED,
                        f"registered domain match: {pat}")

    # 2. Subdomain prefix match
    if first_label:
        for category, prefixes in SUBDOMAIN_PREFIX_RULES:
            if first_label in prefixes:
                return (category, CONFIDENCE_SUBDOMAIN,
                        f"subdomain prefix: {first_label}")

    # 3. CNAME hints (e.g. domain CNAMEs to cloudfront)
    if cname_hints:
        for hint in cname_hints:
            cat, conf, _ = classify_domain_with_confidence(hint)
            if cat != "other" and conf >= CONFIDENCE_SUBDOMAIN:
                return (cat, conf * 0.8, f"cname hint: {hint}")

    return "other", CONFIDENCE_NONE, "no match"


def classify_batch(domains: List[str],
                   cname_map: Optional[Dict[str, List[str]]] = None
                   ) -> Dict[str, str]:
    """Classify many domains at once. Returns {domain: category}."""
    cname_map = cname_map or {}
    return {d: classify_domain(d, cname_map.get(d)) for d in domains}


def category_counts(categories: List[str]) -> Dict[str, int]:
    """Count occurrences per category, including zero-count categories."""
    counts = {c: 0 for c in CATEGORY_ORDER}
    for c in categories:
        counts[c] = counts.get(c, 0) + 1
    return counts
