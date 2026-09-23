"""V5 professional analysis report generator.

Generates a self-contained HTML report and a Markdown report after each merge:
  - Executive summary, optimization funnel
  - Rule type / category distribution (ECharts)
  - Top domain suffixes
  - Per-source contribution table (unique vs shared)
  - V5: $ modifier distribution
  - V5: pairwise source overlap matrix (top overlaps + coverage rates)
  - Failed source warnings, diff summary
  - Performance metrics, grammar coverage matrix
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from typing import Any, Dict, List

from .models import Rule
from .domain_classifier import CATEGORY_ORDER, CATEGORY_LABELS


def _classify_rule(rule: Rule) -> str:
    if rule.normalized_domain == "":
        return "regex"
    if rule.wildcard:
        return "wildcard"
    parts = rule.normalized_domain.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return "ip"
    return "domain"


def _extract_suffix(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) < 2:
        return domain
    second_level_cc = {"co", "com", "net", "org", "gov", "edu"}
    if len(parts) >= 3 and parts[-2] in second_level_cc and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def analyze_rules(blocks: List[Rule], allows: List[Rule]) -> Dict[str, Any]:
    all_rules = blocks + allows
    type_counts = Counter(_classify_rule(r) for r in all_rules)
    cat_counts = Counter(r.category for r in blocks)
    suffix_counts = Counter()
    domain_lengths = []
    for r in blocks:
        if r.normalized_domain:
            suffix_counts[_extract_suffix(r.normalized_domain)] += 1
            domain_lengths.append(len(r.normalized_domain))
    return {
        "rule_types": dict(type_counts),
        "categories": dict(cat_counts),
        "top_suffixes": suffix_counts.most_common(20),
        "allow_types": dict(Counter(_classify_rule(r) for r in allows)),
        "avg_domain_length": sum(domain_lengths) / len(domain_lengths) if domain_lengths else 0,
        "max_domain_length": max(domain_lengths) if domain_lengths else 0,
        "min_domain_length": min(domain_lengths) if domain_lengths else 0,
    }


# ── shared helpers ────────────────────────────────────────────────

def _modifier_total(modifier_stats: Dict[str, int]) -> int:
    return sum(modifier_stats.values())


def _overlap_heat_color(rate: float) -> str:
    """Return a background color for an overlap rate (0-100)."""
    if rate >= 80:
        return "#f8d7da"
    if rate >= 50:
        return "#fff3cd"
    if rate >= 20:
        return "#d1ecf1"
    return "#d4edda"


# ── HTML report ───────────────────────────────────────────────────

def generate_html_report(blocks, allows, outcome, analysis) -> str:
    now = datetime.now()
    generated_at = now.isoformat()
    total_block = len(blocks)
    total_allow = len(allows)
    raw_count = outcome.raw_count
    dedup_rate = (1 - (total_block + total_allow) / raw_count) * 100 if raw_count else 0
    cats = analysis["categories"]
    top_suffix_labels = [s[0] for s in analysis["top_suffixes"]]
    top_suffix_values = [s[1] for s in analysis["top_suffixes"]]
    rt = analysis["rule_types"]
    domain_count = rt.get("domain", 0)
    wildcard_count = rt.get("wildcard", 0)
    regex_count = rt.get("regex", 0)
    ip_count = rt.get("ip", 0)
    modifier_stats = getattr(outcome, "modifier_stats", {}) or {}
    modifier_total = _modifier_total(modifier_stats)
    source_overlap = getattr(outcome, "source_overlap", {}) or {}
    overlap_pairs = source_overlap.get("pairs", [])
    source_effective = source_overlap.get("source_effective", {})

    # contribution rows
    contrib_rows = ""
    for c in getattr(outcome, "contributions", [])[:25]:
        total_c = c["unique_rules"] + c["shared_rules"]
        ratio = (c["unique_rules"] / total_c * 100) if total_c else 0
        contrib_rows += (
            f"<tr><td>{c['name']}</td><td>{c['raw_rules']:,}</td>"
            f"<td>{c['unique_rules']:,}</td><td>{c['shared_rules']:,}</td>"
            f"<td>{ratio:.0f}%</td></tr>\n"
        )

    # V5: modifier rows
    modifier_rows = ""
    if modifier_stats:
        for mod, cnt in modifier_stats.items():
            pct = cnt / modifier_total * 100 if modifier_total else 0
            modifier_rows += (
                f"<tr><td><code>${mod}</code></td><td>{cnt:,}</td>"
                f"<td>{pct:.1f}%</td></tr>\n"
            )
    else:
        modifier_rows = '<tr><td colspan="3" style="text-align:center;color:#999">无带修饰符规则</td></tr>'

    # V5: conflict rows (multi-source)
    conflict_rows = ""
    conflicts = getattr(outcome, "conflicts", []) or []
    for c in conflicts[:50]:
        blocked_srcs = ", ".join(c.get("blocked_sources", [])) or c.get("source", "-")
        allow_srcs = ", ".join(c.get("whitelist_sources", [])) or "-"
        ctype = c.get("conflict_type", "exact")
        ctype_tag = "级联" if ctype == "cascade" else "精确"
        conflict_rows += (
            f"<tr><td><code>{c.get('domain', '')}</code></td>"
            f"<td><code>{c.get('blocked_rule', '')}</code></td>"
            f"<td>{blocked_srcs}</td>"
            f"<td><code>{c.get('whitelist_rule', '')}</code></td>"
            f"<td>{allow_srcs}</td>"
            f"<td><span class='tag tag-yellow'>{ctype_tag}</span></td></tr>\n"
        )
    if not conflict_rows:
        conflict_rows = '<tr><td colspan="6" style="text-align:center;color:#999">无冲突</td></tr>'

    # V5: whitelist audit rows
    whitelist_audit = getattr(outcome, "whitelist_audit", {}) or {}
    audit_summary = whitelist_audit.get("summary", {})
    audit_rules = whitelist_audit.get("rules", [])
    audit_rows = ""
    rating_tag = {
        "malicious": "tag-red", "suspicious": "tag-yellow",
        "safe": "tag-green", "unknown": "tag-blue",
    }
    rating_label = {
        "malicious": "🔴 恶意", "suspicious": "🟡 可疑",
        "safe": "🟢 安全", "unknown": "⚪ 未知",
    }
    for r in audit_rules:
        tag_cls = rating_tag.get(r["rating"], "tag-blue")
        label = rating_label.get(r["rating"], r["rating"])
        cat_label = CATEGORY_LABELS.get(r.get("category", "other"), r.get("category", "other"))
        conf = r.get("category_confidence", 0)
        conf_cls = "tag-green" if conf >= 0.9 else ("tag-yellow" if conf >= 0.6 else "tag-blue")
        audit_rows += (
            f"<tr><td><code>{r['domain']}</code></td>"
            f"<td><span class='tag {tag_cls}'>{label}</span></td>"
            f"<td>{cat_label}</td>"
            f"<td><span class='tag {conf_cls}'>{conf:.2f}</span></td>"
            f"<td>{r['reason']}</td>"
            f"<td>{', '.join(r.get('sources', []))}</td></tr>\n"
        )
    if not audit_rows and whitelist_audit:
        audit_rows = '<tr><td colspan="6" style="text-align:center;color:#999">白名单审计未启用或无域名规则</td></tr>'

    # V5: whitelist category distribution rows
    cat_counts = audit_summary.get("category_counts", {})
    cat_rows = ""
    if cat_counts:
        total_cat = sum(cat_counts.values()) or 1
        for cat in CATEGORY_ORDER:
            cnt = cat_counts.get(cat, 0)
            if cnt == 0:
                continue
            pct = cnt / total_cat * 100
            label = CATEGORY_LABELS.get(cat, cat)
            cat_rows += (
                f"<tr><td>{label}</td><td>{cnt}</td>"
                f"<td><div class='bar-bg'><div class='bar-fill' style='width:{pct:.1f}%'></div></div></td>"
                f"<td>{pct:.1f}%</td></tr>\n"
            )
    if not cat_rows:
        cat_rows = '<tr><td colspan="4" style="text-align:center;color:#999">分类统计不可用</td></tr>'

    # V5: classification confidence distribution
    conf_dist = audit_summary.get("category_confidence", {})
    conf_rows = ""
    if conf_dist:
        total_conf = sum(conf_dist.values()) or 1
        for level in ("high(>=0.9)", "medium(0.6-0.89)", "low(<0.6)"):
            cnt = conf_dist.get(level, 0)
            pct = cnt / total_conf * 100
            label = {"high(>=0.9)": "高置信度 (注册域名匹配)",
                     "medium(0.6-0.89)": "中置信度 (子域名前缀)",
                     "low(<0.6)": "低置信度 (无法分类)"}.get(level, level)
            conf_rows += (
                f"<tr><td>{label}</td><td>{cnt}</td>"
                f"<td><div class='bar-bg'><div class='bar-fill' style='width:{pct:.1f}%'></div></div></td>"
                f"<td>{pct:.1f}%</td></tr>\n"
            )

    # V5: multi-layer defense overview
    layers_enabled = audit_summary.get("layers_enabled", {})
    layer_hits = audit_summary.get("layer_hits", {})
    layer_rows = ""
    if layers_enabled:
        layer_info = [
            ("dns", "DNS 解析", "NXDOMAIN/私有IP检测", "免费"),
            ("urlhaus", "URLhaus", "恶意软件分发域名", "免费"),
            ("threatfox", "ThreatFox", "C2 命令控制域名", "免费"),
            ("rdap", "RDAP 域名年龄", "新注册域名<30天标记", "免费"),
            ("scam_check", "MarketNow 诈骗检测", "拼写劫持/可疑TLD/未注册", "免费"),
            ("virustotal", "VirusTotal", "多引擎厂商信誉", "需API Key"),
            ("ai", "AI/LLM 分类", "低置信度域名语义分类", "需API Key"),
        ]
        for key, name, desc, cost in layer_info:
            enabled = layers_enabled.get(key, False)
            if key == "dns":
                hits = layer_hits.get("dns_nxdomain", 0) + layer_hits.get("dns_private_ip", 0)
            else:
                hits = layer_hits.get(key, 0)
            status = "✅ 启用" if enabled else "⬜ 未启用"
            status_cls = "tag-green" if enabled else "tag-blue"
            layer_rows += (
                f"<tr><td>{name}</td><td>{desc}</td>"
                f"<td><span class='tag {status_cls}'>{status}</span></td>"
                f"<td>{cost}</td><td>{hits if enabled else '-'}</td></tr>\n"
            )

    # V5: source effective coverage rows (raw vs effective vs self-dedup rate)
    effective_rows = ""
    contributions = getattr(outcome, "contributions", [])
    contrib_by_name = {c["name"]: c for c in contributions}
    for name, eff in source_effective.items():
        c = contrib_by_name.get(name, {})
        raw = c.get("raw_rules", 0)
        self_dedup = (1 - eff / raw) * 100 if raw else 0
        effective_rows += (
            f"<tr><td>{name}</td><td>{raw:,}</td><td>{eff:,}</td>"
            f"<td>{self_dedup:.1f}%</td></tr>\n"
        )

    # V5: top overlap pairs (top 20)
    overlap_rows = ""
    for p in overlap_pairs[:20]:
        bg_a = _overlap_heat_color(p["rate_a"])
        bg_b = _overlap_heat_color(p["rate_b"])
        overlap_rows += (
            f"<tr><td>{p['source_a']}</td><td>{p['source_b']}</td>"
            f"<td>{p['overlap']:,}</td>"
            f"<td style='background:{bg_a}'>{p['rate_a']:.1f}%</td>"
            f"<td style='background:{bg_b}'>{p['rate_b']:.1f}%</td></tr>\n"
        )
    if not overlap_rows:
        overlap_rows = '<tr><td colspan="5" style="text-align:center;color:#999">无源间重复</td></tr>'

    failed_html = ""
    if outcome.failed_sources:
        items = "".join(f"<li><b>{f['name']}</b> — {f['error']}</li>" for f in outcome.failed_sources)
        failed_html = f'<div class="section" style="border-left:4px solid #dc3545"><h2>⚠️ 失败源 ({len(outcome.failed_sources)})</h2><ul>{items}</ul></div>'

    after_exact = raw_count - outcome.exact_merged - outcome.normalized_merged - outcome.regex_merged
    after_agg = after_exact - outcome.aggregated - outcome.wildcard_aggregated - outcome.wildcard_promoted

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AdGuard Rules Merger V5 - 规则分析报告</title>
<script src="https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js"></script>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:#f5f7fa; color:#333; line-height:1.6; }}
.container {{ max-width:1280px; margin:0 auto; padding:20px; }}
.header {{ background:linear-gradient(135deg,#0f4c75 0%,#3282b8 100%); color:#fff; padding:40px; border-radius:12px; margin-bottom:30px; }}
.header h1 {{ font-size:2.2em; margin-bottom:8px; }}
.header .subtitle {{ opacity:.9; font-size:1.1em; }}
.header .meta {{ margin-top:15px; font-size:.9em; opacity:.8; }}
.stats-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:16px; margin-bottom:30px; }}
.stat-card {{ background:#fff; padding:20px; border-radius:10px; box-shadow:0 2px 8px rgba(0,0,0,.06); text-align:center; }}
.stat-card .value {{ font-size:1.7em; font-weight:700; color:#3282b8; }}
.stat-card .label {{ color:#666; font-size:.82em; margin-top:4px; }}
.bar-bg {{ background:#eef2f7; border-radius:4px; height:18px; overflow:hidden; min-width:80px; }}
.bar-fill {{ background:linear-gradient(90deg,#3282b8,#5ba3d9); height:100%; border-radius:4px; }}
.section {{ background:#fff; padding:25px; border-radius:10px; box-shadow:0 2px 8px rgba(0,0,0,.06); margin-bottom:25px; }}
.section h2 {{ margin-bottom:20px; color:#0f4c75; border-left:4px solid #3282b8; padding-left:15px; font-size:1.3em; }}
.two-col {{ display:grid; grid-template-columns:1fr 1fr; gap:20px; margin-bottom:25px; }}
@media(max-width:768px) {{ .two-col {{ grid-template-columns:1fr; }} }}
.chart {{ width:100%; height:350px; }}
table {{ width:100%; border-collapse:collapse; font-size:.9em; }}
th,td {{ padding:9px 12px; text-align:left; border-bottom:1px solid #eee; }}
th {{ background:#f8f9fa; font-weight:600; color:#555; }}
tr:hover {{ background:#f8f9fa; }}
.funnel-step {{ display:flex; align-items:center; padding:12px 15px; margin:8px 0; border-radius:8px; background:#f8f9fa; }}
.funnel-step .step-name {{ flex:1; font-weight:500; }}
.funnel-step .step-count {{ font-weight:700; color:#3282b8; }}
.funnel-step .step-diff {{ width:120px; text-align:right; color:#28a745; font-size:.9em; }}
.tag {{ display:inline-block; padding:2px 10px; border-radius:12px; font-size:.82em; font-weight:500; }}
.tag-green {{ background:#d4edda; color:#155724; }}
.tag-blue {{ background:#d1ecf1; color:#0c5460; }}
.tag-yellow {{ background:#fff3cd; color:#856404; }}
.tag-red {{ background:#f8d7da; color:#721c24; }}
.footer {{ text-align:center; color:#999; padding:20px; font-size:.85em; }}
.note {{ font-size:.85em; color:#888; margin-top:8px; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>🛡️ AdGuard Rules Merger V5</h1>
    <div class="subtitle">专业规则合并分析报告</div>
    <div class="meta">生成时间：{generated_at[:19].replace('T',' ')} | 源：{outcome.sources_ok}/{outcome.sources_total} | 缓存：{outcome.sources_cached}</div>
  </div>

  {failed_html}

  <div class="stats-grid">
    <div class="stat-card"><div class="value">{total_block:,}</div><div class="label">Block 规则</div></div>
    <div class="stat-card"><div class="value">{total_allow:,}</div><div class="label">Allow 白名单</div></div>
    <div class="stat-card"><div class="value">{dedup_rate:.1f}%</div><div class="label">综合去重率</div></div>
    <div class="stat-card"><div class="value">{outcome.aggregated + outcome.wildcard_aggregated + outcome.wildcard_promoted:,}</div><div class="label">聚合精简</div></div>
    <div class="stat-card"><div class="value">{outcome.conflict_resolved:,}</div><div class="label">冲突消解</div></div>
    <div class="stat-card"><div class="value">{modifier_total:,}</div><div class="label">带 $ 修饰符规则</div></div>
    <div class="stat-card"><div class="value">{outcome.elapsed:.1f}s</div><div class="label">总耗时</div></div>
  </div>

  <div class="section">
    <h2>📊 优化流水线漏斗</h2>
    <div class="funnel-step"><div class="step-name">原始规则（Raw）</div><div class="step-count">{raw_count:,}</div><div class="step-diff">-</div></div>
    <div class="funnel-step"><div class="step-name">去重后（精确 {outcome.exact_merged:,} / 规范化 {outcome.normalized_merged:,} / 正则 {outcome.regex_merged:,}）</div><div class="step-count">{after_exact:,}</div><div class="step-diff">-{outcome.exact_merged + outcome.normalized_merged + outcome.regex_merged:,}</div></div>
    <div class="funnel-step"><div class="step-name">聚合后（精确 {outcome.aggregated:,} / 通配符 {outcome.wildcard_aggregated:,} / 升级 {outcome.wildcard_promoted:,}）</div><div class="step-count">{after_agg:,}</div><div class="step-diff">-{outcome.aggregated + outcome.wildcard_aggregated + outcome.wildcard_promoted:,}</div></div>
    <div class="funnel-step"><div class="step-name">冲突消解后</div><div class="step-count">{total_block + total_allow:,}</div><div class="step-diff">-{outcome.conflict_resolved:,}</div></div>
  </div>

  <div class="two-col">
    <div class="section"><h2>📋 规则类型分布</h2><div id="ruleTypeChart" class="chart"></div></div>
    <div class="section"><h2>🏷️ 类别分布</h2><div id="categoryChart" class="chart"></div></div>
  </div>

  <div class="section"><h2>🌐 域名后缀 Top 20</h2><div id="suffixChart" class="chart" style="height:450px;"></div></div>

  <div class="section">
    <h2>🔗 按源贡献分析（独占 vs 共享）</h2>
    <table>
      <thead><tr><th>源</th><th>原始规则</th><th>独占规则</th><th>与其他源共享</th><th>独占率</th></tr></thead>
      <tbody>{contrib_rows}</tbody>
    </table>
  </div>

  <div class="section">
    <h2>🔄 源间重复矩阵 Top 20</h2>
    <p class="note">每对源共同拥有的规则数；覆盖率 = 重复数 / 该源去重后有效规则数。颜色：<span style="background:#f8d7da;padding:2px 8px;">≥80%</span> <span style="background:#fff3cd;padding:2px 8px;">≥50%</span> <span style="background:#d1ecf1;padding:2px 8px;">≥20%</span> <span style="background:#d4edda;padding:2px 8px;">&lt;20%</span></p>
    <table style="margin-top:12px;">
      <thead><tr><th>源 A</th><th>源 B</th><th>共同规则数</th><th>A 覆盖率</th><th>B 覆盖率</th></tr></thead>
      <tbody>{overlap_rows}</tbody>
    </table>
  </div>

  <div class="section">
    <h2>⚔️ 冲突分析（白名单覆盖拦截）</h2>
    <p class="note">被白名单移除的拦截规则；展示双方来源，便于追溯是哪个源的白名单覆盖了哪个源的拦截。精确=域名完全匹配，级联=白名单父域覆盖子域。</p>
    <table style="margin-top:12px;">
      <thead><tr><th>域名</th><th>被拦规则</th><th>被拦来源</th><th>白名单规则</th><th>白名单来源</th><th>类型</th></tr></thead>
      <tbody>{conflict_rows}</tbody>
    </table>
  </div>

  <div class="section">
    <h2>📐 各源自去重率（原始 vs 去重后有效）</h2>
    <p class="note">有效规则数 = 去重后该源仍覆盖的规则数；自去重率 = 1 - 有效/原始，反映该源内部及与其他源的重复程度。</p>
    <table style="margin-top:12px;">
      <thead><tr><th>源</th><th>原始规则</th><th>去重后有效</th><th>自去重率</th></tr></thead>
      <tbody>{effective_rows}</tbody>
    </table>
  </div>

  <div class="section">
    <h2>🎯 $ 修饰符分布</h2>
    <p class="note">V5 保留 <code>$</code> 修饰符（important / badfilter 等），这些列表是 AdGuard Home 语法适配的，修饰符有 DNS 层语义。</p>
    <table style="margin-top:12px;">
      <thead><tr><th>修饰符</th><th>规则数</th><th>占比</th></tr></thead>
      <tbody>{modifier_rows}</tbody>
    </table>
  </div>

  <div class="section">
    <h2>🛡️ 白名单多层防御审计</h2>
    <p class="note">七层防御体系：DNS解析 → URLhaus/ThreatFox威胁情报 → RDAP域名年龄 → MarketNow诈骗检测 → VirusTotal(可选) → 离线PSL分类 → AI语义分类(可选)。<span class="tag tag-red">🔴 恶意</span> 建议移除此白名单；<span class="tag tag-yellow">🟡 可疑</span> 需人工确认；<span class="tag tag-green">🟢 安全</span> 可放心放行。需在配置中启用 <code>whitelist_audit.enabled</code>。</p>
    {"<div class='stats-grid' style='margin:15px 0'><div class='stat-card'><div class='value'>" + str(audit_summary.get('malicious',0)) + "</div><div class='label'>🔴 恶意</div></div><div class='stat-card'><div class='value'>" + str(audit_summary.get('suspicious',0)) + "</div><div class='label'>🟡 可疑</div></div><div class='stat-card'><div class='value'>" + str(audit_summary.get('safe',0)) + "</div><div class='label'>🟢 安全</div></div><div class='stat-card'><div class='value'>" + str(audit_summary.get('unknown',0)) + "</div><div class='label'>⚪ 未知</div></div></div>" if audit_summary else ""}
    {"<h3 style='margin:20px 0 10px'>🏗️ 防御层概览</h3><table><thead><tr><th>层级</th><th>检测内容</th><th>状态</th><th>成本</th><th>命中数</th></tr></thead><tbody>" + layer_rows + "</tbody></table>" if layer_rows else ""}
    {"<h3 style='margin:20px 0 10px'>📂 白名单域名类别分布</h3><table><thead><tr><th>类别</th><th>数量</th><th>占比</th><th>百分比</th></tr></thead><tbody>" + cat_rows + "</tbody></table>" if cat_counts else ""}
    {"<h3 style='margin:20px 0 10px'>🎯 分类置信度分布</h3><p class='note' style='margin:5px 0'>高置信度=注册域名精确匹配(PSL)，可直接信任；中置信度=子域名前缀匹配，建议人工确认；低置信度=无法分类，需外部API或人工判断。</p><table><thead><tr><th>置信度等级</th><th>数量</th><th>占比</th><th>百分比</th></tr></thead><tbody>" + conf_rows + "</tbody></table>" if conf_dist else ""}
    <h3 style="margin:20px 0 10px">🔍 逐条审计详情</h3>
    <table>
      <thead><tr><th>域名</th><th>评级</th><th>类别</th><th>置信度</th><th>原因</th><th>来源</th></tr></thead>
      <tbody>{audit_rows if audit_rows else '<tr><td colspan="6" style="text-align:center;color:#999">审计未启用</td></tr>'}</tbody>
    </table>
  </div>

  <div class="section">
    <h2>📝 规则语法支持度矩阵</h2>
    <table>
      <thead><tr><th>规则类型</th><th>语法示例</th><th>状态</th><th>处理方式</th><th>数量</th></tr></thead>
      <tbody>
        <tr><td>Block 域名</td><td><code>||example.com^</code></td><td><span class="tag tag-green">✅ 支持</span></td><td>核心输出</td><td>{domain_count:,}</td></tr>
        <tr><td>通配符</td><td><code>||*.example.com^</code></td><td><span class="tag tag-green">✅ 支持</span></td><td>聚合覆盖子域</td><td>{wildcard_count:,}</td></tr>
        <tr><td>Allow 白名单</td><td><code>@@||example.com^</code></td><td><span class="tag tag-green">✅ 支持</span></td><td>分离到 whitelist.txt</td><td>{total_allow:,}</td></tr>
        <tr><td>正则</td><td><code>/ads.*/</code></td><td><span class="tag tag-blue">✅ 保留</span></td><td>原样保留</td><td>{regex_count:,}</td></tr>
        <tr><td>IP 规则</td><td><code>||8.8.8.8^</code></td><td><span class="tag tag-blue">✅ 支持</span></td><td>按域名字符串处理</td><td>{ip_count:,}</td></tr>
        <tr><td>Hosts</td><td><code>0.0.0.0 example.com</code></td><td><span class="tag tag-green">✅ 支持</span></td><td>转换为 ||domain^</td><td>-</td></tr>
        <tr><td>$ 修饰符</td><td><code>||x.com^$important</code></td><td><span class="tag tag-green">✅ 保留</span></td><td>保留修饰符，纳入去重键，跳过聚合，$important 抗白名单</td><td>{modifier_total:,}</td></tr>
        <tr><td>CSS/JS</td><td><code>##.ad</code></td><td><span class="tag tag-red">❌ 丢弃</span></td><td>DNS 层不支持</td><td>{outcome.css_dropped:,}</td></tr>
      </tbody>
    </table>
  </div>

  <div class="two-col">
    <div class="section"><h2>⚡ 性能指标</h2>
      <table>
        <tr><td>总耗时</td><td><strong>{outcome.elapsed:.1f}s</strong></td></tr>
        <tr><td>源成功率</td><td>{outcome.sources_ok}/{outcome.sources_total}</td></tr>
        <tr><td>缓存命中</td><td>{outcome.sources_cached}</td></tr>
        <tr><td>精确去重</td><td>{outcome.exact_merged:,}</td></tr>
        <tr><td>规范化去重</td><td>{outcome.normalized_merged:,}</td></tr>
        <tr><td>正则去重</td><td>{outcome.regex_merged:,}</td></tr>
        <tr><td>本次新增域名</td><td>{len(outcome.added):,}</td></tr>
        <tr><td>本次移除域名</td><td>{len(outcome.removed):,}</td></tr>
      </table>
    </div>
    <div class="section"><h2>📏 域名长度统计</h2>
      <table>
        <tr><td>平均域名长度</td><td>{analysis['avg_domain_length']:.1f} 字符</td></tr>
        <tr><td>最短域名</td><td>{analysis['min_domain_length']} 字符</td></tr>
        <tr><td>最长域名</td><td>{analysis['max_domain_length']} 字符</td></tr>
      </table>
    </div>
  </div>

  <div class="footer">AdGuard Rules Merger V5 · 自动生成 · {generated_at[:10]}</div>
</div>
<script>
const ruleTypeChart = echarts.init(document.getElementById('ruleTypeChart'));
ruleTypeChart.setOption({{ tooltip:{{trigger:'item'}}, legend:{{bottom:0}},
  series:[{{ type:'pie', radius:['40%','70%'],
    data:[
      {{value:{domain_count},name:'普通域名',itemStyle:{{color:'#3282b8'}}}},
      {{value:{wildcard_count},name:'通配符',itemStyle:{{color:'#6ab04c'}}}},
      {{value:{regex_count},name:'正则',itemStyle:{{color:'#f0932b'}}}},
      {{value:{ip_count},name:'IP',itemStyle:{{color:'#eb4d4b'}}}}
    ], label:{{formatter:'{{b}}\\n{{d}}%'}} }}] }});
const categoryChart = echarts.init(document.getElementById('categoryChart'));
const catData = {json.dumps(cats)};
categoryChart.setOption({{ tooltip:{{trigger:'axis'}},
  grid:{{left:'3%',right:'4%',bottom:'3%',containLabel:true}},
  xAxis:{{type:'category',data:Object.keys(catData),axisLabel:{{rotate:30}}}},
  yAxis:{{type:'value'}},
  series:[{{type:'bar',data:Object.values(catData),
    itemStyle:{{color:new echarts.graphic.LinearGradient(0,0,0,1,[{{offset:0,color:'#3282b8'}},{{offset:1,color:'#0f4c75'}}])}}}}] }});
const suffixChart = echarts.init(document.getElementById('suffixChart'));
suffixChart.setOption({{ tooltip:{{trigger:'axis'}},
  grid:{{left:'3%',right:'4%',bottom:'3%',containLabel:true}},
  xAxis:{{type:'value'}},
  yAxis:{{type:'category',data:{json.dumps(list(reversed(top_suffix_labels)))}}},
  series:[{{type:'bar',data:{json.dumps(list(reversed(top_suffix_values)))},itemStyle:{{color:'#3282b8'}}}}] }});
window.addEventListener('resize',()=>{{ruleTypeChart.resize();categoryChart.resize();suffixChart.resize();}});
</script>
</body>
</html>"""
    return html


# ── Markdown report ───────────────────────────────────────────────

def generate_markdown_report(blocks, allows, outcome, analysis) -> str:
    """Generate a plain-text Markdown report (no external dependencies)."""
    now = datetime.now()
    generated_at = now.strftime("%Y-%m-%d %H:%M:%S")
    total_block = len(blocks)
    total_allow = len(allows)
    raw_count = outcome.raw_count
    dedup_rate = (1 - (total_block + total_allow) / raw_count) * 100 if raw_count else 0
    cats = analysis["categories"]
    rt = analysis["rule_types"]
    modifier_stats = getattr(outcome, "modifier_stats", {}) or {}
    modifier_total = _modifier_total(modifier_stats)
    source_overlap = getattr(outcome, "source_overlap", {}) or {}
    overlap_pairs = source_overlap.get("pairs", [])
    source_effective = source_overlap.get("source_effective", {})
    contributions = getattr(outcome, "contributions", [])
    contrib_by_name = {c["name"]: c for c in contributions}
    after_exact = raw_count - outcome.exact_merged - outcome.normalized_merged - outcome.regex_merged
    after_agg = after_exact - outcome.aggregated - outcome.wildcard_aggregated - outcome.wildcard_promoted

    lines: List[str] = []
    lines.append("# AdGuard Rules Merger V5 — 规则分析报告")
    lines.append("")
    lines.append(f"> 生成时间：{generated_at} | 源：{outcome.sources_ok}/{outcome.sources_total} | 缓存命中：{outcome.sources_cached}")
    lines.append("")

    # ── 概览 ──
    lines.append("## 一、概览")
    lines.append("")
    lines.append("| 指标 | 数值 |")
    lines.append("|------|------|")
    lines.append(f"| Block 规则 | {total_block:,} |")
    lines.append(f"| Allow 白名单 | {total_allow:,} |")
    lines.append(f"| 综合去重率 | {dedup_rate:.1f}% |")
    lines.append(f"| 聚合精简 | {outcome.aggregated + outcome.wildcard_aggregated + outcome.wildcard_promoted:,} |")
    lines.append(f"| 冲突消解 | {outcome.conflict_resolved:,} |")
    lines.append(f"| 带 $ 修饰符规则 | {modifier_total:,} |")
    lines.append(f"| 总耗时 | {outcome.elapsed:.1f}s |")
    lines.append("")

    # ── 优化流水线 ──
    lines.append("## 二、优化流水线")
    lines.append("")
    lines.append("| 阶段 | 规则数 | 本阶段减少 |")
    lines.append("|------|--------|-----------|")
    lines.append(f"| 原始规则（Raw） | {raw_count:,} | - |")
    lines.append(f"| 去重后（精确 {outcome.exact_merged:,} / 规范化 {outcome.normalized_merged:,} / 正则 {outcome.regex_merged:,}） | {after_exact:,} | -{outcome.exact_merged + outcome.normalized_merged + outcome.regex_merged:,} |")
    lines.append(f"| 聚合后（精确 {outcome.aggregated:,} / 通配符 {outcome.wildcard_aggregated:,} / 升级 {outcome.wildcard_promoted:,}） | {after_agg:,} | -{outcome.aggregated + outcome.wildcard_aggregated + outcome.wildcard_promoted:,} |")
    lines.append(f"| 冲突消解后 | {total_block + total_allow:,} | -{outcome.conflict_resolved:,} |")
    lines.append("")

    # ── 规则类型与类别 ──
    lines.append("## 三、规则类型与类别分布")
    lines.append("")
    lines.append("### 规则类型")
    lines.append("")
    lines.append("| 类型 | 数量 |")
    lines.append("|------|------|")
    for t, v in sorted(rt.items(), key=lambda x: -x[1]):
        lines.append(f"| {t} | {v:,} |")
    lines.append("")
    lines.append("### 类别分布（Block）")
    lines.append("")
    lines.append("| 类别 | 数量 |")
    lines.append("|------|------|")
    for cat, v in sorted(cats.items(), key=lambda x: -x[1]):
        lines.append(f"| {cat} | {v:,} |")
    lines.append("")

    # ── 按源贡献 ──
    lines.append("## 四、按源贡献分析")
    lines.append("")
    lines.append("| 源 | 原始规则 | 独占规则 | 与其他源共享 | 独占率 |")
    lines.append("|------|---------|---------|-------------|--------|")
    for c in contributions[:25]:
        total_c = c["unique_rules"] + c["shared_rules"]
        ratio = (c["unique_rules"] / total_c * 100) if total_c else 0
        lines.append(f"| {c['name']} | {c['raw_rules']:,} | {c['unique_rules']:,} | {c['shared_rules']:,} | {ratio:.0f}% |")
    lines.append("")

    # ── 源间重复矩阵 ──
    lines.append("## 五、源间重复矩阵 Top 20")
    lines.append("")
    lines.append("> 每对源共同拥有的规则数；覆盖率 = 重复数 / 该源去重后有效规则数。")
    lines.append("")
    lines.append("| 源 A | 源 B | 共同规则数 | A 覆盖率 | B 覆盖率 |")
    lines.append("|------|------|-----------|---------|---------|")
    for p in overlap_pairs[:20]:
        lines.append(f"| {p['source_a']} | {p['source_b']} | {p['overlap']:,} | {p['rate_a']:.1f}% | {p['rate_b']:.1f}% |")
    if not overlap_pairs:
        lines.append("| - | - | - | - | - |")
    lines.append("")

    # ── 各源自去重率 ──
    lines.append("## 六、各源自去重率")
    lines.append("")
    lines.append("> 有效规则数 = 去重后该源仍覆盖的规则数；自去重率 = 1 - 有效/原始。")
    lines.append("")
    lines.append("| 源 | 原始规则 | 去重后有效 | 自去重率 |")
    lines.append("|------|---------|-----------|---------|")
    for name, eff in source_effective.items():
        c = contrib_by_name.get(name, {})
        raw = c.get("raw_rules", 0)
        self_dedup = (1 - eff / raw) * 100 if raw else 0
        lines.append(f"| {name} | {raw:,} | {eff:,} | {self_dedup:.1f}% |")
    lines.append("")

    # ── 冲突分析 ──
    lines.append("## 七、冲突分析（白名单覆盖拦截）")
    lines.append("")
    lines.append("> 被白名单移除的拦截规则；展示双方来源。精确=域名完全匹配，级联=白名单父域覆盖子域。")
    lines.append("")
    lines.append("| 域名 | 被拦规则 | 被拦来源 | 白名单规则 | 白名单来源 | 类型 |")
    lines.append("|------|---------|---------|-----------|-----------|------|")
    for c in (getattr(outcome, "conflicts", []) or [])[:50]:
        blocked_srcs = ", ".join(c.get("blocked_sources", [])) or c.get("source", "-")
        allow_srcs = ", ".join(c.get("whitelist_sources", [])) or "-"
        ctype = "级联" if c.get("conflict_type") == "cascade" else "精确"
        lines.append(f"| `{c.get('domain','')}` | `{c.get('blocked_rule','')}` | {blocked_srcs} | `{c.get('whitelist_rule','')}` | {allow_srcs} | {ctype} |")
    if not (getattr(outcome, "conflicts", []) or []):
        lines.append("| - | - | - | - | - | - |")
    lines.append("")

    # ── $ 修饰符分布 ──
    lines.append("## 八、$ 修饰符分布")
    lines.append("")
    lines.append("> V5 保留 `$` 修饰符（important / badfilter 等），这些列表是 AdGuard Home 语法适配的，修饰符有 DNS 层语义。")
    lines.append("")
    lines.append("| 修饰符 | 规则数 | 占比 |")
    lines.append("|--------|--------|------|")
    if modifier_stats:
        for mod, cnt in modifier_stats.items():
            pct = cnt / modifier_total * 100 if modifier_total else 0
            lines.append(f"| `${mod}` | {cnt:,} | {pct:.1f}% |")
    else:
        lines.append("| 无 | - | - |")
    lines.append("")

    # ── 白名单审计 ──
    lines.append("## 九、白名单威胁情报审计")
    lines.append("")
    lines.append("> 七层防御体系：DNS解析 → URLhaus/ThreatFox威胁情报 → RDAP域名年龄 → MarketNow诈骗检测 → VirusTotal(可选) → 离线PSL分类 → AI语义分类(可选)。🔴 恶意建议移除此白名单；🟡 可疑需人工确认；🟢 安全可放心放行。需在配置中启用 `whitelist_audit.enabled`。")
    lines.append("")
    audit_sum = (getattr(outcome, "whitelist_audit", {}) or {}).get("summary", {})
    if audit_sum:
        lines.append(f"- 🔴 恶意：{audit_sum.get('malicious', 0)}")
        lines.append(f"- 🟡 可疑：{audit_sum.get('suspicious', 0)}")
        lines.append(f"- 🟢 安全：{audit_sum.get('safe', 0)}")
        lines.append(f"- ⚪ 未知：{audit_sum.get('unknown', 0)}")
        lines.append("")
        # V5: multi-layer defense overview
        layers_enabled = audit_sum.get("layers_enabled", {})
        layer_hits = audit_sum.get("layer_hits", {})
        if layers_enabled:
            lines.append("### 防御层概览")
            lines.append("")
            lines.append("| 层级 | 检测内容 | 状态 | 成本 | 命中数 |")
            lines.append("|------|---------|------|------|--------|")
            layer_info = [
                ("dns", "DNS 解析", "NXDOMAIN/私有IP检测", "免费"),
                ("urlhaus", "URLhaus", "恶意软件分发域名", "免费"),
                ("threatfox", "ThreatFox", "C2 命令控制域名", "免费"),
                ("rdap", "RDAP 域名年龄", "新注册域名<30天标记", "免费"),
                ("scam_check", "MarketNow 诈骗检测", "拼写劫持/可疑TLD/未注册", "免费"),
                ("virustotal", "VirusTotal", "多引擎厂商信誉", "需API Key"),
                ("ai", "AI/LLM 分类", "低置信度域名语义分类", "需API Key"),
            ]
            for key, name, desc, cost in layer_info:
                enabled = layers_enabled.get(key, False)
                if key == "dns":
                    hits = layer_hits.get("dns_nxdomain", 0) + layer_hits.get("dns_private_ip", 0)
                else:
                    hits = layer_hits.get(key, 0)
                status = "✅ 启用" if enabled else "⬜ 未启用"
                lines.append(f"| {name} | {desc} | {status} | {cost} | {hits if enabled else '-'} |")
            lines.append("")
        # V5: category distribution
        cat_counts = audit_sum.get("category_counts", {})
        if cat_counts:
            lines.append("### 白名单域名类别分布")
            lines.append("")
            lines.append("| 类别 | 数量 | 占比 |")
            lines.append("|------|------|------|")
            total_cat = sum(cat_counts.values()) or 1
            for cat in CATEGORY_ORDER:
                cnt = cat_counts.get(cat, 0)
                if cnt == 0:
                    continue
                pct = cnt / total_cat * 100
                label = CATEGORY_LABELS.get(cat, cat)
                lines.append(f"| {label} | {cnt} | {pct:.1f}% |")
            lines.append("")
        # V5: classification confidence distribution
        conf_dist = audit_sum.get("category_confidence", {})
        if conf_dist:
            lines.append("### 分类置信度分布")
            lines.append("")
            lines.append("> 高置信度=注册域名精确匹配(PSL)，可直接信任；中置信度=子域名前缀匹配，建议人工确认；低置信度=无法分类，需外部API或人工判断。")
            lines.append("")
            lines.append("| 置信度等级 | 数量 | 占比 |")
            lines.append("|-----------|------|------|")
            total_conf = sum(conf_dist.values()) or 1
            for level in ("high(>=0.9)", "medium(0.6-0.89)", "low(<0.6)"):
                cnt = conf_dist.get(level, 0)
                pct = cnt / total_conf * 100
                label = {"high(>=0.9)": "高置信度 (注册域名匹配)",
                         "medium(0.6-0.89)": "中置信度 (子域名前缀)",
                         "low(<0.6)": "低置信度 (无法分类)"}.get(level, level)
                lines.append(f"| {label} | {cnt} | {pct:.1f}% |")
            lines.append("")
    audit_rules_list = (getattr(outcome, "whitelist_audit", {}) or {}).get("rules", [])
    if audit_rules_list:
        lines.append("| 域名 | 评级 | 类别 | 置信度 | 原因 | 来源 |")
        lines.append("|------|------|------|--------|------|------|")
        rating_md = {"malicious": "🔴 恶意", "suspicious": "🟡 可疑", "safe": "🟢 安全", "unknown": "⚪ 未知"}
        for r in audit_rules_list:
            label = rating_md.get(r["rating"], r["rating"])
            cat_label = CATEGORY_LABELS.get(r.get("category", "other"), r.get("category", "other"))
            conf = r.get("category_confidence", 0)
            srcs = ", ".join(r.get("sources", []))
            lines.append(f"| `{r['domain']}` | {label} | {cat_label} | {conf:.2f} | {r['reason']} | {srcs} |")
        lines.append("")
    else:
        lines.append("*审计未启用或无域名规则*")
        lines.append("")

    # ── 语法支持度 ──
    lines.append("## 十、规则语法支持度")
    lines.append("")
    lines.append("| 规则类型 | 语法示例 | 状态 | 处理方式 | 数量 |")
    lines.append("|---------|---------|------|---------|------|")
    lines.append(f"| Block 域名 | `||example.com^` | ✅ 支持 | 核心输出 | {rt.get('domain', 0):,} |")
    lines.append(f"| 通配符 | `||*.example.com^` | ✅ 支持 | 聚合覆盖子域 | {rt.get('wildcard', 0):,} |")
    lines.append(f"| Allow 白名单 | `@@||example.com^` | ✅ 支持 | 分离到 whitelist.txt | {total_allow:,} |")
    lines.append(f"| 正则 | `/ads.*/` | ✅ 保留 | 原样保留 | {rt.get('regex', 0):,} |")
    lines.append(f"| IP 规则 | `||8.8.8.8^` | ✅ 支持 | 按域名字符串处理 | {rt.get('ip', 0):,} |")
    lines.append("| Hosts | `0.0.0.0 example.com` | ✅ 支持 | 转换为 `||domain^` | - |")
    lines.append(f"| $ 修饰符 | `||x.com^$important` | ✅ 保留 | 保留修饰符，纳入去重键，跳过聚合，$important 抗白名单 | {modifier_total:,} |")
    lines.append(f"| CSS/JS | `##.ad` | ❌ 丢弃 | DNS 层不支持 | {outcome.css_dropped:,} |")
    lines.append("")

    # ── 域名后缀 Top 20 ──
    lines.append("## 十一、域名后缀 Top 20")
    lines.append("")
    lines.append("| 后缀 | 规则数 |")
    lines.append("|------|--------|")
    for suffix, cnt in analysis["top_suffixes"]:
        lines.append(f"| {suffix} | {cnt:,} |")
    lines.append("")

    # ── 性能指标 ──
    lines.append("## 十二、性能与诊断")
    lines.append("")
    lines.append("| 指标 | 数值 |")
    lines.append("|------|------|")
    lines.append(f"| 总耗时 | {outcome.elapsed:.1f}s |")
    lines.append(f"| 源成功率 | {outcome.sources_ok}/{outcome.sources_total} |")
    lines.append(f"| 缓存命中 | {outcome.sources_cached} |")
    lines.append(f"| 精确去重 | {outcome.exact_merged:,} |")
    lines.append(f"| 规范化去重 | {outcome.normalized_merged:,} |")
    lines.append(f"| 正则去重 | {outcome.regex_merged:,} |")
    lines.append(f"| 质量过滤丢弃 | {outcome.quality_dropped:,} |")
    lines.append(f"| 模式丢弃 | {outcome.pattern_dropped:,} |")
    lines.append(f"| CSS 丢弃 | {outcome.css_dropped:,} |")
    lines.append(f"| 本次新增域名 | {len(outcome.added):,} |")
    lines.append(f"| 本次移除域名 | {len(outcome.removed):,} |")
    lines.append(f"| 平均域名长度 | {analysis['avg_domain_length']:.1f} 字符 |")
    lines.append(f"| 最短/最长域名 | {analysis['min_domain_length']} / {analysis['max_domain_length']} 字符 |")
    lines.append("")

    # ── 失败源 ──
    if outcome.failed_sources:
        lines.append("## ⚠️ 失败源")
        lines.append("")
        for f in outcome.failed_sources:
            lines.append(f"- **{f['name']}** — {f['error']}")
        lines.append("")

    lines.append("---")
    lines.append(f"*AdGuard Rules Merger V5 · 自动生成 · {now.strftime('%Y-%m-%d')}*")
    lines.append("")
    return "\n".join(lines)
