# AdGuard Rules Merger V5 — 规则分析报告

> 生成时间：2026-09-23 12:09:16 | 源：18/18 | 缓存命中：18

## 一、概览

| 指标 | 数值 |
|------|------|
| Block 规则 | 3,146,978 |
| Allow 白名单 | 226 |
| 综合去重率 | 16.7% |
| 聚合精简 | 40,064 |
| 冲突消解 | 33 |
| 带 $ 修饰符规则 | 10 |
| 总耗时 | 45.7s |

## 二、优化流水线

| 阶段 | 规则数 | 本阶段减少 |
|------|--------|-----------|
| 原始规则（Raw） | 3,776,482 | - |
| 去重后（精确 584,118 / 规范化 4,901 / 正则 0） | 3,187,463 | -589,019 |
| 聚合后（精确 40,062 / 通配符 2 / 升级 0） | 3,147,399 | -40,064 |
| 冲突消解后 | 3,147,204 | -33 |

## 三、规则类型与类别分布

### 规则类型

| 类型 | 数量 |
|------|------|
| domain | 3,147,068 |
| ip | 72 |
| regex | 63 |
| wildcard | 1 |

### 类别分布（Block）

| 类别 | 数量 |
|------|------|
| malware | 2,203,938 |
| other | 541,716 |
| ads | 338,892 |
| phishing | 61,917 |
| tracking | 370 |
| mining | 145 |

## 四、按源贡献分析

| 源 | 原始规则 | 独占规则 | 与其他源共享 | 独占率 |
|------|---------|---------|-------------|--------|
| HaGeZi's Threat Intelligence Feeds | 2,204,702 | 2,061,462 | 141,631 | 94% |
| HaGeZi's Gambling Blocklist | 531,612 | 525,063 | 6,516 | 99% |
| HaGeZi's Ultimate Blocklist | 283,459 | 121,654 | 160,265 | 43% |
| Phishing Army | 151,279 | 33,986 | 94,100 | 27% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 39,655 | 14,623 | 21,096 | 41% |
| HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 16,472 | 14,592 | 1,610 | 90% |
| CHN: AdRules DNS List | 201,226 | 11,098 | 186,223 | 6% |
| CHN: anti-AD | 100,836 | 7,615 | 92,479 | 8% |
| AdGuard DNS filter | 181,631 | 5,061 | 174,192 | 3% |
| ShadowWhisperer's Dating List | 1,384 | 1,266 | 109 | 92% |
| Malicious URL Blocklist (URLHaus) | 3,504 | 1,045 | 1,669 | 39% |
| Stalkerware Indicators List | 934 | 446 | 61 | 88% |
| OISD Blocklist Small | 57,197 | 97 | 55,622 | 0% |
| Scam Blocklist by DurableNapkin | 941 | 4 | 925 | 0% |
| HaGeZi's DNS Rebind Protection | 25 | 3 | 0 | 100% |
| NoCoin Filter List | 321 | 3 | 266 | 1% |
| HaGeZi's Windows/Office Tracker Blocklist | 397 | 1 | 379 | 0% |
| AWAvenue Ads Rule | 907 | 0 | 742 | 0% |

## 五、源间重复矩阵 Top 20

> 每对源共同拥有的规则数；覆盖率 = 重复数 / 该源去重后有效规则数。

| 源 A | 源 B | 共同规则数 | A 覆盖率 | B 覆盖率 |
|------|------|-----------|---------|---------|
| AdGuard DNS filter | CHN: AdRules DNS List | 166,485 | 92.9% | 84.4% |
| CHN: AdRules DNS List | HaGeZi's Ultimate Blocklist | 87,842 | 44.5% | 31.2% |
| CHN: anti-AD | CHN: AdRules DNS List | 86,535 | 86.5% | 43.9% |
| AdGuard DNS filter | HaGeZi's Ultimate Blocklist | 86,265 | 48.1% | 30.6% |
| Phishing Army | HaGeZi's Threat Intelligence Feeds | 81,011 | 63.2% | 3.7% |
| AdGuard DNS filter | CHN: anti-AD | 77,262 | 43.1% | 77.2% |
| HaGeZi's Threat Intelligence Feeds | HaGeZi's Ultimate Blocklist | 61,896 | 2.8% | 22.0% |
| CHN: anti-AD | HaGeZi's Ultimate Blocklist | 60,098 | 60.0% | 21.3% |
| HaGeZi's Ultimate Blocklist | OISD Blocklist Small | 55,470 | 19.7% | 99.6% |
| CHN: AdRules DNS List | OISD Blocklist Small | 52,184 | 26.4% | 93.7% |
| AdGuard DNS filter | OISD Blocklist Small | 51,585 | 28.8% | 92.6% |
| CHN: anti-AD | OISD Blocklist Small | 40,158 | 40.1% | 72.1% |
| Phishing Army | Phishing URL Blocklist (PhishTank and OpenPhish) | 20,087 | 15.7% | 56.2% |
| Phishing Army | HaGeZi's Ultimate Blocklist | 11,640 | 9.1% | 4.1% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | HaGeZi's Threat Intelligence Feeds | 7,898 | 22.1% | 0.4% |
| HaGeZi's Threat Intelligence Feeds | HaGeZi's Gambling Blocklist | 5,275 | 0.2% | 1.0% |
| CHN: AdRules DNS List | HaGeZi's Threat Intelligence Feeds | 5,204 | 2.6% | 0.2% |
| AdGuard DNS filter | HaGeZi's Threat Intelligence Feeds | 3,774 | 2.1% | 0.2% |
| CHN: anti-AD | HaGeZi's Threat Intelligence Feeds | 2,414 | 2.4% | 0.1% |
| HaGeZi's Threat Intelligence Feeds | OISD Blocklist Small | 1,921 | 0.1% | 3.4% |

## 六、各源自去重率

> 有效规则数 = 去重后该源仍覆盖的规则数；自去重率 = 1 - 有效/原始。

| 源 | 原始规则 | 去重后有效 | 自去重率 |
|------|---------|-----------|---------|
| HaGeZi's Threat Intelligence Feeds | 2,204,702 | 2,203,093 | 0.1% |
| HaGeZi's Gambling Blocklist | 531,612 | 531,579 | 0.0% |
| HaGeZi's Ultimate Blocklist | 283,459 | 281,919 | 0.5% |
| CHN: AdRules DNS List | 201,226 | 197,321 | 1.9% |
| AdGuard DNS filter | 181,631 | 179,253 | 1.3% |
| Phishing Army | 151,279 | 128,086 | 15.3% |
| CHN: anti-AD | 100,836 | 100,094 | 0.7% |
| OISD Blocklist Small | 57,197 | 55,719 | 2.6% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 39,655 | 35,719 | 9.9% |
| HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 16,472 | 16,202 | 1.6% |
| Malicious URL Blocklist (URLHaus) | 3,504 | 2,714 | 22.5% |
| ShadowWhisperer's Dating List | 1,384 | 1,375 | 0.7% |
| Scam Blocklist by DurableNapkin | 941 | 929 | 1.3% |
| AWAvenue Ads Rule | 907 | 742 | 18.2% |
| Stalkerware Indicators List | 934 | 507 | 45.7% |
| HaGeZi's Windows/Office Tracker Blocklist | 397 | 380 | 4.3% |
| NoCoin Filter List | 321 | 269 | 16.2% |
| HaGeZi's DNS Rebind Protection | 25 | 3 | 88.0% |

## 七、冲突分析（白名单覆盖拦截）

> 被白名单移除的拦截规则；展示双方来源。精确=域名完全匹配，级联=白名单父域覆盖子域。

| 域名 | 被拦规则 | 被拦来源 | 白名单规则 | 白名单来源 | 类型 |
|------|---------|---------|-----------|-----------|------|
| `sax.sina.com.cn` | `||sax.sina.com.cn^` | AdGuard DNS filter, CHN: anti-AD, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist, OISD Blocklist Small | `@@||sax.sina.com.cn^` | AdGuard DNS filter | 精确 |
| `data.orders.costco.ca` | `||data.orders.costco.ca^` | AdGuard DNS filter, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@||data.orders.costco.ca^` | AdGuard DNS filter | 精确 |
| `proto2ad.durasite.net` | `||proto2ad.durasite.net^` | AdGuard DNS filter, CHN: anti-AD, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist, OISD Blocklist Small | `@@||proto2ad.durasite.net^` | AdGuard DNS filter | 精确 |
| `stats.tj.gov.cn` | `||stats.tj.gov.cn^` | HaGeZi's Ultimate Blocklist | `@@||tj.gov.cn^` | CHN: anti-AD | 级联 |
| `swasc.homedepot.com` | `||swasc.homedepot.com^` | AdGuard DNS filter, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@||swasc.homedepot.com^` | AdGuard DNS filter | 精确 |
| `api.karte.io` | `||api.karte.io^` | HaGeZi's Ultimate Blocklist | `@@||api.karte.io^` | AdGuard DNS filter | 精确 |
| `omsc.kpn.com` | `||omsc.kpn.com^` | AdGuard DNS filter, CHN: anti-AD, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@||omsc.kpn.com^` | AdGuard DNS filter | 精确 |
| `settings-win.data.microsoft.com` | `||settings-win.data.microsoft.com^` | HaGeZi's Ultimate Blocklist | `@@||settings-win.data.microsoft.com^` | CHN: anti-AD | 精确 |
| `global.api.huangye.miui.com` | `||global.api.huangye.miui.com^` | HaGeZi's Ultimate Blocklist | `@@||api.huangye.miui.com^` | CHN: anti-AD | 级联 |
| `sedge.nfl.com` | `||sedge.nfl.com^` | AdGuard DNS filter, CHN: anti-AD, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@||sedge.nfl.com^` | AdGuard DNS filter | 精确 |
| `ads.privacy.qq.com` | `||ads.privacy.qq.com^` | HaGeZi's Ultimate Blocklist | `@@||ads.privacy.qq.com^` | CHN: anti-AD | 精确 |
| `belgium.wolterskluwer.com` | `||belgium.wolterskluwer.com^` | AdGuard DNS filter, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@||belgium.wolterskluwer.com^` | AdGuard DNS filter | 精确 |
| `afi-b.com` | `||afi-b.com^` | AdGuard DNS filter, CHN: anti-AD, HaGeZi's Ultimate Blocklist | `@@||afi-b.com^` | AdGuard DNS filter | 精确 |
| `datadoghq-browser-agent.com` | `||datadoghq-browser-agent.com^` | AdGuard DNS filter, CHN: anti-AD, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@||datadoghq-browser-agent.com^` | AdGuard DNS filter | 精确 |
| `googleadservices.com` | `||googleadservices.com^` | AdGuard DNS filter, CHN: anti-AD, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist, OISD Blocklist Small, AWAvenue Ads Rule | `@@||googleadservices.com^` | AdGuard DNS filter | 精确 |
| `logentries.com` | `||logentries.com^` | AdGuard DNS filter, CHN: anti-AD, HaGeZi's Ultimate Blocklist | `@@||logentries.com^` | AdGuard DNS filter | 精确 |
| `statcounter.com` | `||statcounter.com^` | AdGuard DNS filter, CHN: anti-AD, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist, OISD Blocklist Small | `@@||statcounter.com^` | AdGuard DNS filter | 精确 |
| `ad.10010.com` | `||ad.10010.com^` | CHN: anti-AD, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist, OISD Blocklist Small, AWAvenue Ads Rule | `@@||ad.10010.com^` | AdGuard DNS filter | 精确 |
| `ad.ourgame.com` | `||ad.ourgame.com^` | CHN: AdRules DNS List | `@@||ad.ourgame.com^` | AdGuard DNS filter | 精确 |
| `awin1.com` | `||awin1.com^` | AdGuard DNS filter, CHN: anti-AD, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@||awin1.com^` | AdGuard DNS filter | 精确 |
| `cmp.osano.com` | `||cmp.osano.com^` | CHN: anti-AD, CHN: AdRules DNS List | `@@||cmp.osano.com^` | AdGuard DNS filter | 精确 |
| `data.digital.costco.ca` | `||data.digital.costco.ca^` | AdGuard DNS filter, CHN: anti-AD, CHN: AdRules DNS List | `@@||data.digital.costco.ca^` | AdGuard DNS filter | 精确 |
| `data.digital.costco.com` | `||data.digital.costco.com^` | AdGuard DNS filter, CHN: anti-AD, CHN: AdRules DNS List | `@@||data.digital.costco.com^` | AdGuard DNS filter | 精确 |
| `data.notify.macys.com` | `||data.notify.macys.com^` | AdGuard DNS filter, CHN: AdRules DNS List | `@@||data.notify.macys.com^` | AdGuard DNS filter | 精确 |
| `data.orders.costco.com` | `||data.orders.costco.com^` | AdGuard DNS filter, CHN: anti-AD, CHN: AdRules DNS List | `@@||data.orders.costco.com^` | AdGuard DNS filter | 精确 |
| `data.promo.timhortons.ca` | `||data.promo.timhortons.ca^` | AdGuard DNS filter, CHN: anti-AD, CHN: AdRules DNS List | `@@||data.promo.timhortons.ca^` | AdGuard DNS filter | 精确 |
| `jdoqocy.com` | `||jdoqocy.com^` | AdGuard DNS filter, CHN: anti-AD, CHN: AdRules DNS List | `@@||jdoqocy.com^` | AdGuard DNS filter | 精确 |
| `marketing.net.idealo-partner.com` | `||marketing.net.idealo-partner.com^` | AdGuard DNS filter, CHN: anti-AD, CHN: AdRules DNS List | `@@||marketing.net.idealo-partner.com^` | AdGuard DNS filter | 精确 |
| `om-ssl.consorsbank.de` | `||om-ssl.consorsbank.de^` | AdGuard DNS filter, CHN: anti-AD, CHN: AdRules DNS List | `@@||om-ssl.consorsbank.de^` | AdGuard DNS filter | 精确 |
| `omniture.walmart.com` | `||omniture.walmart.com^` | AdGuard DNS filter, CHN: AdRules DNS List | `@@||omniture.walmart.com^` | AdGuard DNS filter | 精确 |
| `torimochi.line-apps.com` | `||torimochi.line-apps.com^` | CHN: anti-AD | `@@||torimochi.line-apps.com^` | AdGuard DNS filter | 精确 |
| `tms.capitalone.com` | `||tms.capitalone.com^` | AdGuard DNS filter | `@@||tms.capitalone.com^` | AdGuard DNS filter | 精确 |
| `hb.afl.rakuten.co.jp` | `||hb.afl.rakuten.co.jp^` | AdGuard DNS filter | `@@||hb.afl.rakuten.co.jp^` | AdGuard DNS filter | 精确 |

## 八、$ 修饰符分布

> V5 保留 `$` 修饰符（important / badfilter 等），这些列表是 AdGuard Home 语法适配的，修饰符有 DNS 层语义。

| 修饰符 | 规则数 | 占比 |
|--------|--------|------|
| `$important` | 5 | 50.0% |
| `$badfilter` | 5 | 50.0% |

## 九、白名单威胁情报审计

> 七层防御体系：DNS解析 → URLhaus/ThreatFox威胁情报 → RDAP域名年龄 → MarketNow诈骗检测 → VirusTotal(可选) → 离线PSL分类 → AI语义分类(可选)。🔴 恶意建议移除此白名单；🟡 可疑需人工确认；🟢 安全可放心放行。需在配置中启用 `whitelist_audit.enabled`。

*审计未启用或无域名规则*

## 十、规则语法支持度

| 规则类型 | 语法示例 | 状态 | 处理方式 | 数量 |
|---------|---------|------|---------|------|
| Block 域名 | `||example.com^` | ✅ 支持 | 核心输出 | 3,147,068 |
| 通配符 | `||*.example.com^` | ✅ 支持 | 聚合覆盖子域 | 1 |
| Allow 白名单 | `@@||example.com^` | ✅ 支持 | 分离到 whitelist.txt | 226 |
| 正则 | `/ads.*/` | ✅ 保留 | 原样保留 | 63 |
| IP 规则 | `||8.8.8.8^` | ✅ 支持 | 按域名字符串处理 | 72 |
| Hosts | `0.0.0.0 example.com` | ✅ 支持 | 转换为 `||domain^` | - |
| $ 修饰符 | `||x.com^$important` | ✅ 保留 | 保留修饰符，纳入去重键，跳过聚合，$important 抗白名单 | 10 |
| CSS/JS | `##.ad` | ❌ 丢弃 | DNS 层不支持 | 0 |

## 十一、域名后缀 Top 20

| 后缀 | 规则数 |
|------|--------|
| fbcdn.net | 6,760 |
| weebly.com | 4,615 |
| cloudfront.net | 3,482 |
| hl.cn | 2,636 |
| wixstudio.com | 2,256 |
| web.app | 2,067 |
| amazonaws.com | 2,021 |
| firebaseapp.com | 1,995 |
| eu.cc | 1,894 |
| pages.dev | 1,843 |
| r2.dev | 1,769 |
| run.app | 1,211 |
| sa.com | 1,196 |
| ru.com | 1,083 |
| vercel.app | 1,028 |
| my.id | 995 |
| framer.app | 939 |
| appspot.com | 841 |
| biz.id | 793 |
| za.com | 718 |

## 十二、性能与诊断

| 指标 | 数值 |
|------|------|
| 总耗时 | 45.7s |
| 源成功率 | 18/18 |
| 缓存命中 | 18 |
| 精确去重 | 584,118 |
| 规范化去重 | 4,901 |
| 正则去重 | 0 |
| 质量过滤丢弃 | 38 |
| 模式丢弃 | 878 |
| CSS 丢弃 | 0 |
| 本次新增域名 | 0 |
| 本次移除域名 | 0 |
| 平均域名长度 | 16.8 字符 |
| 最短/最长域名 | 2 / 130 字符 |

---
*AdGuard Rules Merger V5 · 自动生成 · 2026-09-23*
