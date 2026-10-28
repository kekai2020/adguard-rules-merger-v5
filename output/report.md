# AdGuard Rules Merger V5 — 规则分析报告

> 生成时间：2026-10-28 03:19:26 | 源：18/18 | 缓存命中：8

## 一、概览

| 指标 | 数值 |
|------|------|
| Block 规则 | 2,947,485 |
| Allow 白名单 | 272 |
| 综合去重率 | 20.7% |
| 聚合精简 | 35,550 |
| 冲突消解 | 34 |
| 带 $ 修饰符规则 | 5 |
| 总耗时 | 96.3s |

## 二、优化流水线

| 阶段 | 规则数 | 本阶段减少 |
|------|--------|-----------|
| 原始规则（Raw） | 3,716,683 | - |
| 去重后（精确 729,379 / 规范化 3,795 / 正则 0） | 2,983,509 | -733,174 |
| 聚合后（精确 35,548 / 通配符 2 / 升级 0） | 2,947,959 | -35,550 |
| 冲突消解后 | 2,947,757 | -34 |

## 三、规则类型与类别分布

### 规则类型

| 类型 | 数量 |
|------|------|
| domain | 2,947,624 |
| ip | 72 |
| regex | 61 |

### 类别分布（Block）

| 类别 | 数量 |
|------|------|
| malware | 2,095,816 |
| other | 502,718 |
| ads | 286,932 |
| phishing | 61,480 |
| tracking | 375 |
| mining | 164 |

## 四、按源贡献分析

| 源 | 原始规则 | 独占规则 | 与其他源共享 | 独占率 |
|------|---------|---------|-------------|--------|
| HaGeZi's Threat Intelligence Feeds | 2,096,631 | 1,801,836 | 292,849 | 86% |
| HaGeZi's Gambling Blocklist | 618,850 | 486,890 | 131,917 | 79% |
| HaGeZi's Ultimate Blocklist | 247,533 | 84,811 | 161,332 | 34% |
| Phishing Army | 152,920 | 43,099 | 88,135 | 33% |
| HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 16,271 | 14,538 | 1,461 | 91% |
| CHN: AdRules DNS List | 204,142 | 11,909 | 188,213 | 6% |
| CHN: anti-AD | 104,572 | 11,368 | 92,466 | 11% |
| AdGuard DNS filter | 184,161 | 5,156 | 176,526 | 3% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 25,359 | 2,474 | 20,974 | 11% |
| ShadowWhisperer's Dating List | 1,390 | 1,289 | 92 | 93% |
| Malicious URL Blocklist (URLHaus) | 1,817 | 609 | 1,111 | 35% |
| Stalkerware Indicators List | 938 | 429 | 79 | 84% |
| HaGeZi's DNS Rebind Protection | 66 | 45 | 0 | 100% |
| OISD Blocklist Small | 59,456 | 6 | 57,887 | 0% |
| Scam Blocklist by DurableNapkin | 946 | 4 | 930 | 0% |
| NoCoin Filter List | 321 | 3 | 266 | 1% |
| HaGeZi's Windows/Office Tracker Blocklist | 392 | 1 | 374 | 0% |
| AWAvenue Ads Rule | 918 | 0 | 754 | 0% |

## 五、源间重复矩阵 Top 20

> 每对源共同拥有的规则数；覆盖率 = 重复数 / 该源去重后有效规则数。

| 源 A | 源 B | 共同规则数 | A 覆盖率 | B 覆盖率 |
|------|------|-----------|---------|---------|
| AdGuard DNS filter | CHN: AdRules DNS List | 168,839 | 92.9% | 84.4% |
| HaGeZi's Threat Intelligence Feeds | HaGeZi's Gambling Blocklist | 130,732 | 6.2% | 21.1% |
| HaGeZi's Threat Intelligence Feeds | HaGeZi's Ultimate Blocklist | 90,936 | 4.3% | 36.9% |
| CHN: anti-AD | CHN: AdRules DNS List | 85,023 | 81.9% | 42.5% |
| CHN: AdRules DNS List | HaGeZi's Ultimate Blocklist | 81,161 | 40.6% | 33.0% |
| AdGuard DNS filter | HaGeZi's Ultimate Blocklist | 80,092 | 44.1% | 32.5% |
| AdGuard DNS filter | CHN: anti-AD | 75,368 | 41.5% | 72.6% |
| Phishing Army | HaGeZi's Threat Intelligence Feeds | 72,380 | 55.2% | 3.5% |
| CHN: anti-AD | HaGeZi's Ultimate Blocklist | 60,594 | 58.4% | 24.6% |
| HaGeZi's Ultimate Blocklist | OISD Blocklist Small | 57,741 | 23.5% | 99.7% |
| CHN: AdRules DNS List | OISD Blocklist Small | 54,214 | 27.1% | 93.6% |
| AdGuard DNS filter | OISD Blocklist Small | 53,651 | 29.5% | 92.7% |
| CHN: anti-AD | OISD Blocklist Small | 41,004 | 39.5% | 70.8% |
| CHN: AdRules DNS List | HaGeZi's Threat Intelligence Feeds | 26,606 | 13.3% | 1.3% |
| AdGuard DNS filter | HaGeZi's Threat Intelligence Feeds | 25,461 | 14.0% | 1.2% |
| HaGeZi's Threat Intelligence Feeds | OISD Blocklist Small | 22,368 | 1.1% | 38.6% |
| CHN: anti-AD | HaGeZi's Threat Intelligence Feeds | 20,678 | 19.9% | 1.0% |
| Phishing Army | Phishing URL Blocklist (PhishTank and OpenPhish) | 20,285 | 15.5% | 86.5% |
| Phishing Army | HaGeZi's Ultimate Blocklist | 6,141 | 4.7% | 2.5% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | HaGeZi's Threat Intelligence Feeds | 5,247 | 22.4% | 0.3% |

## 六、各源自去重率

> 有效规则数 = 去重后该源仍覆盖的规则数；自去重率 = 1 - 有效/原始。

| 源 | 原始规则 | 去重后有效 | 自去重率 |
|------|---------|-----------|---------|
| HaGeZi's Threat Intelligence Feeds | 2,096,631 | 2,094,685 | 0.1% |
| HaGeZi's Gambling Blocklist | 618,850 | 618,807 | 0.0% |
| HaGeZi's Ultimate Blocklist | 247,533 | 246,143 | 0.6% |
| CHN: AdRules DNS List | 204,142 | 200,122 | 2.0% |
| AdGuard DNS filter | 184,161 | 181,682 | 1.3% |
| Phishing Army | 152,920 | 131,234 | 14.2% |
| CHN: anti-AD | 104,572 | 103,834 | 0.7% |
| OISD Blocklist Small | 59,456 | 57,893 | 2.6% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 25,359 | 23,448 | 7.5% |
| HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 16,271 | 15,999 | 1.7% |
| Malicious URL Blocklist (URLHaus) | 1,817 | 1,720 | 5.3% |
| ShadowWhisperer's Dating List | 1,390 | 1,381 | 0.6% |
| Scam Blocklist by DurableNapkin | 946 | 934 | 1.3% |
| AWAvenue Ads Rule | 918 | 754 | 17.9% |
| Stalkerware Indicators List | 938 | 508 | 45.8% |
| HaGeZi's Windows/Office Tracker Blocklist | 392 | 375 | 4.3% |
| NoCoin Filter List | 321 | 269 | 16.2% |
| HaGeZi's DNS Rebind Protection | 66 | 45 | 31.8% |

## 七、冲突分析（白名单覆盖拦截）

> 被白名单移除的拦截规则；展示双方来源。精确=域名完全匹配，级联=白名单父域覆盖子域。

| 域名 | 被拦规则 | 被拦来源 | 白名单规则 | 白名单来源 | 类型 |
|------|---------|---------|-----------|-----------|------|
| `googleadservices.com` | `||googleadservices.com^` | AdGuard DNS filter, CHN: anti-AD, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist, OISD Blocklist Small, AWAvenue Ads Rule | `@@||googleadservices.com^` | AdGuard DNS filter | 精确 |
| `proto2ad.durasite.net` | `||proto2ad.durasite.net^` | AdGuard DNS filter, CHN: anti-AD, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist, OISD Blocklist Small | `@@||proto2ad.durasite.net^` | AdGuard DNS filter | 精确 |
| `afi-b.com` | `||afi-b.com^` | AdGuard DNS filter, CHN: anti-AD, HaGeZi's Ultimate Blocklist | `@@||afi-b.com^` | AdGuard DNS filter | 精确 |
| `awin1.com` | `||awin1.com^` | AdGuard DNS filter, CHN: anti-AD, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@||awin1.com^` | AdGuard DNS filter | 精确 |
| `om-ssl.consorsbank.de` | `||om-ssl.consorsbank.de^` | AdGuard DNS filter, CHN: anti-AD, CHN: AdRules DNS List | `@@||om-ssl.consorsbank.de^` | AdGuard DNS filter | 精确 |
| `data.digital.costco.ca` | `||data.digital.costco.ca^` | AdGuard DNS filter, CHN: anti-AD, CHN: AdRules DNS List | `@@||data.digital.costco.ca^` | AdGuard DNS filter | 精确 |
| `data.digital.costco.com` | `||data.digital.costco.com^` | AdGuard DNS filter, CHN: anti-AD, CHN: AdRules DNS List | `@@||data.digital.costco.com^` | AdGuard DNS filter | 精确 |
| `data.orders.costco.com` | `||data.orders.costco.com^` | AdGuard DNS filter, CHN: anti-AD, CHN: AdRules DNS List | `@@||data.orders.costco.com^` | AdGuard DNS filter | 精确 |
| `datadoghq-browser-agent.com` | `||datadoghq-browser-agent.com^` | AdGuard DNS filter, CHN: anti-AD, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@||datadoghq-browser-agent.com^` | AdGuard DNS filter | 精确 |
| `marketing.net.idealo-partner.com` | `||marketing.net.idealo-partner.com^` | AdGuard DNS filter, CHN: anti-AD, CHN: AdRules DNS List | `@@||marketing.net.idealo-partner.com^` | AdGuard DNS filter | 精确 |
| `jdoqocy.com` | `||jdoqocy.com^` | AdGuard DNS filter, CHN: anti-AD, CHN: AdRules DNS List | `@@||jdoqocy.com^` | AdGuard DNS filter | 精确 |
| `omsc.kpn.com` | `||omsc.kpn.com^` | AdGuard DNS filter, CHN: anti-AD, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@||omsc.kpn.com^` | AdGuard DNS filter | 精确 |
| `torimochi.line-apps.com` | `||torimochi.line-apps.com^` | CHN: anti-AD | `@@||torimochi.line-apps.com^` | AdGuard DNS filter | 精确 |
| `logentries.com` | `||logentries.com^` | AdGuard DNS filter, CHN: anti-AD, HaGeZi's Ultimate Blocklist | `@@||logentries.com^` | AdGuard DNS filter | 精确 |
| `sedge.nfl.com` | `||sedge.nfl.com^` | AdGuard DNS filter, CHN: anti-AD, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@||sedge.nfl.com^` | AdGuard DNS filter | 精确 |
| `cmp.osano.com` | `||cmp.osano.com^` | CHN: anti-AD, CHN: AdRules DNS List | `@@||cmp.osano.com^` | AdGuard DNS filter | 精确 |
| `data.promo.timhortons.ca` | `||data.promo.timhortons.ca^` | AdGuard DNS filter, CHN: anti-AD, CHN: AdRules DNS List | `@@||data.promo.timhortons.ca^` | AdGuard DNS filter | 精确 |
| `hb.afl.rakuten.co.jp` | `||hb.afl.rakuten.co.jp^` | AdGuard DNS filter | `@@||hb.afl.rakuten.co.jp^` | AdGuard DNS filter | 精确 |
| `data.notify.macys.com` | `||data.notify.macys.com^` | AdGuard DNS filter, CHN: AdRules DNS List | `@@||data.notify.macys.com^` | AdGuard DNS filter | 精确 |
| `data.orders.costco.ca` | `||data.orders.costco.ca^` | AdGuard DNS filter, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@||data.orders.costco.ca^` | AdGuard DNS filter | 精确 |
| `omniture.walmart.com` | `||omniture.walmart.com^` | AdGuard DNS filter, CHN: AdRules DNS List | `@@||omniture.walmart.com^` | AdGuard DNS filter | 精确 |
| `swasc.homedepot.com` | `||swasc.homedepot.com^` | AdGuard DNS filter, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@||swasc.homedepot.com^` | AdGuard DNS filter | 精确 |
| `tms.capitalone.com` | `||tms.capitalone.com^` | AdGuard DNS filter | `@@||tms.capitalone.com^` | AdGuard DNS filter | 精确 |
| `belgium.wolterskluwer.com` | `||belgium.wolterskluwer.com^` | AdGuard DNS filter, CHN: AdRules DNS List | `@@||belgium.wolterskluwer.com^` | AdGuard DNS filter | 精确 |
| `statcounter.com` | `||statcounter.com^` | AdGuard DNS filter, CHN: anti-AD, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist, OISD Blocklist Small | `@@||statcounter.com^` | AdGuard DNS filter | 精确 |
| `aax-fe.amazon.co.jp` | `||aax-fe.amazon.co.jp^` | HaGeZi's Ultimate Blocklist | `@@||aax-fe.amazon.co.jp^` | AdGuard DNS filter | 精确 |
| `sax.sina.com.cn` | `||sax.sina.com.cn^` | AdGuard DNS filter, CHN: anti-AD, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist, OISD Blocklist Small | `@@||sax.sina.com.cn^` | AdGuard DNS filter | 精确 |
| `ad.cityu.edu.hk` | `||ad.cityu.edu.hk^` | HaGeZi's Ultimate Blocklist | `@@||ad.cityu.edu.hk^` | CHN: anti-AD | 精确 |
| `api.karte.io` | `||api.karte.io^` | HaGeZi's Ultimate Blocklist | `@@||api.karte.io^` | AdGuard DNS filter | 精确 |
| `settings-win.data.microsoft.com` | `||settings-win.data.microsoft.com^` | HaGeZi's Ultimate Blocklist | `@@||settings-win.data.microsoft.com^` | CHN: anti-AD | 精确 |
| `global.api.huangye.miui.com` | `||global.api.huangye.miui.com^` | HaGeZi's Ultimate Blocklist | `@@||api.huangye.miui.com^` | CHN: anti-AD | 级联 |
| `ads.privacy.qq.com` | `||ads.privacy.qq.com^` | HaGeZi's Ultimate Blocklist | `@@||ads.privacy.qq.com^` | CHN: anti-AD | 精确 |
| `ad.10010.com` | `||ad.10010.com^` | CHN: anti-AD, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist, OISD Blocklist Small, AWAvenue Ads Rule | `@@||ad.10010.com^` | AdGuard DNS filter | 精确 |
| `ad.ourgame.com` | `||ad.ourgame.com^` | CHN: AdRules DNS List | `@@||ad.ourgame.com^` | AdGuard DNS filter | 精确 |

## 八、$ 修饰符分布

> V5 保留 `$` 修饰符（important / badfilter 等），这些列表是 AdGuard Home 语法适配的，修饰符有 DNS 层语义。

| 修饰符 | 规则数 | 占比 |
|--------|--------|------|
| `$important` | 5 | 100.0% |

## 九、白名单威胁情报审计

> 七层防御体系：DNS解析 → URLhaus/ThreatFox威胁情报 → RDAP域名年龄 → MarketNow诈骗检测 → VirusTotal(可选) → 离线PSL分类 → AI语义分类(可选)。🔴 恶意建议移除此白名单；🟡 可疑需人工确认；🟢 安全可放心放行。需在配置中启用 `whitelist_audit.enabled`。

- 🔴 恶意：0
- 🟡 可疑：23
- 🟢 安全：216
- ⚪ 未知：32

### 防御层概览

| 层级 | 检测内容 | 状态 | 成本 | 命中数 |
|------|---------|------|------|--------|
| DNS 解析 | NXDOMAIN/私有IP检测 | ✅ 启用 | 免费 | 23 |
| URLhaus | 恶意软件分发域名 | ✅ 启用 | 免费 | 0 |
| ThreatFox | C2 命令控制域名 | ✅ 启用 | 免费 | 0 |
| RDAP 域名年龄 | 新注册域名<30天标记 | ✅ 启用 | 免费 | 0 |
| MarketNow 诈骗检测 | 拼写劫持/可疑TLD/未注册 | ✅ 启用 | 免费 | 0 |
| VirusTotal | 多引擎厂商信誉 | ⬜ 未启用 | 需API Key | - |
| AI/LLM 分类 | 低置信度域名语义分类 | ⬜ 未启用 | 需API Key | - |

### 白名单域名类别分布

| 类别 | 数量 | 占比 |
|------|------|------|
| 广告/营销 | 18 | 6.6% |
| 分析/追踪 | 9 | 3.3% |
| CDN/基础设施 | 8 | 3.0% |
| 微软/Windows 遥测 | 12 | 4.4% |
| 联盟营销/跳转 | 23 | 8.5% |
| 社交/分享 | 4 | 1.5% |
| 电商/支付 | 10 | 3.7% |
| 隐私/安全 | 7 | 2.6% |
| 其他 | 180 | 66.4% |

### 分类置信度分布

> 高置信度=注册域名精确匹配(PSL)，可直接信任；中置信度=子域名前缀匹配，建议人工确认；低置信度=无法分类，需外部API或人工判断。

| 置信度等级 | 数量 | 占比 |
|-----------|------|------|
| 高置信度 (注册域名匹配) | 55 | 20.3% |
| 中置信度 (子域名前缀) | 36 | 13.3% |
| 低置信度 (无法分类) | 180 | 66.4% |

| 域名 | 评级 | 类别 | 置信度 | 原因 | 来源 |
|------|------|------|--------|------|------|
| `a.adwolf.ru` | 🟡 可疑 | 广告/营销 | 0.90 | DNS NXDOMAIN（域名已过期，白名单可能无效） | AdGuard DNS filter |
| `ad.cityu.edu.hk` | 🟡 可疑 | 广告/营销 | 0.60 | 解析到私有/回环 IP: ['172.26.255.1', '172.26.255.2', '172.26.255.11', '172.26.255.12'] | CHN: anti-AD |
| `ads.tdbank.com` | 🟡 可疑 | 广告/营销 | 0.60 | DNS NXDOMAIN（域名已过期，白名单可能无效） | AdGuard DNS filter |
| `avqs.mcafee.com` | 🟡 可疑 | 隐私/安全 | 0.90 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `avts.mcafee.com` | 🟡 可疑 | 隐私/安全 | 0.90 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `cloud.notification-naviextras.com` | 🟡 可疑 | 其他 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | AdGuard DNS filter |
| `dishy.starlink.com` | 🟡 可疑 | 其他 | 0.00 | 解析到私有/回环 IP: ['192.168.100.1'] | HaGeZi's DNS Rebind Protection |
| `dns.msftncsi.com` | 🟡 可疑 | 微软/Windows 遥测 | 0.90 | 解析到私有/回环 IP: ['131.107.255.255', 'fd3e:4f5a:5b81::1'] | HaGeZi's DNS Rebind Protection |
| `edge-enterprise.activity.windows.com` | 🟡 可疑 | 微软/Windows 遥测 | 0.90 | 解析到私有/回环 IP: ['127.0.0.1'] | CHN: anti-AD |
| `edge.activity.windows.com` | 🟡 可疑 | 微软/Windows 遥测 | 0.90 | 解析到私有/回环 IP: ['127.0.0.1'] | CHN: anti-AD |
| `email.procook.co.uk` | 🟡 可疑 | 其他 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | AdGuard DNS filter |
| `fritz.nas` | 🟡 可疑 | 其他 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `fritz.powerline` | 🟡 可疑 | 其他 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `fritz.repeater` | 🟡 可疑 | 其他 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `fritz.smartgateway` | 🟡 可疑 | 其他 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `guce.advertising.com` | 🟡 可疑 | 广告/营销 | 0.90 | DNS NXDOMAIN（域名已过期，白名单可能无效） | AdGuard DNS filter |
| `meizu.coapi.moji.com` | 🟡 可疑 | 其他 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | CHN: anti-AD |
| `plex.direct` | 🟡 可疑 | 其他 | 0.00 | 解析到私有/回环 IP: ['0.0.0.0'] | HaGeZi's DNS Rebind Protection |
| `router.asus.com` | 🟡 可疑 | 其他 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `speedport.ip` | 🟡 可疑 | 其他 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `sponsor.nitropay.com` | 🟡 可疑 | 其他 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | AdGuard DNS filter |
| `thumbnail.thench.net` | 🟡 可疑 | 其他 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | AdGuard DNS filter |
| `tlaol.com` | 🟡 可疑 | 其他 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | AdGuard DNS filter |
| `3gppnetwork.org` | ⚪ 未知 | 其他 | 0.00 | 检测不完整：DNS 查询失败 ([Errno -5] No address associated with hostname)，威胁情报无有效命中 | HaGeZi's DNS Rebind Protection |
| `ad.10010.com` | ⚪ 未知 | 广告/营销 | 0.60 | 检测不完整：DNS 查询失败 ([Errno -5] No address associated with hostname)，威胁情报无有效命中 | AdGuard DNS filter |
| `ad.abchina.com` | ⚪ 未知 | 广告/营销 | 0.60 | 检测不完整：DNS 查询失败 ([Errno -5] No address associated with hostname)，威胁情报无有效命中 | AdGuard DNS filter |
| `ad.azure.com` | ⚪ 未知 | 微软/Windows 遥测 | 0.90 | 检测不完整：DNS 查询失败 ([Errno -5] No address associated with hostname)，威胁情报无有效命中 | CHN: anti-AD |
| `adcdn.pingan.com` | ⚪ 未知 | 其他 | 0.00 | 检测不完整：DNS 查询失败 ([Errno -5] No address associated with hostname)，威胁情报无有效命中 | AdGuard DNS filter |
| `analysis.windows.net` | ⚪ 未知 | 微软/Windows 遥测 | 0.90 | 检测不完整：DNS 查询失败 ([Errno -5] No address associated with hostname)，威胁情报无有效命中 | CHN: anti-AD |
| `asusrouter.com` | ⚪ 未知 | 其他 | 0.00 | 检测不完整：DNS 查询失败 ([Errno -5] No address associated with hostname)，威胁情报无有效命中 | HaGeZi's DNS Rebind Protection |
| `b.barracudacentral.org` | ⚪ 未知 | 其他 | 0.00 | 检测不完整：DNS 查询失败 ([Errno -5] No address associated with hostname)，威胁情报无有效命中 | HaGeZi's DNS Rebind Protection |
| `bl.blocklist.de` | ⚪ 未知 | 其他 | 0.00 | 检测不完整：DNS 查询失败 ([Errno -5] No address associated with hostname)，威胁情报无有效命中 | HaGeZi's DNS Rebind Protection |
| `buyad.bi-xenon.cn` | ⚪ 未知 | 其他 | 0.00 | 检测不完整：DNS 查询失败 ([Errno -5] No address associated with hostname)，威胁情报无有效命中 | AdGuard DNS filter |
| `datadoghq-browser-agent.com` | ⚪ 未知 | 其他 | 0.00 | 检测不完整：DNS 查询失败 ([Errno -5] No address associated with hostname)，威胁情报无有效命中 | AdGuard DNS filter |
| `direct.quickconnect.to` | ⚪ 未知 | 其他 | 0.00 | 检测不完整：DNS 查询失败 ([Errno -5] No address associated with hostname)，威胁情报无有效命中 | HaGeZi's DNS Rebind Protection |
| `dnsbl.dronebl.org` | ⚪ 未知 | 其他 | 0.00 | 检测不完整：DNS 查询失败 ([Errno -5] No address associated with hostname)，威胁情报无有效命中 | HaGeZi's DNS Rebind Protection |
| `dq.spamhaus.net` | ⚪ 未知 | 其他 | 0.00 | 检测不完整：DNS 查询失败 ([Errno -5] No address associated with hostname)，威胁情报无有效命中 | HaGeZi's DNS Rebind Protection |
| `dxcloud.episerver.net` | ⚪ 未知 | 其他 | 0.00 | 检测不完整：DNS 查询失败 ([Errno -5] No address associated with hostname)，威胁情报无有效命中 | CHN: anti-AD |
| `envato.market` | ⚪ 未知 | 其他 | 0.00 | 检测不完整：DNS 查询失败 ([Errno -5] No address associated with hostname)，威胁情报无有效命中 | AdGuard DNS filter |
| `jdoqocy.com` | ⚪ 未知 | 其他 | 0.00 | 检测不完整：DNS 查询失败 ([Errno -5] No address associated with hostname)，威胁情报无有效命中 | AdGuard DNS filter |
| `leechers-paradise.org` | ⚪ 未知 | 其他 | 0.00 | 检测不完整：DNS 查询失败 ([Errno -5] No address associated with hostname)，威胁情报无有效命中 | AdGuard DNS filter |
| `mail.abusix.zone` | ⚪ 未知 | 其他 | 0.00 | 检测不完整：DNS 查询失败 ([Errno -5] No address associated with hostname)，威胁情报无有效命中 | HaGeZi's DNS Rebind Protection |
| `mailspike.net` | ⚪ 未知 | 其他 | 0.00 | 检测不完整：DNS 查询失败 ([Errno -5] No address associated with hostname)，威胁情报无有效命中 | HaGeZi's DNS Rebind Protection |
| `msftconnecttest.com` | ⚪ 未知 | 微软/Windows 遥测 | 0.90 | 检测不完整：DNS 查询失败 ([Errno -5] No address associated with hostname)，威胁情报无有效命中 | CHN: anti-AD |
| `myunraid.net` | ⚪ 未知 | 其他 | 0.00 | 检测不完整：DNS 查询失败 ([Errno -5] No address associated with hostname)，威胁情报无有效命中 | HaGeZi's DNS Rebind Protection |
| `redir.tradedoubler.com` | ⚪ 未知 | 联盟营销/跳转 | 0.90 | 检测不完整：DNS 查询失败 ([Errno -5] No address associated with hostname)，威胁情报无有效命中 | AdGuard DNS filter |
| `sophosxl.net` | ⚪ 未知 | 其他 | 0.00 | 检测不完整：DNS 查询失败 ([Errno -5] No address associated with hostname)，威胁情报无有效命中 | HaGeZi's DNS Rebind Protection |
| `stats.gov.cn` | ⚪ 未知 | 其他 | 0.00 | 检测不完整：DNS 查询失败 ([Errno -5] No address associated with hostname)，威胁情报无有效命中 | CHN: anti-AD |
| `tj.gov.cn` | ⚪ 未知 | 其他 | 0.00 | 检测不完整：DNS 查询失败 (timeout)，威胁情报无有效命中 | CHN: anti-AD |
| `tongji.cn` | ⚪ 未知 | 其他 | 0.00 | 检测不完整：DNS 查询失败 ([Errno -5] No address associated with hostname)，威胁情报无有效命中 | CHN: anti-AD |
| `tongji.edu.cn` | ⚪ 未知 | 其他 | 0.00 | 检测不完整：DNS 查询失败 ([Errno -5] No address associated with hostname)，威胁情报无有效命中 | CHN: anti-AD |
| `tor.dan.me.uk` | ⚪ 未知 | 其他 | 0.00 | 检测不完整：DNS 查询失败 ([Errno -5] No address associated with hostname)，威胁情报无有效命中 | HaGeZi's DNS Rebind Protection |
| `torexit.dan.me.uk` | ⚪ 未知 | 其他 | 0.00 | 检测不完整：DNS 查询失败 ([Errno -5] No address associated with hostname)，威胁情报无有效命中 | HaGeZi's DNS Rebind Protection |
| `tplinklogin.net` | ⚪ 未知 | 其他 | 0.00 | 检测不完整：DNS 查询失败 (timeout)，威胁情报无有效命中 | HaGeZi's DNS Rebind Protection |
| `uceprotect.net` | ⚪ 未知 | 其他 | 0.00 | 检测不完整：DNS 查询失败 ([Errno -5] No address associated with hostname)，威胁情报无有效命中 | HaGeZi's DNS Rebind Protection |
| `5471782.fls.doubleclick.net` | 🟢 安全 | 广告/营销 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `79423.analytics.edgekey.net` | 🟢 安全 | CDN/基础设施 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `a.sellpoint.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `aax-fe.amazon.co.jp` | 🟢 安全 | 联盟营销/跳转 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ac.ebis.ne.jp` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `acs-m.daraz.com.bd` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `acs-m.daraz.pk` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `action.metaffiliation.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ad-block.dns.adguard.com` | 🟢 安全 | 隐私/安全 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `ad-gone.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `ad-putting.gw.zt-express.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `ad.kazakinfo.com` | 🟢 安全 | 广告/营销 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ad.ourgame.com` | 🟢 安全 | 广告/营销 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ad.siemens.com.cn` | 🟢 安全 | 广告/营销 | 0.60 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `admin.dable.io` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ads.finance` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `ads.privacy.qq.com` | 🟢 安全 | 社交/分享 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `ads.taboola.com` | 🟢 安全 | 广告/营销 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `advert.kf5.com` | 🟢 安全 | 广告/营销 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `advertisement.taobao.com` | 🟢 安全 | 电商/支付 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `afi-b.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `analysis.chess.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `analytics.amplitude.com` | 🟢 安全 | 分析/追踪 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `anwb.webpower.eu` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ap01.records.in.treasuredata.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `api.ads.tvb.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `api.docodoco.jp` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `api.huangye.miui.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `api.karte.io` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `app-advertise.zhihuishu.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `app.adjust.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter, CHN: anti-AD |
| `app.appsflyer.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `app.powerbi.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `artifactory.appodeal.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `autocomplete.clearbit.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `awin1.com` | 🟢 安全 | 联盟营销/跳转 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `backscatterer.org` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `baozhang.baidu.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `belgium.wolterskluwer.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `bl.spamcop.net` | 🟢 安全 | 隐私/安全 | 0.90 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `c.office.com` | 🟢 安全 | 微软/Windows 遥测 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `captcha.su.baidu.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `catchup.thisisdax.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `cdn.atmedia.hu` | 🟢 安全 | CDN/基础设施 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `cdn.duurzaam.greenchoice.nl` | 🟢 安全 | CDN/基础设施 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `cdn.rozetka.com.ua` | 🟢 安全 | CDN/基础设施 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `center-h5api.m.taobao.com` | 🟢 安全 | 电商/支付 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `chart-embed.service.newrelic.com` | 🟢 安全 | 分析/追踪 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `cindyholbrook.lpages.co` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `citiintl.122.2o7.net` | 🟢 安全 | 分析/追踪 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `cj.dotomi.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `cl.link-ag.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `classliving.lpages.co` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `click.appcast.io` | 🟢 安全 | 联盟营销/跳转 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `click.avs.io` | 🟢 安全 | 联盟营销/跳转 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `click.cptrack.de` | 🟢 安全 | 联盟营销/跳转 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `click.simba.taobao.com` | 🟢 安全 | 电商/支付 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `click.trafficguard.ai` | 🟢 安全 | 联盟营销/跳转 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `click.virt.exacttarget.com` | 🟢 安全 | 联盟营销/跳转 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `clickattr.wayup.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `cm-beacon.nakanohito.jp` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `cm-widget.nakanohito.jp` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `cmp.inmobi.com` | 🟢 安全 | 广告/营销 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `cmp.osano.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `content.viralize.tv` | 🟢 安全 | CDN/基础设施 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `counter-strike.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `crm-cdn.peek-cloppenburg.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `cs.silverpop.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `cutcaptcha.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `daikoku.ebis.ne.jp` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `data.digital.costco.ca` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `data.digital.costco.com` | 🟢 安全 | 电商/支付 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `data.notify.macys.com` | 🟢 安全 | 电商/支付 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `data.orders.costco.ca` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `data.orders.costco.com` | 🟢 安全 | 电商/支付 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `data.promo.timhortons.ca` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `dnswl.org` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `dogpile.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `e.customeriomail.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `email.awscloud.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `email.elitedangerous.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `emails.educause.edu` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `f-gear.ec-optimizer.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `feed.adrelayer.com` | 🟢 安全 | 社交/分享 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `forum.notebookreview.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `fritz.box` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `ftp.bmp.ovh` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `future.biz.weibo.com` | 🟢 安全 | 社交/分享 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `gate.first-id.fr` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `get.neofinancial.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `go.adjust.com` | 🟢 安全 | 联盟营销/跳转 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `go.redirectingat.com` | 🟢 安全 | 联盟营销/跳转 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `go.scorptec.com.au` | 🟢 安全 | 联盟营销/跳转 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `googleadservices.com` | 🟢 安全 | 广告/营销 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `goto.target.com` | 🟢 安全 | 电商/支付 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `goto.walmart.com` | 🟢 安全 | 电商/支付 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `grp07.ias.rakuten.co.jp` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `gs.statcounter.com` | 🟢 安全 | 分析/追踪 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `hash.cymru.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `hb.afl.rakuten.co.jp` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `health.halodoc.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `hidive.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `home.focusatwill.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `hostkarma.junkemailfilter.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `href.li` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ia.hit.interia.pl` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `id.i2i.jp` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `img.ads.tvb.com` | 🟢 安全 | CDN/基础设施 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `infra-api.newrelic.com` | 🟢 安全 | 分析/追踪 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `insideruser.microsoft.com` | 🟢 安全 | 微软/Windows 遥测 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `intersport.peerius.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ipv4only.arpa` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `itoya.ec-optimizer.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `js.monitor.azure.com` | 🟢 安全 | 微软/Windows 遥测 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `learn.khanacademy.org` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `link.meet5.net` | 🟢 安全 | 联盟营销/跳转 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `link.morningbrew.com` | 🟢 安全 | 联盟营销/跳转 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `link.nzz.ch` | 🟢 安全 | 联盟营销/跳转 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `link.sylikes.com` | 🟢 安全 | 联盟营销/跳转 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `linka.page` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `links.e.theatlantic.com` | 🟢 安全 | 联盟营销/跳转 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `links.getblueshift.com` | 🟢 安全 | 联盟营销/跳转 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `log.mmstat.com` | 🟢 安全 | CDN/基础设施 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter, CHN: anti-AD |
| `logentries.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `login.sendpulse.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ma135-r.analytics.edgekey.net` | 🟢 安全 | CDN/基础设施 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `marketing.net.idealo-partner.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `media-consumer365.desigual.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `my.tealiumiq.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `netatmo.commander1.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `news-app.abumedia.yql.yahoo.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `news.warhammer.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `nineto5mac-d.openx.net` | 🟢 安全 | 广告/营销 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `nordspam.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `oa.tr.line.me` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `obituaries.startribune.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `obituaries.therecord.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `obituaries.thestar.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `obituaries.toacorn.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `official.paymaya.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `om-ssl.consorsbank.de` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `omniture.walmart.com` | 🟢 安全 | 电商/支付 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `omsc.kpn.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `oneline.nextday.media` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `pagead.l.doubleclick.net` | 🟢 安全 | 广告/营销 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `partner.everydays.de` | 🟢 安全 | 联盟营销/跳转 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `partner.o2online.de` | 🟢 安全 | 联盟营销/跳转 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `passport.bobo.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `prod.impartner.live` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `promo.gramedia.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `proto2ad.durasite.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `psbl.surriel.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `pt.afl.rakuten.co.jp` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `public-cis.exponea.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `puzzles-games-api.gp-prod.conde.digital` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `px.a8.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `radiofrance.targetspot.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `rd.bizrate.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `recommender.scarabresearch.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `redir.ownpage.fr` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `redirect.appmetrica.yandex.com` | 🟢 安全 | 联盟营销/跳转 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ref.rbauction.com` | 🟢 安全 | 联盟营销/跳转 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `refer.discover.com` | 🟢 安全 | 联盟营销/跳转 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `remembering.ca` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `res.ads.nicovideo.jp` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `routerlogin.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `routerlogin.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `s.bluecore.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `s.mvconf.f.360.cn` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `sax.sina.com.cn` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `sbs.demdex.net` | 🟢 安全 | 分析/追踪 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `sdkapi.sms.mob.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `secureimage.securedataimages.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `sedge.nfl.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `settings-win.data.microsoft.com` | 🟢 安全 | 微软/Windows 遥测 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `skyapi.onedrive.live.com` | 🟢 安全 | 微软/Windows 遥测 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `skydrivesync.policies.live.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `smtp.focusgroupresearch.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `spameatingmonkey.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `spamhaus.org` | 🟢 安全 | 隐私/安全 | 0.90 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `spamrats.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `spartaindependent.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ssai.aniview.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `stash.roistat.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `stat.jseea.cn` | 🟢 安全 | 分析/追踪 | 0.60 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `statcounter.com` | 🟢 安全 | 分析/追踪 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `stats.uptimerobot.com` | 🟢 安全 | 分析/追踪 | 0.60 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `storage.live.com` | 🟢 安全 | 微软/Windows 遥测 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `str.hit.gemius.pl` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `support-beacon.nakanohito.jp` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `support-widget.nakanohito.jp` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `surbl.org` | 🟢 安全 | 隐私/安全 | 0.90 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `surveymyopinion.researchnow.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `swasc.homedepot.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `tags.crwdcntrl.net` | 🟢 安全 | 广告/营销 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `taiga.maven.io` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `tlh.gedidigital.it` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `tms.capitalone.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `torimochi.line-apps.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `tplinkap.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `tplinkrepeater.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `tplinkwifi.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `tr.rdrtr.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `track.rutarget.ru` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `track.webgains.com` | 🟢 安全 | 联盟营销/跳转 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `tracker.eu.org` | 🟢 安全 | 广告/营销 | 0.60 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `trk.ecomm.lenovo.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `tube.e.kuaishou.com` | 🟢 安全 | 社交/分享 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `uland.taobao.com` | 🟢 安全 | 电商/支付 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `unsubscribe.lhinsights.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `uribl.com` | 🟢 安全 | 隐私/安全 | 0.90 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `used.ca` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `validate.perfdrive.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `vcentry2.valuecommerce.ne.jp` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `vcentry3.valuecommerce.ne.jp` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `widget.intercom.io` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |

## 十、规则语法支持度

| 规则类型 | 语法示例 | 状态 | 处理方式 | 数量 |
|---------|---------|------|---------|------|
| Block 域名 | `||example.com^` | ✅ 支持 | 核心输出 | 2,947,624 |
| 通配符 | `||*.example.com^` | ✅ 支持 | 聚合覆盖子域 | 0 |
| Allow 白名单 | `@@||example.com^` | ✅ 支持 | 分离到 whitelist.txt | 272 |
| 正则 | `/ads.*/` | ✅ 保留 | 原样保留 | 61 |
| IP 规则 | `||8.8.8.8^` | ✅ 支持 | 按域名字符串处理 | 72 |
| Hosts | `0.0.0.0 example.com` | ✅ 支持 | 转换为 `||domain^` | - |
| $ 修饰符 | `||x.com^$important` | ✅ 保留 | 保留修饰符，纳入去重键，跳过聚合，$important 抗白名单 | 5 |
| CSS/JS | `##.ad` | ❌ 丢弃 | DNS 层不支持 | 0 |

## 十一、域名后缀 Top 20

| 后缀 | 规则数 |
|------|--------|
| fbcdn.net | 7,023 |
| meusitehostgator.com.br | 3,149 |
| cloudfront.net | 3,068 |
| pages.dev | 2,610 |
| wixstudio.com | 2,379 |
| eu.cc | 2,321 |
| weebly.com | 2,308 |
| web.app | 2,018 |
| firebaseapp.com | 1,926 |
| hl.cn | 1,848 |
| amazonaws.com | 1,643 |
| r2.dev | 1,431 |
| vercel.app | 1,246 |
| run.app | 1,068 |
| sa.com | 876 |
| ru.com | 832 |
| co.com | 696 |
| blogspot.com | 692 |
| allserial.icu | 639 |
| dynu.org | 601 |

## 十二、性能与诊断

| 指标 | 数值 |
|------|------|
| 总耗时 | 96.3s |
| 源成功率 | 18/18 |
| 缓存命中 | 8 |
| 精确去重 | 729,379 |
| 规范化去重 | 3,795 |
| 正则去重 | 0 |
| 质量过滤丢弃 | 37 |
| 模式丢弃 | 866 |
| CSS 丢弃 | 0 |
| 本次新增域名 | 0 |
| 本次移除域名 | 0 |
| 平均域名长度 | 17.0 字符 |
| 最短/最长域名 | 2 / 242 字符 |

---
*AdGuard Rules Merger V5 · 自动生成 · 2026-10-28*
