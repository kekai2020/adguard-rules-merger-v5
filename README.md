# AdGuard Rules Merger V5

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Tests](https://img.shields.io/badge/Tests-103%20passed-brightgreen)

自动拉取多个公开的 AdGuard / hosts / 域名规则源，完成 **解析 → 去重 → 向上聚合 → 白名单冲突消解 → 稳定排序**，导出 AdGuard Home 可直接订阅的规则文件，并生成多格式产物与可视化分析报告（HTML + Markdown）。

V5 在 V4 基础上做了一次面向正确性的重构：修复了分类失效、死配置、统计缺失、内存浪费等问题，新增通配符子规则聚合、源间重复分析、六层白名单防御审计与分类分级输出。

---

## 目录

- [功能特性](#功能特性)
- [快速开始](#快速开始)
- [处理流水线](#处理流水线)
- [配置说明](#配置说明configsourcesyaml)
- [白名单七层防御审计](#白名单七层防御审计)
- [输出文件](#输出文件output)
- [内置规则源](#内置规则源18-个)
- [在 AdGuard Home 中订阅](#在-adguard-home-中订阅)
- [GitHub Actions](#github-actions)
- [项目结构](#项目结构)
- [性能基准](#性能基准)
- [V4 → V5 变更](#v4--v5-变更)
- [常见问题](#常见问题)
- [License](#license)

---

## 功能特性

### 核心合并

- **多格式解析**：AdGuard 语法（`||domain^`、`@@||domain^`）、hosts（`0.0.0.0 domain`）、纯域名、正则（`/regex/`），自动识别并统一内部表示
- **三级去重**：精确去重（raw 完全相同）、规范化去重（如 `www` 剥离）、正则去重，分别计数
- **向上聚合**：精确子规则折叠 + 通配符子规则折叠 + 可选的子域阈值升级，大幅压缩规则体积
- **冲突消解**：白名单覆盖黑名单，支持级联子域名，`$important` 修饰符抗白名单
- **分类安全优先级**：重复域名归类时 `malware > phishing > mining > tracking > ads > other`，安全类永远胜出

### 分析与报告

- **可视化报告**：同时输出 `report.html` 和 `report.md`，含优化漏斗、分类分布、后缀 Top20、源贡献表、源间重复矩阵、冲突分析、`$` 修饰符分布
- **按源贡献分析**：`contributions.json` 给出每个源的原始规则数、独占规则数、共享规则数及独占率
- **源间重复矩阵**：量化任意两个源之间的规则重叠，帮助精简冗余源
- **规则增删 diff**：对比上一次输出，生成 `added.txt` / `removed.txt`

### 白名单七层防御审计

- 七层防御体系，**所有网络层异步并行执行**：DNS 解析 → URLhaus/ThreatFox 威胁情报 → RDAP 域名年龄 → MarketNow 诈骗检测 → VirusTotal（可选）→ PSL 离线分类 → AI 语义分类（可选）
- 对白名单域名分类评级（🔴恶意 / 🟡可疑 / 🟢安全 / ⚪未知），结果缓存 24h
- 按评级和类别拆分多个子白名单文件，按需订阅

### 工程质量

- **103 个单元测试**，覆盖解析器、模型、聚合、冲突、分类器、多层审计
- pydantic v2 配置校验，错误配置启动即报错
- 失败源回退 stale 缓存，失败比例超阈值自动中止
- 缓存增量落盘，进程中断不丢失已下载内容
- 导出末尾释放元数据内存，降低峰值占用

---

## 快速开始

### 环境要求

- Python 3.10+
- 依赖见 `requirements.txt`

### 安装与运行

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 校验配置文件
python merge_rules.py validate config/sources.yaml

# 3. 执行合并
python merge_rules.py merge --config config/sources.yaml

# 4. 运行测试
pytest
```

### CLI 命令

```bash
# 合并（-c 为 --config 的简写）
python merge_rules.py merge -c config/sources.yaml

# 跳过缓存，强制重新下载所有源
python merge_rules.py merge -c config/sources.yaml --no-cache

# 显示详细调试日志
python merge_rules.py merge -c config/sources.yaml -v

# 校验配置
python merge_rules.py validate config/sources.yaml

# 查看版本
python merge_rules.py version
```

---

## 处理流水线

```
多源文本（AdGuard / hosts / 纯域名 / 正则）
   │  解析：保留 $ 修饰符；识别并跳过 CSS/JS/URL 规则；统一内部表示
   ▼
质量过滤（长度 / localhost / IP 规则）
   ▼
去重（三类计数）
   ├─ exact_merged       原始字符串完全相同
   ├─ normalized_merged  原始不同但规范化键相同（如 www 剥离）
   └─ regex_merged       正则重复
   ▼
向上聚合
   ├─ 精确子规则折叠（||ads.x.com^ 被 ||*.x.com^ / ||x.com^ 吸收）
   ├─ 通配符子规则折叠（||*.sub.x.com^ 被 ||*.x.com^ 吸收）
   └─ 子域阈值升级（可选，默认关闭）
   ▼
白名单拆分（@@||…^ → whitelist.txt）
   ▼
冲突消解（allow 覆盖 block，受 cascade_subdomains 控制）
   ▼
稳定排序 → 7 种格式 + 分层文件 + JSON + HTML/MD 报告
```

**DNS 层语义依据**：

- `||example.com^` 覆盖根域及其所有子域
- `||*.example.com^` 只覆盖子域，**不覆盖根域本身**
- 因此根精确规则不会被通配父规则吞掉
- `min_aggregator_labels=2` 防止出现 `||*.com^` 这类病态规则吞噬全部规则

---

## 配置说明（`config/sources.yaml`）

### 完整配置示例

```yaml
# 下载设置
timeout: 60                    # 单个源下载超时（秒）
max_concurrency: 50            # 最大并发下载数
fail_threshold: 0.5            # 失败源比例超过该值则中止运行
diff_against: null             # 指向上一次 domains.txt，开启增删 diff

# 去重
dedup:
  strip_www: true              # 将 www.example.com 与 example.com 视为同一域名
                               # 小写、去尾点始终执行，无需配置

# 向上聚合
aggregation:
  enabled: true
  min_aggregator_labels: 2     # 最少标签数，防止 ||*.com^ 病态规则
  wildcard_child_aggregation: true   # 折叠通配符子规则
  wildcard_promotion_threshold: 0    # 0=关闭；设为 N 表示同一父域下有 N 个
                                     # 精确子域时升级为 ||*.parent^

# 冲突消解
conflict_resolution:
  enabled: true
  cascade_subdomains: true      # @@||A^ 是否级联覆盖 A 的所有子域

# 输出
output:
  directory: output
  formats: [adguard, whitelist, hosts, domains, clash, surge, smartdns]
  tiered: true                  # 输出按分类的分层文件
  report: true                  # 输出 report.html 和 report.md
  write_diff: false

# 规则源
sources:
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt
    name: AdGuard DNS filter
    category: ads               # 必填：ads | tracking | malware | phishing | mining | other
    id: 1
```

### 添加自定义规则源

在 `sources` 列表中追加一项：

```yaml
sources:
  - enabled: true
    url: https://example.com/your-rules.txt
    name: My Custom Rules
    category: ads               # 必须声明分类
    id: 19                       # ID 不可重复
```

`category` 字段决定规则归入哪个分层文件；重复域名按安全优先级自动重新归类。

---

## 白名单七层防御审计

白名单（`@@||domain^`）用于放行被误拦的域名，但如果白名单域名本身已过期、被恶意利用，或属于你本不想放行的广告/追踪域名，就会产生安全和隐私风险。七层防御体系逐层检查，**所有网络层异步并行执行**：

| 层级 | 检测内容 | 成本 | 默认 |
|------|---------|------|------|
| 1. DNS 解析 | NXDOMAIN（域名已过期）、解析到私有/回环 IP | 免费 | ✅ |
| 2. URLhaus + ThreatFox | 恶意软件分发域名、C2 命令控制域名 | 免费 | ✅ |
| 3. RDAP 域名年龄 | 注册时间 < 30 天的新域名标记可疑 | 免费 | ✅ |
| 4. MarketNow 诈骗检测 | 拼写劫持（micros0ft）、可疑 TLD、punycode、未注册域名 | 免费 | ✅ |
| 5. VirusTotal | 70+ 安全引擎厂商信誉投票 | 需 API Key | ⬜ |
| 6. PSL 离线分类 | tldextract 精准提取注册域名，9 类分类 + 置信度 | 免费 | ✅ |
| 7. AI / LLM | 对低置信度域名做语义分类 | 需 API Key | ⬜ |

> **并行执行**：层 1-5（所有网络层）对每个域名通过 `asyncio.gather` 并发执行，总延迟 ≈ 最慢层的延迟，而非各层延迟之和。层 6（PSL 分类）是同步的微秒级操作。层 7（AI）仅在层 6 置信度低于阈值时触发。

### 评级标准

| 评级 | 条件 | 建议 |
|------|------|------|
| 🔴 malicious | URLhaus / ThreatFox / VirusTotal 任一命中 | 移除该白名单 |
| 🟡 suspicious | DNS NXDOMAIN、私有 IP、或新注册域名（<30天） | 人工确认 |
| 🟢 safe | DNS 正常解析，无威胁情报命中 | 可放心放行 |
| ⚪ unknown | 所有检查均失败（网络错误） | 稍后重试 |

### 启用审计

```yaml
whitelist_audit:
  enabled: true
  concurrency: 10
  use_dns: true
  use_urlhaus: true
  use_threatfox: true
  use_rdap: true
  new_domain_threshold_days: 30

  # MarketNow 诈骗/钓鱼检测（免费，无需 key）
  use_scam_check: true

  # VirusTotal（可选）
  use_virustotal: false
  virustotal_api_key: "your-vt-api-key"

  # AI / LLM（可选，仅对低置信度域名调用）
  ai:
    enabled: false
    api_key: "your-openai-api-key"
    base_url: "https://api.openai.com/v1"
    model: "gpt-4o-mini"
    min_confidence: 0.6          # 离线置信度低于此值才调用 AI
    max_domains: 100             # 每次运行最多查询数（成本控制）

whitelist_output:
  enabled: true
  by_rating: true                # 输出 whitelist_safe.txt 等
  by_category: true              # 输出 whitelist_by_category/safe_<category>.txt
  include_all_ratings: false     # true 时 safe 文件也包含可疑/未知域名
```

### 域名分类类别

| 类别 | 中文标签 | 说明 |
|------|---------|------|
| `advertising` | 广告 | 广告网络、DSP、广告投放、营销像素 |
| `analytics` | 分析追踪 | 站点分析、性能监控、遥测 |
| `cdn` | CDN | 内容分发、静态资源托管 |
| `microsoft_telemetry` | 微软遥测 | Windows/Office/Azure 遥测、连通性检查 |
| `affiliate` | 联盟营销 | 联盟营销、链接跳转、归因、短链 |
| `social` | 社交 | 社交媒体、分享组件、即时通讯 |
| `ecommerce_payment` | 电商支付 | 支付网关、结账、购物 |
| `privacy_security` | 隐私安全 | 隐私工具、VPN、安全软件 |
| `other` | 其他 | 不属于以上类别 |

分类置信度：注册域名精确匹配 = 0.9（高），子域名前缀匹配 = 0.6（中），无法分类 = 0（低）。

---

## 输出文件（`output/`）

### 规则文件

| 文件 | 内容 |
|------|------|
| `merged_rules.txt` | AdGuard 主拦截规则（`||domain^` + 正则），含统计头部 |
| `whitelist.txt` | 白名单（`@@||domain^`） |
| `hosts.txt` | `0.0.0.0 domain` 格式 |
| `domains.txt` | 每行一个纯域名 |
| `clash.yaml` | Clash 格式 |
| `surge.list` | Surge 格式 |
| `smartdns.conf` | SmartDNS 格式 |

### 分层规则文件

| 文件 | 内容 |
|------|------|
| `merged_ads.txt` | 广告类规则 |
| `merged_tracking.txt` | 追踪类规则 |
| `merged_malware.txt` | 恶意软件类规则 |
| `merged_phishing.txt` | 钓鱼类规则 |
| `merged_mining.txt` | 挖矿类规则 |

### 白名单分级文件（需启用审计）

| 文件 | 内容 |
|------|------|
| `whitelist_safe.txt` | 评级为安全的白名单 |
| `whitelist_suspicious.txt` | 评级为可疑的白名单 |
| `whitelist_malicious.txt` | 评级为恶意的白名单 |
| `whitelist_unknown.txt` | 评级为未知的白名单 |
| `whitelist_by_category/safe_<category>.txt` | 按类别细分的安全白名单 |

### 分析与报告

| 文件 | 内容 |
|------|------|
| `stats.json` | 机器可读统计：去重、聚合、冲突、分类计数、失败源、diff |
| `conflicts.json` | 被白名单移除的拦截规则明细（含多方来源） |
| `contributions.json` | 每个源的原始/独占/共享规则贡献 |
| `whitelist_audit.json` | 白名单审计结果（评级 + 类别 + 置信度 + 各层命中） |
| `added.txt` / `removed.txt` | 相对上一次输出的增删域名（需开 `write_diff`） |
| `report.html` | 可视化 HTML 报告 |
| `report.md` | Markdown 格式报告 |

---

## 内置规则源（18 个）

| 分类 | 规则源 |
|------|--------|
| 广告 | AdGuard DNS filter、AWAvenue Ads Rule、HaGeZi's Ultimate、OISD Blocklist Small、CHN: AdRules DNS List、CHN: anti-AD |
| 追踪 | HaGeZi's Windows/Office Tracker Blocklist |
| 钓鱼 | Phishing URL Blocklist、Phishing Army、Scam Blocklist by DurableNapkin |
| 恶意软件 | HaGeZi's DNS Rebind Protection、HaGeZi's Threat Intelligence Feeds、Stalkerware Indicators List、Malicious URL Blocklist (URLHaus) |
| 挖矿 | NoCoin Filter List |
| 其它 | HaGeZi's Gambling Blocklist、ShadowWhisperer's Dating List、HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass |

> **内存提示**：Ultimate + TIF Full 合计约 430 万条原始规则，合并后约 370 万条。实测合并阶段峰值内存约 **2 GB**（HaGeZi 官方同样建议 TIF Full 至少 2 GB RAM），GitHub Actions 的 ubuntu-latest（7 GB）无压力。低内存设备可将 Ultimate 降为 Pro、TIF 改为 Mini，并参考 `contributions.json` 精简重叠源。

---

## 在 AdGuard Home 中订阅

1. 打开 AdGuard Home 管理界面 → **过滤器 → DNS 黑名单**
2. 点击 **添加黑名单 → 自定义列表**
3. 填入合并后规则文件的 URL，例如：
   - GitHub Pages：`https://<用户名>.github.io/<仓库名>/merged_rules.txt`
   - 或直接使用 GitHub raw 链接
4. 如需只订阅安全白名单，在 **DNS 白名单** 中添加 `whitelist_safe.txt` 的 URL

---

## GitHub Actions

`.github/workflows/merge.yml` 配置：

- **触发条件**：每 6 小时定时执行（`0 */6 * * *`）、手动触发（workflow_dispatch）、推送改动 `config/`、`merger/`、`merge_rules.py` 等路径时触发
- **执行流程**：先运行 `pytest`，测试通过后再执行合并
- **缓存**：使用 `actions/cache` 持久化 `cache/` 目录（key 前缀 `rule-cache-v5-`）
- **自动提交**：仅当 `output/` 有变化时才提交，提交前 `git pull --rebase` 防止冲突
- **制品上传**：同时上传保留 30 天的构建制品 `merged-rules-v5`

---

## 项目结构

```
adguard-rules-merger-v5/
├── merge_rules.py              # Typer CLI 入口（merge / validate / version）
├── config_loader.py            # pydantic v2 配置校验
├── requirements.txt            # Python 依赖
├── pytest.ini                  # pytest 配置
├── config/
│   └── sources.yaml            # 规则源与处理参数
├── merger/
│   ├── __init__.py
│   ├── models.py               # Rule 模型、域名规范化、分类优先级
│   ├── parser.py               # 流式解析器（保留 $ 修饰符）
│   ├── cache.py                # ETag + SHA256 磁盘缓存（增量落盘）
│   ├── core.py                 # 异步引擎：抓取/去重/聚合/冲突/统计
│   ├── exporter.py             # 多格式 + 分层 + JSON 导出
│   ├── report.py               # HTML + Markdown 报告生成
│   ├── domain_classifier.py    # tldextract + PSL 域名分类器（置信度评分）
│   ├── whitelist_audit.py      # 多层决策引擎（七层防御并行融合 + 缓存）
│   ├── whois_audit.py          # RDAP 域名注册信息查询
│   ├── scam_check.py           # MarketNow 诈骗/钓鱼检测（免费）
│   ├── virustotal_audit.py     # VirusTotal 可选集成
│   └── ai_classifier.py        # LLM 语义分类可选层
├── tests/
│   ├── test_parser.py          # 解析器测试
│   ├── test_models.py          # 模型测试
│   ├── test_aggregation.py     # 聚合测试
│   ├── test_conflicts.py       # 冲突测试
│   ├── test_classifier.py      # 分类器测试
│   └── test_audit_layers.py    # 多层审计测试
└── .github/
    └── workflows/
        └── merge.yml           # GitHub Actions 工作流
```

---

## 性能基准

基于 18 个真实上游源的实测数据：

| 指标 | 数值 |
|------|------|
| 原始规则总数 | ~4,300,000 |
| 合并后 Block 规则 | 3,705,647 |
| 合并后 Allow 规则 | 225 |
| 精确去重（exact_merged） | 588,483 |
| 规范化去重（normalized_merged） | 4,808 |
| 冲突消解 | 32 |
| 正则规则 | 63 |
| 跨源去重率 | ~14.6% |
| 峰值内存 | ~2 GB |
| 总耗时 | ~40 秒（本地源） |

> 跨源去重率 14.6% 是健康值：18 个源覆盖广告、追踪、钓鱼、恶意软件等不同领域，跨领域的规则本身零重叠。

---

## V4 → V5 变更

### 修复的缺陷

| 问题 | V4 表现 | V5 修复 |
|------|---------|---------|
| 分类功能完全失效 | `sources.yaml` 无 `category`，分类"先到先得"，categories 全为 0，分层文件只有头部 | 每个源必须声明 `category`；重复域名按安全优先级重新归类 |
| 死配置 | `normalize_case`、`normalize_trailing_dot` 写在配置里但代码从不读取 | 移除无效开关；小写、去尾点始终执行 |
| 死参数 | `cascade_subdomains` 传入引擎但从不引用 | 该开关现在真正控制级联覆盖 |
| 死代码 | 静态方法 `_dedup()` 全项目无调用 | 删除 |
| 统计缺失 | `normalized_merged` 永远为 0；正则去重不计入 | 拆成三类计数 |
| 内存浪费 | 每条规则的 `sources` 元组常驻（约 150–250 MB） | 导出后统一清空 `source_ids` |
| 失败源静默跳过 | 下载失败只打日志，输出无标注 | 失败源进入报告；超阈值中止；回退 stale 缓存 |
| 缓存丢失 | 索引只在全部拉取结束后写一次 | 每个源下载后增量落盘 |
| `$` 修饰符被截断 | `$badfilter` 截断后语义反转（"取消拦截"变"拦截"） | 保留修饰符并纳入去重键；带修饰符规则跳过聚合 |

### 刻意不做的事

V5 **不做**以下改动，因为在 V4 审计中评估为收益近零或风险过高：

- IDN / punycode 转换（实际规则中无 Unicode 域名）
- DNS 有效性校验
- 正则包含判定（NP 难问题）
- 分片并行去重（300–400 万规则规模下收益为负）

---

## 常见问题

### Q：合并时某个源下载失败怎么办？

引擎会自动回退到该源的 stale 缓存（如果有），并在 `stats.json` 和报告中标注。如果失败源比例超过 `fail_threshold`（默认 0.5），整个合并会中止并报错，避免产出残缺规则。

### Q：去重率只有 14.6%，正常吗？

正常。18 个源覆盖广告、追踪、钓鱼、恶意软件等 6 个不同领域，跨领域的规则本身没有重叠。同源内部的重复（如多个源包含同一域名）已被去重和聚合处理。可以查看 `contributions.json` 了解每个源的独占率。

### Q：某个网站/应用打不开，怎么排查？

1. 查看 AdGuard Home 的"最近活动"，找到被拦截的域名和命中的规则
2. 针对性地添加白名单（`@@||domain^`），不要整体关闭列表
3. 如果是 App 内嵌 DoH 端点被拦，检查是否被 Encrypted DNS Bypass 列表命中，加白即可

### Q：URLhaus API 返回错误？

URLhaus 有速率限制，且某些网络环境（如部分机房 IP）可能被拒绝。代码逻辑不受影响，可以在配置中设置 `use_urlhaus: false` 跳过该层，其余五层仍然生效。

### Q：如何在低内存设备上运行？

将 HaGeZi Ultimate 降级为 Pro（或 Normal），TIF Full 改为 TIF Mini，总规则量可降到 40–50 万条，内存占用大幅下降。

---

## License

[MIT](LICENSE)
