# Shadowrocket 自动化可信分流规则仓库实施基线

## 目标与信任边界

新建一个完全独立、自主可控、自动更新、可审计、可回滚、防上游投毒的 Shadowrocket RuleSet 仓库。第三方仓库只能作为候选输入、交叉验证和参考，绝不能直接控制生产发布。

可信链必须是：上游候选数据 -> 本仓库 Fetch -> Parse -> Normalize -> Security Gate -> Semantic Diff -> PASS -> 本仓库 release -> Shadowrocket。所有异常一律 fail closed，并保留 last-known-good release。

## V1 发布范围

仅发布 `direct.list`、`proxy.list`、`reject.list`，不得生成或继承完整 `.conf`。允许的规则类型由 `config/allow_rule_types.txt` 显式控制，初始为：

- `DOMAIN`
- `DOMAIN-SUFFIX`
- `DOMAIN-KEYWORD`
- `IP-CIDR`
- `IP-CIDR6`
- `IP-ASN`
- `USER-AGENT`

候选输入中出现 Shadowrocket 配置段、MITM、脚本、URL Rewrite、Host、General、Proxy、Proxy Group、远程脚本或 HTTP(S) 指令时必须严重失败。

## 仓库与分支

- `main`：可信代码、测试、安全策略、源配置、手工规则、工作流和文档。
- `release`：只保留生成后的 `rules/`、`reports/`、`metadata/`。
- release 必须保持普通连续 Git 历史；禁止 force push、orphan 日更、直接镜像上游。
- GitHub Actions 不得自动修改 main 中的构建脚本、安全策略、源配置或工作流。

## 目录和入口

至少包含：

- `.github/workflows/validate.yml`
- `.github/workflows/daily-build.yml`
- `config/sources.yml`
- `config/policy.yml`
- `config/protected_domains.txt`
- `config/allow_rule_types.txt`
- `config/manual/{direct,proxy,reject}.list`
- `scripts/{fetch,parse,normalize,merge,validate,diff,report,build}.py`
- `scripts/publish.sh`
- `tests/` 与恶意/异常 fixtures
- `reports/.gitkeep`
- `requirements.txt`
- `README.md`
- `SECURITY.md`

命令必须支持：

- `python scripts/fetch.py`
- `python scripts/validate.py`
- `python scripts/diff.py`
- `python scripts/report.py`
- `python scripts/build.py`
- `python scripts/build.py --ci`
- `python -m pytest -q`

退出码：0 PASS，1 BUILD ERROR，2 SECURITY GATE FAIL，3 SOURCE FETCH FAIL，4 POLICY CONFLICT。

## 上游策略

- 优先直接接原始数据源；聚合规则仓库只作为 reference/cross-check。
- 初始端到端源至少采用 blackmatrix7 的纯 Shadowrocket OpenAI RuleSet；后续配置可包括 Telegram、Google、Apple、Microsoft、GFWList、China 和 Advertising。
- 绝不能自动读取第三方仓库的 script、rewrite、external、MITM 或完整 conf。
- source URL 只存在于 `config/sources.yml`，不得硬编码进 Python。

每个 source 至少记录：名称、URL、抓取时间、HTTP 状态、内容长度、SHA-256、ETag、Last-Modified，以及可得时的上游 Git commit SHA。发布产物包含 `metadata/sources.json`、`metadata/hashes.json`、`metadata/build.json`。

## Fetch 要求

- 仅 HTTPS。
- 明确的连接和读取超时、User-Agent、有限重试、最大下载大小。
- 非 200 失败。
- 拒绝 HTML、Cloudflare 错误页、404 页面和其他污染内容。
- 任一失败不得用空文件继续构建或污染 release。

## 内部模型、解析与标准化

将所有输入先解析为内部不可变 Rule 对象，包含 `rule_type`、`value`、`category`、`source`。不得在流水线中一直操作未经解析的原始文本。

统一处理 strip、域名小写、IDNA/punycode、IPv4/IPv6、CIDR canonicalization、注释和空行清理、排序、去重。输出保持稳定，避免无意义 Git diff。CIDR 输出风格统一，并支持可配置的 `no-resolve`。

手工规则优先级最高：MANUAL > AUTO GENERATED > UPSTREAM。冲突应按手工规则和 policy 显式解决；无法确定时阻止发布，禁止多数投票。

## Security Gate

任一 Gate FAIL 都禁止更新 release：

1. Rule type allowlist；未知类型必须失败。
2. 域名合法性：label/总长、字符、空值、通配符、IDNA、IP masquerading。
3. 公共后缀/顶级域保护：如 `com`、`co.uk`、`com.cn`、`github.io` 默认阻止，除非 policy 显式允许。
4. 危险 CIDR：阻止 `0.0.0.0/0`、`::/0`；IPv4/IPv6 最小前缀阈值可配置。
5. Protected domains：策略从 DIRECT/PROXY/REJECT 发生变化时 CRITICAL 并阻止自动发布。
6. Cross-policy conflict：同一规则跨类别冲突，不能明确解决时返回 POLICY CONFLICT。
7. 父子域冲突：必须检测并报告；涉及 protected domain 时升级严重级别。
8. 与 previous release 做 Set Diff；单类 absolute delta 或 percentage delta 超过 policy 阈值则 quarantine。
9. 空规则保护。
10. 每类最小规则数量由 policy 配置。
11. 配置注入检测：MITM、Script、URL Rewrite、General、script-path、http-request/response、hostname 等立即严重失败。
12. 危险 DOMAIN-KEYWORD（例如 `.`、`com`）阻止。

## Semantic Diff 与报告

Semantic Diff 必须基于集合，不受排序变化影响。每天生成 `reports/latest.md` 和 `reports/latest.json`，包含：

- 构建时间、总体结果和发布状态。
- 每个 source 的状态和 provenance。
- DIRECT/PROXY/REJECT 前后数量、added/removed 数量和百分比。
- 各 Security Gate 状态。
- added rules、removed rules、policy changes、protected-domain changes、conflicts。

release 同时保存历史报告，保证可回答规则何时进入、来自哪个 source、当日 SHA、上游 commit、通过哪些 Gate、何时发布及对应 release commit。

## GitHub Actions 与发布

- Validate job 仅 `contents: read`。
- Publish job 单独 `contents: write`，且只有 validate 全部成功后才运行。
- 优先官方 Action，并固定到完整 commit SHA；避免不必要的 Marketplace Action。
- 每日构建按北京时间 09:30，对应 UTC cron 必须正确表达；GitHub Actions cron 不支持 `timezone` 字段。
- 候选产物在 validate 与 publish 间传递并校验 hashes。
- publish 只更新 release 分支的允许路径，保留连续历史，不 force push。

## 依赖与范围

尽量使用 Python 标准库；确需第三方包时固定版本。V1 不实现 AI 判域名、WHOIS、实时全球探测、DNS 污染实测、证书信誉、ASN 风险评分、机器学习或大量上游投票。

## 验收

完成前必须验证：

- `python scripts/build.py` 成功。
- `python -m pytest -q` 全部通过。
- `[MITM]`、`hostname = *`、`[Script]`、`DOMAIN-SUFFIX,com`、`IP-CIDR,0.0.0.0/0` 均失败。
- protected `openai.com` 从 proxy 改为 direct 时阻止自动发布。
- 模拟 +50000 rules 触发 anomaly Gate。
- HTTP 404 或 HTML 上游导致构建失败且 release 不变。
- 连续两次成功发布后 release 分支有正常父子 commit。
- 输入顺序随机化只产生真实 ADD/REMOVE。
- 三个 release URL 可作为 Shadowrocket RULE-SET 使用。

## 最终交付

完整 Git 仓库、main、release、Python builder、Security Gate、单元测试、GitHub Actions、sources/policy/protected/manual 配置、最新审计报告、README、SECURITY、首次 release，并报告仓库 URL、main/release commit SHA、测试结果、规则数量、Gate 结果和 Shadowrocket 订阅 URL。

设计取舍优先级：安全 > 可审计 > 正确性 > 稳定性 > 自动化 > 更新速度。
