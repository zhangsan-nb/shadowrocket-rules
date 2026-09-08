# Shadowrocket Trusted Rules

这是一个独立、失败关闭、可审计、可回滚的 Shadowrocket RuleSet 仓库。第三方内容只作为候选输入；只有经过本仓库抓取、严格解析、标准化、安全门、集合差异和候选哈希绑定的规则，才允许进入 release 分支。

V1 只发布三个纯 RuleSet：

- rules/direct.list
- rules/reject.list
- rules/proxy.list

不会生成完整 Shadowrocket 配置、MITM、脚本或 URL Rewrite。

## 信任链

第三方 HTTPS 输入 → Fetch → Parse → Normalize → Manual override → Security gates → Semantic diff → Sealed candidate → Fast-forward release。

任何阶段失败都不会改动 release；生产端继续使用 last-known-good。

## 快速开始

需要 Python 3.11 或更高版本与 Git。

    python -m pip install -r requirements.txt
    python -m pytest -q
    python scripts/fetch.py
    python scripts/build.py --source-mode snapshot
    python scripts/build.py --source-mode live
    python scripts/validate.py
    python scripts/diff.py
    python scripts/report.py

普通本地 build 默认使用 config/bootstrap 中经人工核实且固定 SHA-256 与上游 commit 的首发快照，便于离线复现；也可以用 `--source-mode live` 显式请求实时 HTTPS。`build --ci` 强制 live，拒绝 snapshot 或网络失败回退。输入解析模式会写入并绑定到候选 manifest；每日自动更新只使用 CI live 模式。

生成目录 candidate 不纳入 main。首次本地发布：

    python scripts/release.py publish --candidate candidate --local-only

正式发布由 daily-build 工作流执行：validate job 只有 contents: read；publish job 在校验成功后单独获得 contents: write。候选经内外两层 SHA-256 校验，publish 不重新抓取、不重新构建。

## 策略顺序

在 Shadowrocket 主配置中按以下顺序引用，首个匹配类别生效：

1. direct
2. reject
3. proxy
4. GEOIP,CN
5. FINAL

跨类别的精确域、后缀域、关键词或 CIDR 语义交集默认阻断。手工规则在同键上覆盖上游，但不能绕过 protected、冲突、CIDR、公共后缀或异常变化门。

## Protected domains

protected 的含义不是永远走某个策略，而是“策略变化不得自动发布”。比较范围包含根域及全部合法子域，不依赖有限抽样。

当前实现使用保守的规则语言签名证明：

- 精确域命中 protected 根域或其任意子域时纳入证明；
- 后缀与 protected 互为祖先或后代时纳入证明；
- 任意 DOMAIN-KEYWORD 都可能出现在某个深层子域，因此任何关键词策略变化都视为可能影响 protected；
- 基线和候选的相关规则语言签名必须完全相同。

它可能拒绝某些实际上安全但无法廉价证明的变化，这是有意的 fail-closed 取舍。根域或固定样本测试只是附加测试，不是证明。

## 配置

为只依赖 Python 标准库，config/sources.yml 和 config/policy.yml 使用 JSON 语法；JSON 是 YAML 1.2 的合法子集。

- config/sources.yml：唯一允许出现上游 URL 的位置
- config/policy.yml：阈值、CIDR、安全例外
- config/protected_domains.txt：受保护域
- config/allow_rule_types.txt：V1 类型白名单
- config/manual：人工最高优先级规则
- config/public_suffix_list.dat 与对应 sha256：版本化、固定哈希的公共后缀安全快照

更新公共后缀快照时，必须人工审查变更并同步更新哈希文件。

## 审计制品

release 只包含 rules、reports、metadata。metadata/manifest.json 使用 canonical JSON，绑定：

- build ID、main source commit、baseline release commit
- 配置、代码、PSL digest
- 每个输入的 provenance 与 SHA-256
- 归一化规则集合与 gate 结果 digest
- 所有候选文件的路径、大小与 SHA-256

manifest 还显式绑定输入解析模式、类别优先级和匹配语义版本。受保护域证明只有在相关规则语言签名、类别优先级和匹配语义版本均与 release 基线一致时才通过。

manifest 不自哈希。额外文件、缺失文件、路径穿越、符号链接或任意字节篡改都会阻断发布。

## 调度与 Action 供应链

daily-build 在 UTC 01:30 运行，即北京时间 09:30。GitHub Actions 不支持 timezone 字段，因此 cron 已直接换算。

所有使用的官方 Actions 都固定到 2026-09-08 从其官方 Git 仓库标签解析得到的完整 commit SHA。升级时必须重新核实，不接受只写 v4 或 main。

## 退出码

- 0：PASS
- 1：BUILD ERROR
- 2：SECURITY GATE FAIL
- 3：SOURCE FETCH FAIL
- 4：POLICY CONFLICT

错误同时输出稳定 error key，便于 CI 告警。

## Shadowrocket 订阅 URL

仓库发布到 GitHub 后，将 OWNER 和 REPOSITORY 替换为实际值：

    https://raw.githubusercontent.com/OWNER/REPOSITORY/release/rules/direct.list
    https://raw.githubusercontent.com/OWNER/REPOSITORY/release/rules/reject.list
    https://raw.githubusercontent.com/OWNER/REPOSITORY/release/rules/proxy.list

在仓库和 release 分支真正上线前，不应把占位 URL 加入客户端。

## 维护

安全策略与发布恢复流程见 SECURITY.md 和 docs/release-runbook.md。原始需求基线保存在 PROJECT_SPEC.md。
