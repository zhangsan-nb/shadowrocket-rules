# Shadowrocket Trusted Rules Audit

- Build: 2026-09-23T23:02:19.186825+00:00
- Build ID: 2bb513160428f5ed9daa
- Result: PASS
- Published: NO (candidate)

## Source status

- blackmatrix7_china_max: PASS, bytes=1522823, sha256=895a6bcd21b9400bdabc85d473bb30dfa5529dfe726d23e7c2503df70640acc0
- blackmatrix7_advertising_lite: PASS, bytes=595771, sha256=e43ab7970cfa5bde9b222a18c0f5673dcced42e1bfada25f04254a514231ec34
- blackmatrix7_proxy: PASS, bytes=96655, sha256=0d6559fcabb08560196fa1c2df970e8713502affc78f741c7216a0d4cb42b300
- blackmatrix7_openai: PASS, bytes=1353, sha256=6f4047cdbf6953cf5d9b38c4ccd6da7bc6f1acb91b7a87134f25d5b8f5d2408b
- blackmatrix7_telegram: PASS, bytes=1338, sha256=09f093cce5b3e2994147a2640e03040aac75e1db7bf2103fd1c9a2509b0176ab

## Security gates

- syntax_allowlist_domain_cidr: PASS
- cross_policy_conflict: PASS
- protected_domains: PASS — 相关规则语言签名完全相同；固定抽样不作为证明
- minimum_nonempty: PASS — {'direct': 110068, 'reject': 37693, 'proxy': 6590}
- anomaly_delta: PASS

## DIRECT

- Previous: 110067
- Current: 110068
- Added: 1
- Removed: 0
- Delta: 0.000909%

### Added rules

- DOMAIN-SUFFIX,sjfls6.com

### Removed rules

- None

## REJECT

- Previous: 37693
- Current: 37693
- Added: 0
- Removed: 0
- Delta: 0.0%

### Added rules

- None

### Removed rules

- None

## PROXY

- Previous: 6588
- Current: 6590
- Added: 2
- Removed: 0
- Delta: 0.030358%

### Added rules

- DOMAIN-SUFFIX,chineseposters.net
- DOMAIN-SUFFIX,note.com

### Removed rules

- None

## Policy changes

- owner-reviewed-direct-lower-priority-exclusions-v1: 当前已审计的 direct/reject 与 direct/proxy 语义冲突由显式域名清单保留给低优先级类别；新的未列冲突仍会失败关闭。
- owner-reviewed-proxy-lower-priority-exclusions-v1: Audited reject/proxy domain conflicts keep the value in higher-priority REJECT; unlisted conflicts fail closed.
- owner-reviewed-proxy-keyword-exclusions-v1: Audited broad proxy keywords are removed while precise proxy domains and CIDRs remain; unlisted conflicts fail closed.

## Protected domain changes

- None

## Conflicts

- None
