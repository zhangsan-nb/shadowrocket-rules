# Shadowrocket Trusted Rules Audit

- Build: 2026-09-14T23:16:35.666172+00:00
- Build ID: ae9173e8997e6421b85a
- Result: PASS
- Published: NO (candidate)

## Source status

- blackmatrix7_china_max: PASS, bytes=1522689, sha256=2dbdd0ab3733f883d21b193a7c1ff33cd0404e15e2c8183f635c2109c9cc593b
- blackmatrix7_advertising_lite: PASS, bytes=595771, sha256=e43ab7970cfa5bde9b222a18c0f5673dcced42e1bfada25f04254a514231ec34
- blackmatrix7_proxy: PASS, bytes=96625, sha256=467945903ff227c420e913ace21bd22c17aa7380afc5a2d32e0a02bce5ed4c83
- blackmatrix7_openai: PASS, bytes=1353, sha256=6f4047cdbf6953cf5d9b38c4ccd6da7bc6f1acb91b7a87134f25d5b8f5d2408b
- blackmatrix7_telegram: PASS, bytes=1338, sha256=09f093cce5b3e2994147a2640e03040aac75e1db7bf2103fd1c9a2509b0176ab

## Security gates

- syntax_allowlist_domain_cidr: PASS
- cross_policy_conflict: PASS
- protected_domains: PASS — 相关规则语言签名完全相同；固定抽样不作为证明
- minimum_nonempty: PASS — {'direct': 110058, 'reject': 37693, 'proxy': 6588}
- anomaly_delta: PASS

## DIRECT

- Previous: 110058
- Current: 110058
- Added: 0
- Removed: 0
- Delta: 0.0%

### Added rules

- None

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
- Current: 6588
- Added: 0
- Removed: 0
- Delta: 0.0%

### Added rules

- None

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
