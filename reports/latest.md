# Shadowrocket Trusted Rules Audit

- Build: 2026-09-09T06:14:27.851894+00:00
- Build ID: 91cda1c09c85656cbbca
- Result: PASS
- Published: NO (candidate)

## Source status

- blackmatrix7_openai: PASS, bytes=1353, sha256=6f4047cdbf6953cf5d9b38c4ccd6da7bc6f1acb91b7a87134f25d5b8f5d2408b

## Security gates

- syntax_allowlist_domain_cidr: PASS
- cross_policy_conflict: PASS
- protected_domains: PASS — 相关规则语言签名完全相同；固定抽样不作为证明
- minimum_nonempty: PASS — {'direct': 1, 'reject': 1, 'proxy': 35}
- anomaly_delta: PASS

## DIRECT

- Previous: 1
- Current: 1
- Added: 0
- Removed: 0
- Delta: 0.0%

### Added rules

- None

### Removed rules

- None

## REJECT

- Previous: 1
- Current: 1
- Added: 0
- Removed: 0
- Delta: 0.0%

### Added rules

- None

### Removed rules

- None

## PROXY

- Previous: 35
- Current: 35
- Added: 0
- Removed: 0
- Delta: 0.0%

### Added rules

- None

### Removed rules

- None

## Policy changes

- None

## Protected domain changes

- None

## Conflicts

- None
