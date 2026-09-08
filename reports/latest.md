# Shadowrocket Trusted Rules Audit

- Build: 2026-09-08T14:45:48.536426+00:00
- Build ID: 7014331037decbdb8853
- Result: PASS
- Published: NO (candidate)

## Source status

- blackmatrix7_openai: PASS, bytes=1354, sha256=52984c9768f3cae1d740fb22eace657048054aa97f75146147c467644e173aba

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
