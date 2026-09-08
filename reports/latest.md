# Shadowrocket Trusted Rules Audit

- Build: 2026-09-08T13:40:34.383598+00:00
- Build ID: 34abf10bb33a21082e92
- Result: PASS
- Published: NO (candidate)

## Source status

- blackmatrix7_openai: PASS, bytes=1354, sha256=52984c9768f3cae1d740fb22eace657048054aa97f75146147c467644e173aba

## Security gates

- syntax_allowlist_domain_cidr: PASS
- cross_policy_conflict: PASS
- protected_domains: N/A — 首次发布：无可信基线；其他内在门仍强制执行
- minimum_nonempty: PASS — {'direct': 1, 'reject': 1, 'proxy': 35}
- anomaly_delta: N/A — 首次发布无可信数量基线

## DIRECT

- Previous: 0
- Current: 1
- Added: 1
- Removed: 0
- Delta: 100.0%

### Added rules

- DOMAIN,time.apple.com

### Removed rules

- None

## REJECT

- Previous: 0
- Current: 1
- Added: 1
- Removed: 0
- Delta: 100.0%

### Added rules

- DOMAIN,ads.example.com

### Removed rules

- None

## PROXY

- Previous: 0
- Current: 35
- Added: 35
- Removed: 0
- Delta: 100.0%

### Added rules

- DOMAIN,browser-intake-datadoghq.com
- DOMAIN,chat.openai.com.cdn.cloudflare.net
- DOMAIN,openai-api.arkoselabs.com
- DOMAIN,openaicom-api-bdcpf8c6d2e9atf6.z01.azurefd.net
- DOMAIN,openaicomproductionae4b.blob.core.windows.net
- DOMAIN,production-openaicom-storage.azureedge.net
- DOMAIN,static.cloudflareinsights.com
- DOMAIN-KEYWORD,openai
- DOMAIN-SUFFIX,ai.com
- DOMAIN-SUFFIX,algolia.net
- DOMAIN-SUFFIX,api.statsig.com
- DOMAIN-SUFFIX,auth0.com
- DOMAIN-SUFFIX,chatgpt.com
- DOMAIN-SUFFIX,chatgpt.livekit.cloud
- DOMAIN-SUFFIX,client-api.arkoselabs.com
- DOMAIN-SUFFIX,events.statsigapi.net
- DOMAIN-SUFFIX,featuregates.org
- DOMAIN-SUFFIX,host.livekit.cloud
- DOMAIN-SUFFIX,identrust.com
- DOMAIN-SUFFIX,intercom.io
- DOMAIN-SUFFIX,intercomcdn.com
- DOMAIN-SUFFIX,launchdarkly.com
- DOMAIN-SUFFIX,oaistatic.com
- DOMAIN-SUFFIX,oaiusercontent.com
- DOMAIN-SUFFIX,observeit.net
- DOMAIN-SUFFIX,openai.com
- DOMAIN-SUFFIX,openaiapi-site.azureedge.net
- DOMAIN-SUFFIX,openaicom.imgix.net
- DOMAIN-SUFFIX,segment.io
- DOMAIN-SUFFIX,sentry.io
- DOMAIN-SUFFIX,stripe.com
- DOMAIN-SUFFIX,turn.livekit.cloud
- IP-ASN,20473,no-resolve
- IP-CIDR,24.199.123.28/32,no-resolve
- IP-CIDR,64.23.132.171/32,no-resolve

### Removed rules

- None

## Policy changes

- None

## Protected domain changes

- None

## Conflicts

- None
