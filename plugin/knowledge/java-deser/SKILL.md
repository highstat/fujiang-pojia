---
name: "kb-java-deser"
description: "Java serialization, unsafe expression/lookup handling and dependency assessment; public CVE records and non-exploit validation plans. Laboratory verification is not implied."
verified: false
sources: "Compiled from public sources (CVE advisories / public analyses / business-logic classes; see each entry's references)"
---

# Java deserialization / expression injection (14 entries)
> Public-source notes and assessment cards. Candidate matches are not proof of exploitation; laboratory verification requires dated, redacted evidence.

Hit indicators: the Java tech stack appears in response headers or errors (Tomcat/Jetty/WebLogic/Resin), parameters get written to logs, JSON request bodies, `Set-Cookie: rememberMe=deleteMe`, `Content-Type` parsed by the server.

## Entries

| File | Vulnerability | Severity | Entry Point |
|---|---|---|---|
| `cve-2015-4852-weblogic-t3.md` | WebLogic T3 deserialization (CommonsCollections) | critical | T3 handshake + ysoserial serialized object |
| `cve-2016-4437-shiro-rememberme.md` | Shiro rememberMe default-key deserialization RCE (CVE-2016-4437) | critical | Cookie: rememberMe=<AES-encrypted gadget chain> |
| `cve-2017-10271-weblogic-wls-wsat.md` | WebLogic wls-wsat XMLDecoder deserialization RCE | critical | WebLogic WLS-WSAT HTTP web service |
| `cve-2017-5638-struts2-s2-045.md` | Struts2 S2-045 Content-Type OGNL injection | critical | Struts2 multipart request handling |
| `cve-2021-44228-log4shell.md` | Apache Log4j2 JNDI injection (Log4Shell) | critical | Application inputs logged by vulnerable Log4j2 |
| `cve-2022-1471-snakeyaml.md` | SnakeYAML deserialization RCE (CVE-2022-1471) | critical | Any YAML input (uploads/configuration/endpoints) |
| `cve-2022-21449-psychic-signatures.md` | Java ECDSA empty signature bypass (Psychic Signatures) | high | Empty signatures with r=0,s=0 are accepted |
| `cve-2022-22965-spring4shell.md` | Spring Framework data binding RCE (Spring4Shell) | critical | Spring MVC request parameter binding |
| `cve-2022-25845-fastjson-autotype.md` | Fastjson autoType deserialization RCE | high | Fastjson JSON deserialization input |
| `cve-2020-14645-oracle-weblogic.md` | Oracle WebLogic: IIOP listener (CVE-2020-14645) | critical | IIOP listener |
| `cve-2020-2883-oracle-weblogic.md` | Oracle WebLogic: T3 deserialization (CVE-2020-2883) | critical | T3 deserialization |
| `cve-2021-44832-apache-log4j.md` | Apache Log4j: Writable logging configuration (CVE-2021-44832) | medium | Writable logging configuration |
| `cve-2021-45046-apache-log4j.md` | Apache Log4j: Log4j message lookup configuration (CVE-2021-45046) | critical | Log4j message lookup configuration |
| `cve-2021-45105-apache-log4j.md` | Apache Log4j: Recursive logging lookups (CVE-2021-45105) | medium | Recursive logging lookups |

## How to use this page

1. First confirm the component and version range via "Fingerprint" (if the version is outside the range, do not fire the PoC and present it as a conclusion).
2. Each PoC provides both a **probe form** and an **exploit form**; run the probe first and confirm the hit via dnslog / echo headers / observable behavior, then run the exploit.
3. For those requiring outbound connections (JNDI, deserialization callbacks), first confirm the target has outbound access; for targets without outbound access, switch to a local gadget + echo, or simply submit "exploitability evidence".
4. Land the remediation recommendation as the one-liner in the entry, and state clearly in the report "tested version + hit evidence + recommended version".
