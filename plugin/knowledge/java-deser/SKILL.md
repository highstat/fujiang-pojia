---
name: kb-java-deser
description: CVE/PoC knowledge base · Java deserialization and expression injection: Log4Shell (2021-44228), Spring4Shell (2022-22965), Struts2 S2-045 (2017-5638), WebLogic T3 (2015-4852)/wls-wsat (2017-10271), Fastjson autoType (2022-25845), Java ECDSA empty signature (2022-21449). Each entry has a corresponding PoC and exploitation steps; compiled from public sources, verified=false.
verified: false
sources: Compiled from public sources (CVE advisories / public analyses / business-logic classes; see each entry's references)
---

# Java deserialization / expression injection (9 entries)
> Entries are compiled from public sources (see "References" at the end of each file); `Exploitation steps` are hypotheses pending validation; self-validate against the target version before reporting and set `verified` to true.

Hit indicators: the Java tech stack appears in response headers or errors (Tomcat/Jetty/WebLogic/Resin), parameters get written to logs, JSON request bodies, `Set-Cookie: rememberMe=deleteMe`, `Content-Type` parsed by the server.

## Entries

| File | Vulnerability | Severity | Entry |
|---|---|---|---|
| `cve-2015-4852-weblogic-t3.md` | WebLogic T3 deserialization (CommonsCollections) | critical | T3 handshake + ysoserial serialized object |
| `cve-2016-4437-shiro-rememberme.md` | Shiro rememberMe default-key deserialization RCE (CVE-2016-4437) | critical | Cookie: rememberMe=<AES-encrypted gadget chain> |
| `cve-2017-10271-weblogic-wls-wsat.md` | WebLogic wls-wsat XMLDecoder deserialization RCE | critical | - |
| `cve-2017-5638-struts2-s2-045.md` | Struts2 S2-045 Content-Type OGNL injection | critical | - |
| `cve-2021-44228-log4shell.md` | Apache Log4j2 JNDI injection (Log4Shell) | critical | - |
| `cve-2022-1471-snakeyaml.md` | SnakeYAML deserialization RCE (CVE-2022-1471) | critical | arbitrary YAML input (upload/config/API) |
| `cve-2022-21449-psychic-signatures.md` | Java ECDSA empty signature bypass (Psychic Signatures) | high | empty signature with r=0,s=0 is accepted |
| `cve-2022-22965-spring4shell.md` | Spring Framework data binding RCE (Spring4Shell) | critical | - |
| `cve-2022-25845-fastjson-autotype.md` | Fastjson autoType deserialization RCE | high | - |

## How to use this page

1. First confirm the component and version range via "Fingerprint" (if the version is outside the range, do not fire the PoC and present it as a conclusion).
2. Each PoC provides both a **probe form** and an **exploit form**; run the probe first and confirm the hit via dnslog / echo headers / observable behavior, then run the exploit.
3. For those requiring outbound connections (JNDI, deserialization callbacks), first confirm the target has outbound access; for targets without outbound access, switch to a local gadget + echo, or simply submit "exploitability evidence".
4. Land the remediation recommendation as the one-liner in the entry, and state clearly in the report "tested version + hit evidence + recommended version".
