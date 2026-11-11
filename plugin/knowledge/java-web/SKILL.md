---
name: kb-java-web
description: CVE/PoC knowledge base · Java Web / CI / middleware — Confluence OGNL(2022-26134)/pre-auth(2021-26084)/SSTI(2023-22527)/restore(2023-22518)/administrator takeover(2023-22515), Jenkins(2024-23897), TeamCity(2023-42793/2024-27198), Solr(2019-17558), Tomcat AJP(2020-1938)/PUT(2017-12615), Struts2 S2-066(2023-50164), ActiveMQ(2023-46604), WebLogic console(2020-14882)/async(2019-2725). Each entry has a corresponding PoC; compiled from public sources, verified=false.
verified: false
sources: Compiled from public sources (CVE advisories / public analyses / business logic issues; see each entry's references)
---

# Java Web / CMS / CI (22 entries)
> Entries are compiled from public sources (see References at the end); `Exploitation Steps` are hypotheses pending verification. Before reporting, validate against the target version and set `verified` to true.

Deployment leftovers in customized RuoYi / Spring Boot applications (default passwords, Druid, Actuator) are covered alongside business logic issues in `kb-gray-market`; this section covers **Java Web / CI components with CVEs**.

## Entries

| File | Vulnerability | Severity | Entry Point |
|---|---|---|---|
| `cve-2017-12615-tomcat-put.md` | Tomcat PUT arbitrary file write (JSP deployment) | critical | PUT /x.jsp/ to write a webshell |
| `cve-2019-17558-solr-velocity.md` | Apache Solr Velocity template injection RCE | high | - |
| `cve-2019-2725-weblogic-async.md` | WebLogic wls9_async_response unauthenticated RCE (exploited in the wild in 2019) | critical | /wls9_async_response/on/asyncResponseService |
| `cve-2020-14882-weblogic-console.md` | WebLogic console unauthenticated RCE (console.portal path traversal) | critical | /console/css/%252e%252e%252fconsole.portal |
| `cve-2020-1938-tomcat-ajp-ghostcat.md` | Tomcat AJP file read / inclusion (Ghostcat) | critical | Read WEB-INF/web.xml over AJP 8009 |
| `cve-2021-25646-druid-rce.md` | Apache Druid unauthenticated RCE (CVE-2021-25646) | critical | Insert JS into the filter in POST /druid/indexer/v1/sampler |
| `cve-2021-26084-confluence-ognl-preauth.md` | Confluence unauthenticated OGNL injection (pre-auth, ENCODED_TOKEN) | critical | queryString in /pages/doenterpagevariables.action |
| `cve-2022-22947-gateway-spel.md` | Spring Cloud Gateway Actuator SpEL injection RCE (CVE-2022-22947) | critical | Add a SpEL filter at /actuator/gateway/routes, then refresh |
| `cve-2022-22963-spring-cloud-function.md` | Spring Cloud Function SpEL injection RCE (CVE-2022-22963) | critical | spring.cloud.function.routing-expression request header |
| `cve-2022-26134-confluence-ognl.md` | Confluence unauthenticated OGNL injection (Confluence OGNL RCE) | critical | - |
| `cve-2023-22515-confluence-admin.md` | Confluence unauthenticated administrator takeover (setup flow left enabled) | critical | Reopen the setup flow to recreate an administrator |
| `cve-2023-22518-confluence-setup-restore.md` | Confluence unauthenticated restore leading to administrator takeover | critical | Upload your own export to /json/setup-restore.action |
| `cve-2023-22527-confluence-ssti.md` | Confluence template injection RCE (text-inline.vm) | critical | - |
| `cve-2023-27350-papercut-setup-bypass.md` | PaperCut NG/MF authentication bypass → RCE (CVE-2023-27350) | critical | Unauthenticated /app?service=page/SetupCompleted → print script execution |
| `cve-2023-42793-teamcity-auth-bypass.md` | TeamCity authentication bypass → administrator token → RCE | critical | - |
| `cve-2023-46604-activemq-openwire.md` | Apache ActiveMQ OpenWire deserialization RCE | critical | Send ClassInfo over OpenWire to load remote XML |
| `cve-2023-50164-struts2-s2-066.md` | Struts2 file upload path traversal (S2-066) | critical | Directory traversal by modifying the uploaded filename |
| `cve-2023-7028-gitlab-takeover.md` | GitLab arbitrary account takeover (CVE-2023-7028) | critical | Supply two addresses in user[email][] in POST /users/password |
| `cve-2024-23897-jenkins-file-read.md` | Jenkins CLI arbitrary file read | high | - |
| `cve-2024-27198-teamcity-bypass.md` | TeamCity authentication bypass (;.jsp path parameter) | critical | Bypass authorization at /app/rest/server;.jsp, then create an administrator |
| `cve-2024-38856-ofbiz-unauth-rce.md` | Apache OFBiz unauthenticated RCE (CVE-2024-38856) | critical | Unauthenticated Groovy execution at /webtools/control/ProgramExport |
| `cve-2024-53677-struts2-s2-067.md` | Struts2 file upload path traversal → RCE (S2-067, CVE-2024-53677) | critical | Use ../ in multipart UploadFileName to traverse to the web root |

## How to Use This Page

- Check these four "development leftovers" first: `/prod-api/`, `/druid/`, `/actuator`, `/swagger-ui.html`. This is much faster than looking for CVEs.
- Actuator/heapdump can directly expose DB/Redis passwords and the JWT secret; once obtained, return to the asset classification in `kb-triage`.
- "Scheduled tasks" and "code generators" in RuoYi-based admin panels are ready-made RCE entry points, more reliable than chained deserialization.
