---
id: "fingerprint-workflow"
title: "Fingerprint-to-vulnerability matching workflow"
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
keywords: "fingerprint, recon, mapping, version"
entry: "Asset fingerprinting and version-identification workflow"
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

## 1. Classify the asset first (determines which category to consult)

| Observation | Asset type | First category |
|---|---|---|
| 7001 / `WebLogic` | Java middleware | `kb-java-deser` |
| `X-Confluence-*` / `X-Jenkins` / `GitLab` | Java Web / CI | `kb-java-web` |
| 8090/8111/8983 and a Java stack | Same as above | `kb-java-web` |
| `GlobalProtect` / `Citrix Gateway` / `FortiGate` / `BIG-IP` | Edge device | `kb-edge-device` |
| `/owa/` `/ecp/` `/autodiscover/` | Exchange | `kb-exchange-ad` |
| 445 + domain controller / 88 open | AD | `kb-exchange-ad` |
| `X-Powered-By: PHP` / Drupal / ThinkPHP | PHP site | `kb-web-cms` |
| Low-privilege shell / inside a container | Privilege escalation | `kb-linux-priv` |
| 2375 / 6379 / 5432 / 8848 / 6443 / 10250 | Cloud-native and middleware | `kb-cloud-container` |

## 2. Obtain the version (ordered by reliability)

1. Application-reported: `/version`, `/api/v1/version`, `X-Jenkins`, `X-OWA-Version`, `X-FEServer`, `X-Generator`, `Server`.
2. Static-resource fingerprints: hashes under `/static/js/...`, `CHANGELOG.txt`, `/core/CHANGELOG.txt`, `/help`, `/login.action` footers.
3. Error differences: stacks triggered by invalid parameters, `Whitelabel Error Page`, `Ignition` pages.
4. Ports/protocols: `nmap -sV` banners (often inaccurate for custom middleware; reference only).

## 3. Map to entries

- Cross-check the product in `name` and the `versions` range; if the range does not cover the target, select another entry or record "component not observed".
- One asset may match several entries (for example, Exchange 2019 may expose ProxyLogon / ProxyShell / zero-day surfaces); rank by **impact × verifiability**.

## 4. Common misinterpretations

- Reverse proxies/gateways rewrite response headers → the apparent version belongs to the gateway.
- Container-image version ≠ application version (`Server: nginx` may hide Tomcat).
- A WAF's 403/blank 200 response is mistaken for "not vulnerable"; verify again using a different path/parameter.
- A CDN caches an outdated `/version` value.
