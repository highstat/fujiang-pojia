---
name: kb-cloud-container
description: CVE/PoC knowledge base · cloud-native / virtualization / middleware: runc (2024-21626), cgroups (2022-0492), Docker API 2375, unauthenticated Redis, Nacos (2021-29441), vCenter upload (2021-21972), Workspace ONE SSTI (2022-22954). Each entry has a matching PoC; compiled from public sources, verified=false.
verified: false
sources: Compiled from public sources (CVE advisories / public analyses / business-logic issues; see each entry's references)
---

# Cloud / Containers / Middleware (14 entries)
> Entries are compiled from public sources (see "References" at the end); `Exploitation steps` are unverified hypotheses. Before reporting, validate against the target version and set `verified` to true.

The criterion is always "**can this service be reached directly?**" Three things are especially common on gambling / payment-processing sites: a publicly listable `bucket` (ID photos, deposit receipts), `3306/27017` exposed with weak credentials, and a wide-open `Redis`. They are worth more than any CVE.

## Entries

| File | Vulnerability | Severity | Entry |
|---|---|---|---|
| `cve-2019-7238-nexus-rce.md` | Nexus Repository unauthenticated RCE (CVE-2019-7238) | critical | EL injection in POST /service/extdirect |
| `cve-2019-9193-postgres.md` | PostgreSQL COPY PROGRAM command execution (CVE-2019-9193) | high | COPY ... TO PROGRAM |
| `cve-2021-21972-vcenter-upload.md` | vCenter Server unauthenticated upload → RCE (vROPS plugin) | critical | POST /ui/vropspluginui/rest/services/uploadova |
| `cve-2021-29441-nacos.md` | Nacos authentication bypass (User-Agent allowlist) | critical | - |
| `cve-2021-43798-grafana-file-read.md` | Grafana plugin path traversal arbitrary file read (CVE-2021-43798) | high | /public/plugins/<plugin>/../../../../etc/passwd |
| `cve-2022-0492-cgroup-release-agent.md` | cgroups release_agent container escape | high | Mount cgroup v1 and write release_agent |
| `cve-2022-22954-workspace-one-ssti.md` | VMware Workspace ONE Access template injection RCE | critical | /catalog-portal/ui/oauth/verify?deviceUdid= |
| `cve-2023-27532-veeam-credential-dump.md` | Veeam Backup credential leak (CVE-2023-27532) | high | 9401 Backup Service returns configuration database credentials |
| `cve-2024-21626-runc-leaky-vessels.md` | runc file descriptor leak escape (Leaky Vessels) | critical | WORKDIR /proc/self/fd/N yields a host fd |
| `cve-2024-37085-esxi-auth-bypass.md` | VMware ESXi authentication bypass → hypervisor compromise (CVE-2024-37085) | critical | Create an "ESX Admins" group in AD → automatically gain ESXi admin rights |
| `cve-2024-40711-veeam-rce.md` | Veeam Backup unauthenticated RCE (CVE-2024-40711) | critical | Credential deserialization in the 9419 console |
| `docker-api-2375.md` | Docker Remote API unauthenticated (take the host directly) | critical | - |
| `mongodb-unauth.md` | MongoDB unauthenticated access (dump the database directly) | critical | mongod has no auth and is exposed |
| `redis-unauth.md` | Redis unauthenticated (file write / module load / master-slave replication) | critical | - |

## How to use this page

- Start collecting from **frontend assets**: image domains in JS, `ossUrl` in `config.js`, `?Expires=` signatures in download links → infer bucket names.
- For object storage, only list and fetch 1 object as evidence; for databases, only run `select 1` and pull one sample row — do not dump the database.
- Once you have DB access, look first at the four tables "members / orders / withdrawals / agents" — that is the entire value of these targets.
