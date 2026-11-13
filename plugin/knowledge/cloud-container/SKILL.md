---
name: "kb-cloud-container"
description: "Cloud infrastructure, virtualization, containers, build systems and middleware; CVE applicability, runtime isolation, management exposure and defensive triage."
verified: false
sources: "Compiled from public sources (CVE advisories / public analyses / business-logic issues; see each entry's references)"
---

# Cloud / Containers / Middleware (27 entries)
> Public-source notes and assessment cards. Candidate matches are not proof of exploitation; laboratory verification requires dated, redacted evidence.

The criterion is always "**can this service be reached directly?**" Three things are especially common on gambling / payment-processing sites: a publicly listable `bucket` (ID photos, deposit receipts), `3306/27017` exposed with weak credentials, and a wide-open `Redis`. They are worth more than any CVE.

## Entries

| File | Vulnerability | Severity | Entry Point |
|---|---|---|---|
| `cve-2019-7238-nexus-rce.md` | Nexus Repository unauthenticated RCE (CVE-2019-7238) | critical | EL injection in POST /service/extdirect |
| `cve-2019-9193-postgres.md` | PostgreSQL COPY PROGRAM command execution (CVE-2019-9193) | high | COPY ... TO PROGRAM |
| `cve-2021-21972-vcenter-upload.md` | vCenter Server unauthenticated upload → RCE (vROPS plugin) | critical | POST /ui/vropspluginui/rest/services/uploadova |
| `cve-2021-29441-nacos.md` | Nacos authentication bypass (User-Agent allowlist) | critical | Nacos HTTP authentication and configuration API |
| `cve-2021-43798-grafana-file-read.md` | Grafana plugin path traversal arbitrary file read (CVE-2021-43798) | high | /public/plugins/<plugin>/../../../../etc/passwd |
| `cve-2022-0492-cgroup-release-agent.md` | cgroups release_agent container escape | high | Mount cgroup v1 and write release_agent |
| `cve-2022-22954-workspace-one-ssti.md` | VMware Workspace ONE Access template injection RCE | critical | /catalog-portal/ui/oauth/verify?deviceUdid= |
| `cve-2023-27532-veeam-credential-dump.md` | Veeam Backup credential leak (CVE-2023-27532) | high | 9401 Backup Service returns configuration database credentials |
| `cve-2024-21626-runc-leaky-vessels.md` | runc file descriptor leak escape (Leaky Vessels) | critical | WORKDIR /proc/self/fd/N yields a host fd |
| `cve-2024-37085-esxi-auth-bypass.md` | VMware ESXi authentication bypass → hypervisor compromise (CVE-2024-37085) | critical | Create an "ESX Admins" group in AD → automatically gain ESXi admin rights |
| `cve-2024-40711-veeam-rce.md` | Veeam Backup unauthenticated RCE (CVE-2024-40711) | critical | Credential deserialization in the 9419 console |
| `docker-api-2375.md` | Docker Remote API unauthenticated (take the host directly) | critical | Docker Remote API on TCP 2375 or 2376 |
| `mongodb-unauth.md` | MongoDB unauthenticated access (dump the database directly) | critical | mongod has no auth and is exposed |
| `redis-unauth.md` | Redis unauthenticated (file write / module load / master-slave replication) | critical | Redis network service without authentication |
| `cve-2023-32315-openfire.md` | Openfire: Administration console (CVE-2023-32315) | high | Administration console |
| `cve-2024-0132-nvidia-container-toolkit.md` | NVIDIA Container Toolkit: Container runtime device configuration (CVE-2024-0132) | critical | Container runtime device configuration |
| `cve-2024-23651-moby-buildkit.md` | Moby BuildKit: Build cache mounts (CVE-2024-23651) | high | Build cache mounts |
| `cve-2024-23652-moby-buildkit.md` | Moby BuildKit: Build cleanup handling (CVE-2024-23652) | critical | Build cleanup handling |
| `cve-2024-23653-moby-buildkit.md` | Moby BuildKit: Build entitlement checks (CVE-2024-23653) | critical | Build entitlement checks |
| `cve-2024-29849-veeam-backup-enterprise-manager.md` | Veeam Backup Enterprise Manager: Enterprise Manager authentication (CVE-2024-29849) | critical | Enterprise Manager authentication |
| `cve-2024-37079-vmware-vcenter-server.md` | VMware vCenter Server: DCERPC service (CVE-2024-37079) | critical | DCERPC service |
| `cve-2024-38812-vmware-vcenter-server.md` | VMware vCenter Server: DCERPC service (CVE-2024-38812) | critical | DCERPC service |
| `cve-2024-41110-docker-engine.md` | Docker Engine: Authorization plugins (CVE-2024-41110) | critical | Authorization plugins |
| `cve-2025-14847-mongodb.md` | MongoDB: Compressed network messages (CVE-2025-14847) | high | Compressed network messages |
| `cve-2025-22224-vmware-esxi-workstation.md` | VMware ESXi Workstation: Virtual machine device handling (CVE-2025-22224) | critical | Virtual machine device handling |
| `cve-2025-22225-vmware-esxi.md` | VMware ESXi: Hypervisor isolation (CVE-2025-22225) | high | Hypervisor isolation |
| `cve-2025-22226-vmware-esxi-workstation-fusion.md` | VMware ESXi Workstation Fusion: Virtual machine data handling (CVE-2025-22226) | high | Virtual machine data handling |

## How to use this page

- Start collecting from **frontend assets**: image domains in JS, `ossUrl` in `config.js`, `?Expires=` signatures in download links → infer bucket names.
- For object storage, only list and fetch 1 object as evidence; for databases, only run `select 1` and pull one sample row — do not dump the database.
- Once you have DB access, look first at the four tables "members / orders / withdrawals / agents" — that is the entire value of these targets.
