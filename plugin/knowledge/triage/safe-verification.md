---
title: Safe PoC verification and evidence-collection standards
cve: None
severity: info
cvss: 0
product: Methodology
ports: Any
keywords: verification, evidence, safety, cleanup
verified: false
sources: Compiled from public sources (business-logic / implementation / configuration flaws without CVEs; see references below)
---

## Authorization prerequisites (state them explicitly in the report)

- Target list and time window, approver, and approved level (read-only / verification / exploitation).
- Impact surface: single host, single instance, shared database, edge device (a crash can affect the entire service chain).

## Verification levels (lightest to heaviest; use the lightest sufficient action)

| Level | Action | Examples |
|---|---|---|
| L1 Read-only | Read versions/configuration, unauthenticated GET | `/actuator/env`, `redis-cli INFO`, `/nacos/v1/auth/users` |
| L2 Probe | Send harmless payloads and check output/DNS | `${jndi:dns://token}`, `id` command, DNSLog |
| L3 Exploitation | Write files, establish callbacks, add accounts | Write JSP, add an administrator, load modules |
| L4 Deployment | Persistence, lateral movement | Scheduled tasks, golden tickets, configuration changes |

**Stop at L2 by default**, unless authorization explicitly covers L3/L4.

## Evidence checklist (retain every item)

- Raw request (complete headers and body) + raw response (status code and relevant output).
- Timestamp and timezone, source IP, target IP:port.
- Version evidence (one command and its output).
- L3 and above: paths and content summaries of written files, process trees, callback records, and before/after cleanup comparison.

## Precautions for high-risk actions

- Kernel exploits (nf_tables / overlayfs): test first on a comparable lab system and record panic frequency; request a maintenance window before production use.
- Domain-controller operations (Zerologon / noPac): **modify machine accounts or directory attributes**; prepare recovery scripts first.
- Edge devices: first check whether they are in the production service path; leave policy changes/certificate deletion until last.
- Always use disposable listener ports for callbacks and close them afterward; avoid exposing the testing host to the target network.

## Cleanup checklist

1. Remove written webshells / scheduled tasks / SUID files / newly created accounts.
2. Restore modified configuration (OAB, `params.resource.loader`, `session.auto_start`, `pipeline.first.*`).
3. Revoke tokens, temporary ServiceAccounts, and API keys you created.
4. Record cleanup actions and timestamps in the report for client review.
