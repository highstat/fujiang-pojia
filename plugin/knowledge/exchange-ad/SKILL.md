---
name: kb-exchange-ad
description: CVE/PoC knowledge base · Exchange and Windows/AD: ProxyLogon (2021-26855), ProxyShell (2021-34473), ProxyNotShell (2022-41040), ViewState (2020-0688), Zerologon (2020-1472), noPac (2021-42287), AD CS ESC, PrintNightmare (2021-34527), MS17-010, Follina (2022-30190). Each entry has a matching PoC; compiled from public sources, verified=false.
verified: false
sources: Compiled from public sources (CVE advisories / public analyses / business-logic classes; see each entry's references)
---

# Exchange / Windows / AD (14 entries)
> Entries are compiled from public sources (see "References" at the end of each file); `Exploitation steps` are hypotheses pending validation; self-validate against the target version before reporting and set `verified` to true.

Two main tracks:
1. **Unauthenticated external entry points** (Exchange proxy vulnerabilities, MS17-010, Zerologon) — prioritize minimal-impact validation.
2. **Post-credential domain privilege escalation** (noPac, AD CS, Kerberoast, DCSync) — from a regular domain user to domain admin.

## Entries

| File | Vulnerability | Severity | Entry |
|---|---|---|---|
| `adcs-esc1-esc8.md` | AD CS certificate abuse (ESC1 / ESC8 etc.) | critical | - |
| `cve-2017-0144-eternalblue.md` | EternalBlue (MS17-010 SMBv1 remote overflow) | critical | - |
| `cve-2020-0688-exchange-viewstate.md` | Exchange ViewState deserialization (static machineKey) | critical | web.config static machineKey + ysoserial.net payload |
| `cve-2020-1472-zerologon.md` | Zerologon (Netlogon key zeroing → domain controller takeover) | critical | - |
| `cve-2021-26855-proxylogon.md` | Exchange ProxyLogon (SSRF + arbitrary file write → RCE) | critical | - |
| `cve-2021-34473-proxyshell.md` | Exchange ProxyShell (three bugs chained → RCE) | critical | - |
| `cve-2021-34527-printnightmare.md` | PrintNightmare (print spooler arbitrary DLL load) | critical | - |
| `cve-2021-42287-nopac.md` | noPac (sAMAccountName spoofing + PAC-less ticket → domain admin) | critical | - |
| `cve-2021-42321-exchange-deser.md` | Exchange post-auth deserialization RCE (CVE-2021-42321) | critical | .NET serialized blob in the EWS request body |
| `cve-2022-30190-follina.md` | MSDT protocol remote code execution (Follina) | critical | document references ms-msdt:/id PCWDiagnostic |
| `cve-2022-41040-proxynotshell.md` | Exchange ProxyNotShell (SSRF + PowerShell remoting) | critical | autodiscover @ bypass + /powershell endpoint |
| `cve-2024-21410-exchange-ntlm-relay.md` | Exchange EWS NTLM relay privilege escalation (CVE-2024-21410) | critical | /ews/exchange.asmx allows NTLM relay |
| `cve-2024-21413-outlook-monikerlink.md` | Outlook MonikerLink bypass and NTLM leak (CVE-2024-21413) | critical | append ! after file:// to bypass Protected View |
| `cve-2024-45519-zimbra-postjournal.md` | Zimbra postjournal unauthenticated command execution (CVE-2024-45519) | critical | SMTP recipient containing a base64 command sent to postjournal |

## How to use this page

- First distinguish "taking the host" from "taking the domain": host access only gives you a foothold; domain rights give you the whole forest.
- After exploiting Exchange, you must **clean up webshells and privilege-escalation backdoors** (`/owa/auth/*.aspx`, `/aspnet_client/`), otherwise the next scan will still hit them.
- For any domain operation, check logs and alerting conditions (4768/4769/4624/7045) first, then decide which ticket form to use.
