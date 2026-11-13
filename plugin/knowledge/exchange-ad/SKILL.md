---
name: "kb-exchange-ad"
description: "Windows, Active Directory, Exchange, Outlook and SharePoint CVE assessment; identity prerequisites, patch applicability and defensive investigation."
verified: false
sources: "Compiled from public sources (CVE advisories / public analyses / business-logic classes; see each entry's references)"
---

# Exchange / Windows / AD (31 entries)
> Public-source notes and assessment cards. Candidate matches are not proof of exploitation; laboratory verification requires dated, redacted evidence.

Two main tracks:
1. **Unauthenticated external entry points** (Exchange proxy vulnerabilities, MS17-010, Zerologon) — prioritize minimal-impact validation.
2. **Post-credential domain privilege escalation** (noPac, AD CS, Kerberoast, DCSync) — from a regular domain user to domain admin.

## Entries

| File | Vulnerability | Severity | Entry Point |
|---|---|---|---|
| `adcs-esc1-esc8.md` | AD CS certificate abuse (ESC1 / ESC8 etc.) | critical | AD CS certificate enrollment and web enrollment services |
| `cve-2017-0144-eternalblue.md` | EternalBlue (MS17-010 SMBv1 remote overflow) | critical | Windows SMBv1 service on TCP 445 |
| `cve-2020-0688-exchange-viewstate.md` | Exchange ViewState deserialization (static machineKey) | critical | web.config static machineKey + ysoserial.net payload |
| `cve-2020-1472-zerologon.md` | Zerologon (Netlogon key zeroing → domain controller takeover) | critical | Domain controller Netlogon RPC service |
| `cve-2021-26855-proxylogon.md` | Exchange ProxyLogon (SSRF + arbitrary file write → RCE) | critical | Exchange HTTPS frontend and proxy endpoints |
| `cve-2021-34473-proxyshell.md` | Exchange ProxyShell (three bugs chained → RCE) | critical | Exchange HTTPS Autodiscover and backend services |
| `cve-2021-34527-printnightmare.md` | PrintNightmare (print spooler arbitrary DLL load) | critical | Windows Print Spooler RPC service |
| `cve-2021-42287-nopac.md` | noPac (sAMAccountName spoofing + PAC-less ticket → domain admin) | critical | Active Directory account management and Kerberos |
| `cve-2021-42321-exchange-deser.md` | Exchange post-auth deserialization RCE (CVE-2021-42321) | critical | .NET serialized blob in an EWS request body |
| `cve-2022-30190-follina.md` | MSDT protocol remote code execution (Follina) | critical | Document references ms-msdt:/id PCWDiagnostic |
| `cve-2022-41040-proxynotshell.md` | Exchange ProxyNotShell (SSRF + PowerShell remoting) | critical | autodiscover @ bypass + /powershell endpoint |
| `cve-2024-21410-exchange-ntlm-relay.md` | Exchange EWS NTLM relay privilege escalation (CVE-2024-21410) | critical | /ews/exchange.asmx permits NTLM relay |
| `cve-2024-21413-outlook-monikerlink.md` | Outlook MonikerLink bypass and NTLM leak (CVE-2024-21413) | critical | Append ! after file:// to bypass Protected View |
| `cve-2024-45519-zimbra-postjournal.md` | Zimbra postjournal unauthenticated command execution (CVE-2024-45519) | critical | Send postjournal an SMTP recipient containing a base64 command |
| `cve-2019-0708-microsoft-remote-desktop-services.md` | Microsoft Remote Desktop Services: Remote Desktop Services (CVE-2019-0708) | critical | Remote Desktop Services |
| `cve-2020-0796-microsoft-windows-smb.md` | Microsoft Windows SMB: SMBv3 compression (CVE-2020-0796) | critical | SMBv3 compression |
| `cve-2021-36934-microsoft-windows.md` | Microsoft Windows: Sensitive registry hive permissions (CVE-2021-36934) | high | Sensitive registry hive permissions |
| `cve-2022-26923-microsoft-active-directory-certificate-services.md` | Microsoft Active Directory Certificate Services: Certificate identity mapping (CVE-2022-26923) | high | Certificate identity mapping |
| `cve-2022-26925-microsoft-windows-lsa.md` | Microsoft Windows LSA: Authentication handling (CVE-2022-26925) | high | Authentication handling |
| `cve-2022-33679-microsoft-windows-kerberos.md` | Microsoft Windows Kerberos: Kerberos authentication (CVE-2022-33679) | high | Kerberos authentication |
| `cve-2022-37966-microsoft-windows-kerberos.md` | Microsoft Windows Kerberos: Kerberos authentication (CVE-2022-37966) | high | Kerberos authentication |
| `cve-2022-37967-microsoft-windows-kerberos.md` | Microsoft Windows Kerberos: Kerberos PAC validation (CVE-2022-37967) | high | Kerberos PAC validation |
| `cve-2023-23397-microsoft-outlook.md` | Microsoft Outlook: Mail client authentication behavior (CVE-2023-23397) | critical | Mail client authentication behavior |
| `cve-2024-38063-microsoft-windows.md` | Microsoft Windows: IPv6 network stack (CVE-2024-38063) | critical | IPv6 network stack |
| `cve-2024-49112-microsoft-windows-ldap.md` | Microsoft Windows LDAP: LDAP service (CVE-2024-49112) | critical | LDAP service |
| `cve-2024-49113-microsoft-windows-ldap.md` | Microsoft Windows LDAP: LDAP service (CVE-2024-49113) | high | LDAP service |
| `cve-2025-24054-microsoft-windows.md` | Microsoft Windows: File-triggered authentication (CVE-2025-24054) | medium | File-triggered authentication |
| `cve-2025-33073-microsoft-windows-smb.md` | Microsoft Windows SMB: SMB authentication integrity (CVE-2025-33073) | high | SMB authentication integrity |
| `cve-2025-47981-microsoft-windows-spnego.md` | Microsoft Windows SPNEGO: Network authentication negotiation (CVE-2025-47981) | critical | Network authentication negotiation |
| `cve-2025-53770-microsoft-sharepoint-server.md` | Microsoft SharePoint Server: On-premises SharePoint request processing (CVE-2025-53770) | critical | On-premises SharePoint request processing |
| `cve-2025-53771-microsoft-sharepoint-server.md` | Microsoft SharePoint Server: SharePoint path handling (CVE-2025-53771) | medium | SharePoint path handling |

## How to use this page

- First distinguish "taking the host" from "taking the domain": host access only gives you a foothold; domain rights give you the whole forest.
- After exploiting Exchange, you must **clean up webshells and privilege-escalation backdoors** (`/owa/auth/*.aspx`, `/aspnet_client/`), otherwise the next scan will still hit them.
- For any domain operation, check logs and alerting conditions (4768/4769/4624/7045) first, then decide which ticket form to use.
