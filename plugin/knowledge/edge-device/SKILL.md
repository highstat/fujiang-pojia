---
name: kb-edge-device
description: CVE/PoC knowledge base · edge devices and remote operations: PAN-OS (2024-3400), Ivanti (2023-46805+2024-21887), Pulse file read (2019-11510), Citrix path traversal (2019-19781), FortiOS management-plane bypass (2022-40684)/traversal (2018-13379)/2FA bypass (2020-12812), F5 iControl (2022-1388/2021-22986)/TMUI (2020-5902). Each entry has a matching PoC; compiled from public sources, verified=false.
verified: false
sources: Compiled from public sources (CVE advisories / public analyses / business-logic issues; see each entry's references)
---

# Edge Devices / VPN / Load Balancers (16 entries)
> Entries are compiled from public sources (see "References" at the end); `Exploitation steps` are unverified hypotheses. Before reporting, validate against the target version and set `verified` to true.

The value of these targets is not single-host access but **sessions and credentials**: an SSL VPN's memory holds everyone's live tokens, an ADC's configuration stores backend addresses and certificates, and a firewall's management plane often leads straight to the internal core.

## Entries

| File | Vulnerability | Severity | Entry |
|---|---|---|---|
| `cve-2018-13379-fortinet-fortios.md` | FortiOS SSL VPN path traversal (credential read) | critical | - |
| `cve-2019-11510-pulse-secure-file-read.md` | Pulse Secure arbitrary file read (credentials and sessions) | critical | /dana-na/../dana/html5acc/guacamole/ traversal |
| `cve-2019-19781-citrix-path-traversal.md` | Citrix ADC path traversal → template injection RCE | critical | - |
| `cve-2020-12812-fortios-2fa-case-bypass.md` | FortiOS SSL VPN two-factor bypass (username case) | high | Change the username case to skip 2FA |
| `cve-2020-5902-f5-tmui.md` | F5 BIG-IP TMUI unauthenticated RCE (..;/ path traversal) | critical | /tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp |
| `cve-2021-22986-f5-icontrol.md` | F5 iControl REST unauthenticated RCE (2021 variant) | critical | POST /mgmt/tm/util/bash with a fake token |
| `cve-2022-1388-f5-icontrol.md` | F5 BIG-IP iControl REST authentication bypass → command execution | critical | - |
| `cve-2022-40684-fortios-auth-bypass.md` | FortiOS / FortiProxy management-plane authentication bypass (forged Forwarded header) | critical | Forwarded: for="127.0.0.1" impersonating localhost |
| `cve-2023-35078-ivanti-epmm-auth-bypass.md` | Ivanti EPMM authentication bypass (CVE-2023-35078) | critical | /mifs/aad/api/v2/admins/users unauthenticated |
| `cve-2023-46805-2024-21887-ivanti.md` | Ivanti Connect Secure authentication bypass + command injection (chained) | critical | - |
| `cve-2023-48788-forticlient-ems-sqli.md` | FortiClient EMS SQL injection → unauthenticated RCE (CVE-2023-48788) | critical | /api/v1/fortitray/installer multipart field injection |
| `cve-2024-0012-panos-auth-bypass.md` | PAN-OS management-plane authentication bypass → root RCE (CVE-2024-0012 + CVE-2024-9474) | critical | /php/ztp_gate.php?PanGPSRunning=true bypasses auth → escalate with /php/utils.php |
| `cve-2024-0204-goanywhere-auth-bypass.md` | GoAnywhere MFT authentication bypass → create a new admin (CVE-2024-0204) | critical | /goanywhere/images/..;/wizard/InitialAccountSetup.xhtml |
| `cve-2024-24919-checkpoint-quantum.md` | Check Point Quantum security gateway arbitrary file read (CVE-2024-24919) | critical | POST /clients/MyCRL a parameter reads arbitrary files |
| `cve-2024-3400-panos-globalprotect.md` | PAN-OS GlobalProtect command injection | critical | - |
| `cve-2024-47575-fortimanager-fortijump.md` | FortiManager unauthenticated RCE (FortiJump, CVE-2024-47575) | critical | FGFM (541) protocol unauthenticated registration → push scripts |

## How to use this page

1. **Identify the device before attacking**: login-page fingerprint + version endpoint; do not fire a PAN-OS PoC at a FortiGate.
2. For device targets, prioritize **read-only evidence collection** (config export, session tables); put destructive exploitation (changing policies, deleting certificates) last.
3. Before attacking, confirm whether the device is in a production path: if the VPN/ADC goes down, the whole service goes down. Choose an off-peak window and validate on a node that does not affect production.
4. Once you have the device, first export the config (including local accounts and hashes) and capture the `sslvpn_websession` / `SESSID` tables for lateral movement into the internal network.
