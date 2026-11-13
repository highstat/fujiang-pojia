---
name: "kb-edge-device"
description: "VPN, firewall, gateway, NAS and remote-support appliances; CVE applicability, management-plane exposure, incident scoping and remediation."
verified: false
sources: "Compiled from public sources (CVE advisories / public analyses / business-logic issues; see each entry's references)"
---

# Edge Devices / VPN / Load Balancers (36 entries)
> Public-source notes and assessment cards. Candidate matches are not proof of exploitation; laboratory verification requires dated, redacted evidence.

The value of these targets is not single-host access but **sessions and credentials**: an SSL VPN's memory holds everyone's live tokens, an ADC's configuration stores backend addresses and certificates, and a firewall's management plane often leads straight to the internal core.

## Entries

| File | Vulnerability | Severity | Entry Point |
|---|---|---|---|
| `cve-2018-13379-fortinet-fortios.md` | FortiOS SSL VPN path traversal (credential read) | critical | FortiOS SSL VPN web portal |
| `cve-2019-11510-pulse-secure-file-read.md` | Pulse Secure arbitrary file read (credentials and sessions) | critical | /dana-na/../dana/html5acc/guacamole/ traversal |
| `cve-2019-19781-citrix-path-traversal.md` | Citrix ADC path traversal → template injection RCE | critical | Citrix ADC or Gateway web interface |
| `cve-2020-12812-fortios-2fa-case-bypass.md` | FortiOS SSL VPN two-factor bypass (username case) | critical | Change the username case to skip 2FA |
| `cve-2020-5902-f5-tmui.md` | F5 BIG-IP TMUI unauthenticated RCE (..;/ path traversal) | critical | /tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp |
| `cve-2021-22986-f5-icontrol.md` | F5 iControl REST unauthenticated RCE (2021 variant) | critical | POST /mgmt/tm/util/bash with a fake token |
| `cve-2022-1388-f5-icontrol.md` | F5 BIG-IP iControl REST authentication bypass → command execution | critical | BIG-IP iControl REST management API |
| `cve-2022-40684-fortios-auth-bypass.md` | FortiOS / FortiProxy management-plane authentication bypass (forged Forwarded header) | critical | Forwarded: for="127.0.0.1" impersonating localhost |
| `cve-2023-35078-ivanti-epmm-auth-bypass.md` | Ivanti EPMM authentication bypass (CVE-2023-35078) | critical | /mifs/aad/api/v2/admins/users unauthenticated |
| `cve-2023-46805-2024-21887-ivanti.md` | Ivanti Connect Secure authentication bypass + command injection (chained) | critical | Ivanti Connect Secure or Policy Secure web interface |
| `cve-2023-48788-forticlient-ems-sqli.md` | FortiClient EMS SQL injection → unauthenticated RCE (CVE-2023-48788) | critical | multipart field injection in /api/v1/fortitray/installer |
| `cve-2024-0012-panos-auth-bypass.md` | PAN-OS management-plane authentication bypass → root RCE (CVE-2024-0012 + CVE-2024-9474) | critical | /php/ztp_gate.php?PanGPSRunning=true bypasses authentication → use /php/utils.php to escalate |
| `cve-2024-0204-goanywhere-auth-bypass.md` | GoAnywhere MFT authentication bypass → create a new admin (CVE-2024-0204) | critical | /goanywhere/images/..;/wizard/InitialAccountSetup.xhtml |
| `cve-2024-24919-checkpoint-quantum.md` | Check Point Quantum security gateway arbitrary file read (CVE-2024-24919) | critical | the a parameter of POST /clients/MyCRL reads arbitrary files |
| `cve-2024-3400-panos-globalprotect.md` | PAN-OS GlobalProtect command injection | critical | PAN-OS GlobalProtect portal or gateway |
| `cve-2024-47575-fortimanager-fortijump.md` | FortiManager unauthenticated RCE (FortiJump, CVE-2024-47575) | critical | unauthenticated registration on the FGFM (541) protocol → push scripts |
| `cve-2023-20198-cisco-ios-xe.md` | Cisco IOS XE: Web UI management service (CVE-2023-20198) | critical | Web UI management service |
| `cve-2023-20273-cisco-ios-xe.md` | Cisco IOS XE: Web UI command handling (CVE-2023-20273) | high | Web UI command handling |
| `cve-2023-27997-fortinet-fortios-fortiproxy.md` | Fortinet FortiOS FortiProxy: SSL VPN (CVE-2023-27997) | critical | SSL VPN |
| `cve-2023-3519-citrix-netscaler-adc-gateway.md` | Citrix NetScaler ADC Gateway: Gateway and authentication virtual servers (CVE-2023-3519) | critical | Gateway and authentication virtual servers |
| `cve-2023-4966-citrix-netscaler-adc-gateway.md` | Citrix NetScaler ADC Gateway: Appliance session handling (CVE-2023-4966) | critical | Appliance session handling |
| `cve-2024-1708-connectwise-screenconnect.md` | ConnectWise ScreenConnect: Path handling (CVE-2024-1708) | high | Path handling |
| `cve-2024-1709-connectwise-screenconnect.md` | ConnectWise ScreenConnect: Setup and authentication workflow (CVE-2024-1709) | critical | Setup and authentication workflow |
| `cve-2024-21762-fortinet-fortios.md` | Fortinet FortiOS: SSL VPN (CVE-2024-21762) | critical | SSL VPN |
| `cve-2024-23113-fortinet-fortios.md` | Fortinet FortiOS: FGFM management protocol (CVE-2024-23113) | critical | FGFM management protocol |
| `cve-2024-27130-qnap-qts-quts-hero.md` | QNAP QTS QuTS hero: NAS sharing functionality (CVE-2024-27130) | high | NAS sharing functionality |
| `cve-2024-28995-solarwinds-serv-u.md` | SolarWinds Serv-U: File-transfer HTTP path handling (CVE-2024-28995) | high | File-transfer HTTP path handling |
| `cve-2024-55591-fortinet-fortios-fortiproxy.md` | Fortinet FortiOS FortiProxy: Management interface (CVE-2024-55591) | critical | Management interface |
| `cve-2024-57727-simplehelp.md` | SimpleHelp: Remote-support service (CVE-2024-57727) | critical | Remote-support service |
| `cve-2025-0108-palo-alto-networks-pan-os.md` | Palo Alto Networks PAN-OS: Management web interface (CVE-2025-0108) | high | Management web interface |
| `cve-2025-0282-ivanti-connect-secure.md` | Ivanti Connect Secure: VPN appliance service (CVE-2025-0282) | critical | VPN appliance service |
| `cve-2025-22457-ivanti-connect-secure.md` | Ivanti Connect Secure: VPN appliance input processing (CVE-2025-22457) | critical | VPN appliance input processing |
| `cve-2025-24472-fortinet-fortios-fortiproxy.md` | Fortinet FortiOS FortiProxy: Management interface (CVE-2025-24472) | high | Management interface |
| `cve-2025-25257-fortinet-fortiweb.md` | Fortinet FortiWeb: Web management database requests (CVE-2025-25257) | critical | Web management database requests |
| `cve-2025-5777-citrix-netscaler-adc-gateway.md` | Citrix NetScaler ADC Gateway: Gateway memory handling (CVE-2025-5777) | critical | Gateway memory handling |
| `cve-2025-6543-citrix-netscaler-adc-gateway.md` | Citrix NetScaler ADC Gateway: Gateway memory handling (CVE-2025-6543) | critical | Gateway memory handling |

## How to use this page

1. **Identify the device before attacking**: login-page fingerprint + version endpoint; do not fire a PAN-OS PoC at a FortiGate.
2. For device targets, prioritize **read-only evidence collection** (config export, session tables); put destructive exploitation (changing policies, deleting certificates) last.
3. Before attacking, confirm whether the device is in a production path: if the VPN/ADC goes down, the whole service goes down. Choose an off-peak window and validate on a node that does not affect production.
4. Once you have the device, first export the config (including local accounts and hashes) and capture the `sslvpn_websession` / `SESSID` tables for lateral movement into the internal network.
