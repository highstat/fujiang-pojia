---
name: "kb-linux-priv"
description: "Linux kernel, system libraries, services and local privilege boundaries; distribution-aware CVE assessment, prerequisites and patch verification."
verified: false
sources: "Compiled from public sources (CVE advisories / public analyses / business-logic issues; see each entry's references)"
---

# Linux local privilege escalation (22 entries)
> Public-source notes and assessment cards. Candidate matches are not proof of exploitation; laboratory verification requires dated, redacted evidence.

Standard steps after obtaining a low-privilege shell (`www-data`, `nobody`, or root inside a container):

```bash
uname -a; cat /etc/os-release; id; sudo -l 2>/dev/null; find / -perm -4000 -type f 2>/dev/null
dpkg -l | grep -E 'sudo|policykit|glibc' 2>/dev/null || rpm -qa | grep -E 'sudo|polkit|glibc'
```

**Check the kernel and glibc/sudo/polkit versions first**, then match entries. Do not immediately compile an unfamiliar kernel exploit—a crash is more likely than successful escalation.

## Entries

| File | Vulnerability | Severity | Entry Point |
|---|---|---|---|
| `cve-2021-3156-baron-samedit.md` | Baron Samedit (sudo heap-overflow privilege escalation) | high | Local sudo/sudoedit command-line processing |
| `cve-2021-3493-ubuntu-overlayfs.md` | Ubuntu overlayfs local privilege escalation (2021) | high | userns + copying setuid attributes through overlayfs |
| `cve-2021-4034-pwnkit.md` | PwnKit (polkit pkexec local privilege escalation) | high | Local pkexec executable |
| `cve-2022-0185-fs-context-overflow.md` | fs_context heap-overflow privilege escalation (legacy_parse_param) | high | unshare -Ur + oversized legacy mount parameters |
| `cve-2022-0847-dirtypipe.md` | Dirty Pipe (page-cache overwrite privilege escalation) | high | Local Linux pipe and page-cache operations |
| `cve-2023-0386-overlayfs.md` | overlayfs copy-up permission-bypass privilege escalation | high | Local Linux OverlayFS and user namespace operations |
| `cve-2023-22809-sudo-edit.md` | sudoedit environment-variable injection privilege escalation (EDITOR containing --) | high | EDITOR='vim -- /etc/sudoers' |
| `cve-2023-2640-gameoverlay.md` | Ubuntu overlayfs privilege escalation (GameOver(lay)) | high | unshare + overlayfs xattr copy bypass |
| `cve-2023-32233-nftables.md` | nf_tables use-after-free privilege escalation (2023) | high | unshare + batched nft rules triggering UAF |
| `cve-2024-0582-io-uring-uaf.md` | Linux io_uring local privilege escalation (CVE-2024-0582) | high | Page release after fixed-file registration → remap and overwrite |
| `cve-2024-1086-nftables.md` | nf_tables use-after-free privilege escalation | high | Local Linux nftables and user namespace operations |
| `cve-2022-2588-linux-kernel.md` | Linux kernel: Network traffic-control filters (CVE-2022-2588) | medium | Network traffic-control filters |
| `cve-2023-38545-curl-libcurl.md` | curl libcurl: SOCKS5 proxy hostname handling (CVE-2023-38545) | high | SOCKS5 proxy hostname handling |
| `cve-2023-4911-gnu-glibc.md` | GNU glibc: Dynamic loader environment parsing (CVE-2023-4911) | high | Dynamic loader environment parsing |
| `cve-2024-3094-xz-utils.md` | XZ Utils: Compromised release artifacts (CVE-2024-3094) | critical | Compromised release artifacts |
| `cve-2024-47076-libcupsfilters.md` | libcupsfilters: IPP attribute validation (CVE-2024-47076) | high | IPP attribute validation |
| `cve-2024-47175-libppd.md` | libppd: Printer description generation (CVE-2024-47175) | high | Printer description generation |
| `cve-2024-47176-cups-browsed.md` | cups-browsed: Printer discovery service (CVE-2024-47176) | medium | Printer discovery service |
| `cve-2024-6387-openssh.md` | OpenSSH: sshd connection handling (CVE-2024-6387) | high | sshd connection handling |
| `cve-2024-6409-openssh.md` | OpenSSH: Distribution-specific sshd behavior (CVE-2024-6409) | high | Distribution-specific sshd behavior |
| `cve-2025-32462-sudo.md` | sudo: sudo host matching (CVE-2025-32462) | low | sudo host matching |
| `cve-2025-32463-sudo.md` | sudo: sudo root-directory handling (CVE-2025-32463) | critical | sudo root-directory handling |

## How to use this page

1. In containers, check privileges first: `capsh --print`, `cat /proc/self/status | grep Cap`. With `CAP_SYS_ADMIN`, prioritize `cgroup`/`overlayfs`/`mount` paths rather than a kernel UAF.
2. Kernel exploits can cause panics; test on a lab machine with a similar kernel before deciding whether to run against production.
3. After escalation, establish reusable credentials (`sudo` user, `authorized_keys`) before removing exploit files.
