---
name: kb-linux-priv
description: CVE/PoC knowledge base · Linux local privilege escalation: PwnKit(2021-4034), Dirty Pipe(2022-0847), Baron Samedit(2021-3156), fs_context(2022-0185), GameOver(lay)(2023-2640), nf_tables(2024-1086/2023-32233), overlayfs(2023-0386/2021-3493), sudoedit(2023-22809). Each entry includes a PoC; compiled from public sources, verified=false.
verified: false
sources: Compiled from public sources (CVE advisories / public analyses / business-logic issues; see each entry's references)
---

# Linux local privilege escalation (11 entries)
> Entries are compiled from public sources (see References below). `Exploitation steps` are unverified hypotheses; validate against the target version before reporting and set `verified` to true only after verification.

Standard steps after obtaining a low-privilege shell (`www-data`, `nobody`, or root inside a container):

```bash
uname -a; cat /etc/os-release; id; sudo -l 2>/dev/null; find / -perm -4000 -type f 2>/dev/null
dpkg -l | grep -E 'sudo|policykit|glibc' 2>/dev/null || rpm -qa | grep -E 'sudo|polkit|glibc'
```

**Check the kernel and glibc/sudo/polkit versions first**, then match entries. Do not immediately compile an unfamiliar kernel exploit—a crash is more likely than successful escalation.

## Entries

| File | Vulnerability | Severity | Entry point |
|---|---|---|---|
| `cve-2021-3156-baron-samedit.md` | Baron Samedit (sudo heap-overflow privilege escalation) | high | - |
| `cve-2021-3493-ubuntu-overlayfs.md` | Ubuntu overlayfs local privilege escalation (2021) | high | userns + copying setuid attributes through overlayfs |
| `cve-2021-4034-pwnkit.md` | PwnKit (polkit pkexec local privilege escalation) | high | - |
| `cve-2022-0185-fs-context-overflow.md` | fs_context heap-overflow privilege escalation (legacy_parse_param) | high | unshare -Ur + oversized legacy mount parameters |
| `cve-2022-0847-dirtypipe.md` | Dirty Pipe (page-cache overwrite privilege escalation) | high | - |
| `cve-2023-0386-overlayfs.md` | overlayfs copy-up permission-bypass privilege escalation | high | - |
| `cve-2023-22809-sudo-edit.md` | sudoedit environment-variable injection privilege escalation (EDITOR containing --) | high | EDITOR='vim -- /etc/sudoers' |
| `cve-2023-2640-gameoverlay.md` | Ubuntu overlayfs privilege escalation (GameOver(lay)) | high | unshare + overlayfs xattr copy bypass |
| `cve-2023-32233-nftables.md` | nf_tables use-after-free privilege escalation (2023) | high | unshare + batched nft rules triggering UAF |
| `cve-2024-0582-io-uring-uaf.md` | Linux io_uring local privilege escalation (CVE-2024-0582) | high | page release after fixed-file registration → remap and overwrite |
| `cve-2024-1086-nftables.md` | nf_tables use-after-free privilege escalation | high | - |

## How to use this page

1. In containers, check privileges first: `capsh --print`, `cat /proc/self/status | grep Cap`. With `CAP_SYS_ADMIN`, prioritize `cgroup`/`overlayfs`/`mount` paths rather than a kernel UAF.
2. Kernel exploits can cause panics; test on a lab machine with a similar kernel before deciding whether to run against production.
3. After escalation, establish reusable credentials (`sudo` user, `authorized_keys`) before removing exploit files.
