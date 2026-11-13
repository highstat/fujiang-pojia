---
id: "lottery-prng-predictable"
title: "Predictable draw results (weak PRNG / client-side algorithm / fixed seed)"
kind: "implementation"
cve: null
related-cves: null
cve-note: "None (implementation flaw)"
severity: "critical"
cvss: 9.1
severity-basis: "cvss"
severity-note: null
product: "In-house lottery / Kuai San / 28-style games"
versions: "Any"
ports: "80, 443"
keywords: "lottery, prng, draws, predictable, seeds, Kuai San, Shi Shi Cai"
entry: "Historical draw statistics + reproduction of the frontend JS algorithm"
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

- Endpoints: `/api/lottery/history?issue=`, `/api/lottery/next`, `/api/bet/result`;
- The frontend bundle contains draw calculations (`Math.random`, `Math.floor(...*10)`, custom shuffling);
- The server's next-draw endpoint returns `seed`/`hash`, or `openTime` permits inference.

## Prerequisites

- An authorized environment; historical draws are usually publicly retrievable (no login), **at least 100 draws**.

## PoC

```bash
# 1) Fetch history and analyze distributions and correlations between adjacent draws
curl -s 'https://target/api/lottery/history?pageSize=200' > hist.json
python3 - <<'PY'
import json
from math import comb
d=json.load(open("hist.json"))["data"]
nums=[x["result"] for x in d]; n=len(nums)
K=2      # Set the outcome space by game: big/small K=2; Kuai San sum K=14; single-number bets K=10. Do not use sample distinct values as K (this underestimates K and raises the baseline)
M=int(input("Pre-registered correct predictions M = ")); N=int(input("Total registered predictions N = "))
p0=1/K
p=sum(comb(N,i)*p0**i*(1-p0)**(N-i) for i in range(M, N+1))
print(f"n={n} K={K} M/N={M}/{N} baseline={p0:.3f} p={p:.6f} -> " + ("significant" if p<0.01 else "not significant"))
PY

# 2) Locate the frontend algorithm
npx source-map-explorer app.js.map 2>/dev/null | head
grep -o 'Math\.random[^;]*' app.js | head
```

## Exploitation Steps

1. Obtain ≥100 historical draws for basic statistics: outcome space `k`, identical adjacent results, and correlation with `openTime`.
2. **Random baseline**: with uniform independent outcomes, per-draw success probability ≈ `1/k`; compare the prediction hit rate with `1/k`; require `n≥100` and binomial-test `p<0.01` for significance, not visual impressions.
3. Find the algorithm in frontend JS/sourcemaps; if it uses `Date.now()`, a fixed `seed`, or "next seed = md5(previous draw + time)", capturing two draws suffices for derivation.
4. **Timing requirement**: **register predictions before the draw** (screenshot/text + timestamp + draw number), then compare results; post-hoc fitting is not evidence.
5. Two confirmation levels:
   - ① The frontend algorithm matches every draw result exactly (a definitive `N/N` finding);
   - ② Pre-registered predictions achieve `M/N` significantly above `1/k` (`p<0.01`).
6. Verify only with small amounts in an authorized environment; report "predictability ⇒ unbounded financial impact", without actual betting arbitrage.

## Remediation and Mitigation

### Remediation and Mitigation (Hardening)

- Server-side CSPRNG (`crypto.randomInt`) + a trusted third-party draw source;
- commit-reveal: publish `hash(seed)` before the draw and `seed` afterward, enabling verification without predictability;
- Never send the algorithm or seed to the frontend; audit draw numbers and results separately.

## References

- OWASP Top 10 A02 Cryptographic Failures; provably fair implementation patterns.
