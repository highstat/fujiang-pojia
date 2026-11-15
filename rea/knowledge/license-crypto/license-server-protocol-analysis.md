---
id: "license-server-protocol-analysis"
title: "Licence server protocol analysis"
domain: "license-crypto"
kind: "technique"
platforms: "windows, macos, linux, android, ios"
arch: "x86, x86-64, arm64"
difficulty: "intermediate"
tools: "mitmproxy, Frida, radare2, Python, openssl"
verified: false
updated: "2026-11-15"
summary: "Observe, document and replay a licence activation protocol: capture the request and response shapes, locate where certificate pinning is enforced, neutralise the pinning, and serve a rewritten success envelope to the client."
---

## Summary

A licence server protocol is an ordinary HTTP conversation with three parts that matter:

- **Request**: product and version identity, a machine identifier, a nonce, and often a
  request signature over the canonical form of those fields.
- **Response envelope**: a status code, an expiry, an entitlement list, and a signature over
  the payload.
- **Transport enforcement**: TLS certificate pinning, which decides whether the conversation
  can be observed at all.

The procedure is: capture the traffic, document the envelope, identify the pinning
mechanism, neutralise the pinning, then replay a rewritten response. The rewritten response
must still satisfy the signature check unless that check is also neutralised — see
[Asymmetric licence signature verification](asymmetric-license-signature-verification.md).

## Recognition

**Client-side markers.**

```bash
rabin2 -i target.exe | grep -iE 'WinHttp|InternetConnect|HttpSendRequest|curl|libcurl|SSL_connect'
rabin2 -z target.exe | grep -iE 'api/(licen[cs]e|activat|register)|X-License|user-agent'
r2 -q -c 'izz~licen' target.exe | head -40
```

**Typical request fields** (JSON body or form body):

```json
{
  "product": "Studio Pro",
  "version": "4.2.1",
  "machine_id": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
  "nonce": "3f9c0a1b",
  "timestamp": 1763222400,
  "signature": "base64(HMAC-SHA256(body_without_signature, app_secret))"
}
```

**Typical response envelope:**

```json
{
  "code": 0,
  "msg": "ok",
  "expire": 4102444800,
  "features": ["export", "plugins"],
  "machine_id": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
  "sig": "base64(RSA-PKCS1-SHA256(canonical_payload))"
}
```

`code` is the field the client branches on. Zero means success; non-zero values carry a
meaning (`401` expired, `403` machine mismatch, `404` unknown key, `500` server error).

**Custom headers** worth documenting: `X-License-Key`, `X-License-Machine`, `X-License-Version`,
`X-Activation-Id`, `X-Request-Signature`, `X-License-Nonce`. The `User-Agent` often carries
the product and version in a parseable form (`StudioPro/4.2.1 (Windows NT 10.0; x64)`).

**Protobuf bodies.** When the body is protobuf rather than JSON, the field numbers are stable
across builds and can be read without the schema:

```bash
protoc --decode_raw < captured_body.bin
```

The output lists field numbers and wire types. Field 1 `wire_type 2` is usually the product
string, field 2 the version, field 3 the machine id.

## Method

### Step 1 — Capture the traffic

Use a proxy as the default path; fall back to a hook when the client ignores proxy settings.

```bash
# mitmproxy: capture everything, keep the flows on disk
mkdir -p ~/rea-capture && cd ~/rea-capture
mitmdump -w flows.mitm --listen-port 8080

# point the client at the proxy
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080
```

On Windows, set the system proxy or launch the client with:

```powershell
$env:HTTPS_PROXY = "http://127.0.0.1:8080"
```

Burp and Charles work the same way; the mitmproxy workflow below is scriptable.

Read the capture back:

```bash
mitmdump -nr flows.mitm --set console_eventlog_verbosity=info
```

Filter to the interesting exchange:

```bash
mitmdump -nr flows.mitm -q \
  -s 'filter_by_host("licence.vendor.example")'
```

### Step 2 — Document the envelope

Export one exchange for inspection:

```bash
python3 - <<'PY'
import json, subprocess, sys
# mitmproxy flow files are pickled; use mitmdump's scripting API instead
script = '''
from mitmproxy import io, http

def response(flow: http.HTTPFlow):
    if flow.request.path.split("?")[0].startswith("/api/"):
        print("=== " + flow.request.method + " " + flow.request.pretty_url)
        for k, v in flow.request.headers.items():
            print("H> " + k + ": " + v)
        print("BODY> " + flow.request.get_text(strict=False)[:4000])
        for k, v in flow.response.headers.items():
            print("H< " + k + ": " + v)
        print("BODY< " + flow.response.get_text(strict=False)[:4000])
'''
open("/tmp/dump_flow.py", "w").write(script)
PY
mitmdump -nr flows.mitm -s /tmp/dump_flow.py
```

Note the exact ordering of the JSON keys. A signature is usually computed over a canonical
form (sorted keys, no whitespace) or over a subset of fields, and getting the canonical form
wrong is the usual reason a forged response is rejected.

### Step 3 — Locate the pinning

| Stack | Where pinning lives | Marker |
| --- | --- | --- |
| OpenSSL (native) | `SSL_CTX_set_verify` / `SSL_set_verify_callback` | `SSL_set_verify` in the import table, callback installed at setup |
| OpenSSL (native, strict) | `SSL_get_verify_result` compared against `X509_V_OK` | `SSL_get_verify_result` import |
| OkHttp / Retrofit (Android, JVM) | `okhttp3.CertificatePinner.check` | `CertificatePinner` class in the DEX |
| NSURLSession (Apple) | `URLSession:didReceiveChallenge:completionHandler:` delegate, or `SecTrustEvaluate` | delegate method in the binary |
| WinHTTP / .NET | `ServerCertificateCustomValidationCallback`, `ServicePointManager` | managed code |
| Chromium / Electron | `net::CertVerifier`, `--ignore-certificate-errors` | command line switch |

Find the native markers:

```bash
rabin2 -i target.exe | grep -iE 'SSL_set_verify|SSL_CTX_set_verify|SSL_get_verify_result'
r2 -q -c 'aaa; axt @ sym.imp.SSL_set_verify_callback' target.exe
```

### Step 4 — Neutralise the pinning

#### Native OpenSSL

```javascript
// bypass_pinning_openssl.js — Frida 17.x
//   frida -f target.exe -l bypass_pinning_openssl.js
function findModule(needle) {
  for (const m of Process.enumerateModules()) {
    if (m.name.indexOf(needle) !== -1 || m.path.indexOf(needle) !== -1) return m;
  }
  return null;
}

const sslMod = findModule("libssl");
if (sslMod) {
  const ssl = Process.getModuleByName(sslMod.path);
  try {
    // long SSL_get_verify_result(const SSL *ssl) -> X509_V_OK (0) means "trusted"
    Interceptor.attach(ssl.getExportByName("SSL_get_verify_result"), {
      onLeave(retval) {
        console.log("[hook] SSL_get_verify_result -> X509_V_OK");
        retval.replace(ptr(0));
      }
    });
    console.log("[+] SSL_get_verify_result patched");
  } catch (e) {
    console.log("[!] SSL_get_verify_result not exported: " + e.message);
  }
}
```

If the client verifies inside its own callback (not via `SSL_get_verify_result`), the
callback pointer has to be replaced. Capture it when it is installed:

```javascript
// capture_verify_cb.js — Frida 17.x
const sslMod = Process.enumerateModules().find(m => m.name.indexOf("libssl") !== -1);
const ssl = Process.getModuleByName(sslMod.path);
Interceptor.attach(ssl.getExportByName("SSL_set_verify_callback"), {
  onEnter(args) {
    console.log("[hook] SSL_set_verify_callback cb = " + args[1]);
    // replace the callback with a permissive one
    const permissive = new NativeCallback(function (preverify_ok, x509store_ctx) {
      console.log("[hook] permissive verify callback");
      return 1;      // preverify_ok
    }, "int", ["int", "pointer"]);
    args[1] = permissive;
  }
});
```

#### OkHttp / Retrofit

Since Frida 17.0.0 the Java bridge is a separate package; bundle with `frida-compile`:

```bash
npm install frida-java-bridge
frida-compile okhttp_pin.ts -o okhttp_pin.js
```

```typescript
// okhttp_pin.ts
Java.perform(() => {
  const CertificatePinner = Java.use("okhttp3.CertificatePinner");

  // OkHttp 4.x / 5.x: check(String, List) and check(String, List, String)
  try {
    CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation =
      function (hostname, pins) {
        console.log("[hook] CertificatePinner.check(" + hostname + ") bypassed");
      };
  } catch (e) {
    console.log("[!] overload (String, List) not present");
  }
  try {
    CertificatePinner.check.overload(
        "java.lang.String", "java.util.List", "java.lang.String").implementation =
      function (hostname, pins, message) {
        console.log("[hook] CertificatePinner.check(" + hostname + ", ...) bypassed");
      };
  } catch (e) {
    console.log("[!] overload (String, List, String) not present");
  }

  // Hardened variants also verify the hostname after the pin check
  try {
    const OkHostnameVerifier = Java.use("okhttp3.internal.tls.OkHostnameVerifier");
    OkHostnameVerifier.verify.overload("java.lang.String", "javax.net.ssl.X509Certificate[]",
                                       "java.io.PrintStream").implementation =
      function (hostname, certs, stream) {
        console.log("[hook] OkHostnameVerifier.verify bypassed for " + hostname);
        return true;
      };
  } catch (e) {}
});
```

#### NSURLSession / macOS

```javascript
// bypass_pinning_macos.js — Frida 17.x
const secMod = Process.enumerateModules().find(
  m => m.path.indexOf("Security.framework") !== -1);
if (secMod) {
  const sec = Process.getModuleByName(secMod.path);
  // Boolean SecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error)
  try {
    Interceptor.attach(sec.getExportByName("SecTrustEvaluateWithError"), {
      onEnter(args) { this.errorPtr = args[1]; },
      onLeave(retval) {
        console.log("[hook] SecTrustEvaluateWithError -> true");
        retval.replace(ptr(1));
      }
    });
  } catch (e) {}
  // OSStatus SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) -> 0 = success
  try {
    Interceptor.attach(sec.getExportByName("SecTrustEvaluate"), {
      onLeave(retval) {
        console.log("[hook] SecTrustEvaluate -> errSecSuccess");
        retval.replace(ptr(0));
      }
    });
  } catch (e) {}
  console.log("[+] Security.framework trust hooks installed");
}
```

On iOS the Security framework lives at
`/System/Library/Frameworks/Security.framework/Security`; the same code applies.

#### .NET

In dnSpyEx 6.6.0, set `HttpClientHandler.ServerCertificateCustomValidationCallback` to
`(msg, cert, chain, errors) => true`, or patch
`ServicePointManager.ServerCertificateValidationCallback`. For Mono, set
`MONO_TLS_PROVIDER` or remove the pin from `SslStream`.

### Step 5 — Rewrite the licence response

The mitmproxy addon below rewrites the licence activation response into a fixed success
envelope, preserving the request's machine identifier so the client's binding check still
matches.

```python
# license_rewrite.py — mitmproxy addon
#   mitmdump -s license_rewrite.py --listen-port 8080
import json
from mitmproxy import http

LICENSE_PATHS = (
    "/api/license/activate",
    "/api/license/validate",
    "/v1/activate",
    "/license/check",
)

FIXED_FEATURES = ["export", "plugins", "updates"]
# Signature placeholder: the client either ignores it, or the signature check is
# neutralised separately. See asymmetric-license-signature-verification.md.
FIXED_SIG = "c2lnbmF0dXJlLXBsYWNlaG9sZGVy"

class LicenseRewrite:
    def response(self, flow: http.HTTPFlow):
        path = flow.request.path.split("?")[0]
        if path not in LICENSE_PATHS:
            return
        if flow.response.status_code != 200:
            return

        machine = ""
        for header in ("X-License-Machine", "X-Machine-Id", "X-Device-Id"):
            if header in flow.request.headers:
                machine = flow.request.headers[header]
                break
        if not machine:
            try:
                req = json.loads(flow.request.get_text(strict=False))
                machine = req.get("machine_id", "")
            except Exception:
                machine = ""

        body = {
            "code": 0,
            "msg": "ok",
            "expire": 4102444800,          # 2100-01-01T00:00:00Z
            "features": FIXED_FEATURES,
            "machine_id": machine,
            "sig": FIXED_SIG,
        }
        raw = json.dumps(body).encode()
        flow.response.headers["content-type"] = "application/json"
        flow.response.headers.pop("content-encoding", None)
        flow.response.headers.pop("content-length", None)
        flow.response.content = raw
        flow.response.headers["content-length"] = str(len(raw))
        flow.response.status_code = 200
```

Variants of the same addon:

- **Rewrite only `expire`** to extend an existing licence, preserving the original signature
  — this fails when the signature covers the expiry, and succeeds when the expiry is
  validated separately.
- **Rewrite `code` only** to turn an error response into a success response.
- **Rewrite `features`** to grant entitlements that the account does not have.

### Step 6 — Replay a captured success response

Capture one genuine success exchange, then serve it to the client:

```bash
# capture with the addon disabled
mitmdump -w flows.mitm --listen-port 8080
# ... trigger a successful activation in the client ...

# replay it
mitmdump -nr flows.mitm -s /tmp/dump_flow.py
```

To serve a stored response to the client regardless of what the server returns, store the
recorded body and substitute it in the addon:

```python
# license_replay.py — mitmproxy addon
from mitmproxy import http

RECORDED = open("recorded_response.bin", "rb").read()

class Replay:
    def response(self, flow: http.HTTPFlow):
        if flow.request.path.split("?")[0] == "/api/license/activate":
            flow.response.status_code = 200
            flow.response.headers["content-type"] = "application/json"
            flow.response.headers.pop("content-encoding", None)
            flow.response.headers.pop("content-length", None)
            flow.response.content = RECORDED
            flow.response.headers["content-length"] = str(len(RECORDED))
```

### Step 7 — Deal with the signature over the response

If the client verifies `sig` over the response payload, rewriting the body invalidates the
signature. Three ways forward, in order of preference:

1. **Rewrite only unsigned fields.** If `expire` is not covered by the signature, extend it
   directly.
2. **Re-sign.** Extract the canonical payload, sign it with a key you control, and swap the
   embedded public key (see
   [Asymmetric licence signature verification](asymmetric-license-signature-verification.md)).
3. **Neutralise the verification.** Patch or hook the verify call so the result is always
   success.

To determine which fields the signature covers, flip one field at a time in the rewrite and
observe whether the client rejects the response. A rejection immediately after changing
`expire` means `expire` is covered.

## Variations

**HTTP/2 and gRPC.** The proxy must speak HTTP/2 to the client. mitmproxy does this by
default; gRPC bodies are protobuf and are best read with `protoc --decode_raw`.

**QUIC/HTTP3.** A client that negotiates QUIC bypasses the proxy entirely. Force HTTP/1.1
by disabling QUIC in the client, or capture with a kernel-level tracer.

**Certificate pinning in the TLS library of a game engine.** Unity/Unreal often embed their
own TLS stack in the binary; find it with `rabin2 -i` and look for `mbedtls_ssl_verify` or
`mbedtls_x509_crt_verify`.

**Encrypted payloads.** The licence may be encrypted inside the JSON envelope, in which case
the rewrite only needs to supply a blob for the client's own decryption — the key hunt
belongs in [Symmetric licence blob formats](symmetric-license-blob-formats.md).

**Native clients that ignore proxy variables.** WinHTTP, .NET `HttpClient` and some Go
clients honour `HTTP_PROXY` only when configured. Fall back to hooking the send function:

```javascript
// dump_http.js — Frida 17.x (Windows)
const winhttp = Process.getModuleByName("winhttp.dll");
Interceptor.attach(winhttp.getExportByName("WinHttpSendRequest"), {
  onEnter(args) {
    const len = args[3].toUInt32();
    if (len > 0 && len < 65536) {
      const b = new Uint8Array(args[2].readByteArray(len));
      let s = "";
      for (let i = 0; i < b.length; i++) s += ("0" + b[i].toString(16)).slice(-2);
      console.log("[WinHttpSendRequest] " + s);
    }
  }
});
```

**Server-side enforcement.** When the client also sends a heartbeat with the licence token
and the server revokes on mismatch, a local rewrite only survives while the server accepts
the token. A captured token is often reusable.

**Non-HTTP protocols.** Some products use a raw TCP protocol with a custom framing. The
same procedure applies with a socket hook instead of a proxy:

```javascript
// dump_tcp.js — Frida 17.x
const ws2 = Process.getModuleByName("ws2_32.dll");
Interceptor.attach(ws2.getExportByName("send"), {
  onEnter(args) {
    const len = args[2].toInt32();
    if (len > 0 && len < 65536) {
      const b = new Uint8Array(args[1].readByteArray(len));
      let s = "";
      for (let i = 0; i < b.length; i++) s += ("0" + b[i].toString(16)).slice(-2);
      console.log("[send " + len + "] " + s);
    }
  }
});
```

## Verification

1. **Traffic captured.** The capture contains the activation exchange with the request and
   the response body intact. Confirm with `mitmdump -nr flows.mitm -s /tmp/dump_flow.py`.
2. **Pinning neutralised.** With the hook active, the client completes the TLS handshake
   against the proxy certificate. Without the hook, it fails with a pinning error
   (`SSLPeerUnverifiedException`, `TrustKit` error 1, `HostnameVerifier` failure).
3. **Rewrite applied.** The client logs the new expiry or the new entitlement list. Compare
   the client's log output with the rewritten body.
4. **Positive test.** The client reports the licence as valid and unlocks the features named
   in `features`.
5. **Negative test — the rewrite is actually in the path.** Stop the proxy and confirm the
   client fails or falls back. If the client still succeeds, it used a cached licence and
   the server was never consulted.
6. **Negative test — a different machine is not silently accepted.** The rewritten body
   echoes the request's machine id. Change the machine id in the request and confirm the
   client rejects the response, which proves the binding check is still live and the licence
   is genuinely bound rather than merely accepted.
7. **Signature test.** If the response is signed, confirm that corrupting the `sig` field
   causes a rejection. If it does not, the signature is not covering that field and the
   rewrite is safe.

## Pitfalls

- **The proxy is bypassed.** The client uses its own TLS stack with pinned certificates and
  no proxy support, or it uses HTTP/3. Hooking the send function is more reliable than
  fighting the proxy configuration.
- **Certificate pinning survives the trust store.** Adding the proxy CA to the system store
  is not enough when the client pins the leaf public key or the SPKI hash. Hook the
  verification, not the trust evaluation.
- **Response compression.** A gzip-encoded response must have `content-encoding` removed
  when the body is replaced, otherwise the client fails to parse the rewritten body.
- **Content length.** Some clients verify `content-length` against the received body.
  Recompute it after every rewrite.
- **The signature covers the expiry.** Rewriting `expire` alone then yields a "signature
  invalid" error, not an "expired" error. Read the error text to tell the two apart.
- **Canonical form mismatch.** The server signs a canonicalised payload (sorted keys, no
  whitespace, concatenated fields). Re-signing the raw JSON bytes fails even when the
  content is identical.
- **Nonce and timestamp replay.** The server rejects a replayed nonce, or the client
  rejects a response whose timestamp is outside the accepted window. Re-sign rather than
  replay when the server is strict.
- **The response is consumed once.** Some clients delete the activation file after use, so
  the rewrite only works on the first run. Restore the file or patch the deletion.
- **Multiple licences.** The app may contact several endpoints (activation, entitlement
  refresh, phone-home). Rewriting only the activation response leaves the refresh response
  authoritative.
- **Legal.** Intercepting and rewriting a licence server for a product you do not own is
  not authorised testing. Work on targets you have permission to test.

## References

- mitmproxy documentation and addons — <https://docs.mitmproxy.org/stable/addons/>
- OkHttp `CertificatePinner` —
  <https://square.github.io/okhttp/okhttp3/okhttp3.OkHttpClient.Builder.html>
- Apple `URLSession:didReceiveChallenge:completionHandler:` and `SecTrustEvaluate` —
  <https://developer.apple.com/documentation/foundation/urlsession>
- OpenSSL `SSL_set_verify_callback` / `SSL_get_verify_result` —
  <https://docs.openssl.org/3.0/man3/SSL_get_verify_result/>
- protobuf wire format decoding — <https://protobuf.dev/programming-guides/encoding/>
- Frida 17.x `Interceptor` API — <https://frida.re/docs/javascript-api/>
- Sibling entries: [Asymmetric licence signature verification](asymmetric-license-signature-verification.md),
  [Offline activation and machine binding](offline-activation-and-machine-binding.md),
  [Symmetric licence blob formats](symmetric-license-blob-formats.md)
