---
id: "play-billing-entitlement-faking"
title: "Play Billing entitlement faking"
domain: "android"
kind: "technique"
platforms: "android"
arch: "x86-64, arm, arm64"
difficulty: "advanced"
tools: "Frida, frida-java-bridge, frida-compile, jadx, adb, sqlite3, Play Integrity Fix"
verified: false
updated: "2026-11-15"
summary: "Trace how an Android app turns a Google Play purchase into a local entitlement, then fake that entitlement at the billing client, in the local cache, or in the DEX, and understand why a patched client cannot satisfy a server-side Play Integrity check."
---

## Summary

A Play Billing entitlement is a value the app derives, not a value the store gives it. The
purchase arrives through `BillingClient.queryPurchasesAsync`, becomes a `Purchase` object with
a `purchaseState` and an `isAcknowledged` flag, and is then usually copied into a local
cache — a `SharedPreferences` boolean, a Room row, a JSON config — which is what the rest of
the app reads.

Faking it therefore has three levels: fake the purchase result at the Java layer, fake the
cached entitlement, or fake the flag in the DEX. The third is the most durable. The fourth
possibility, faking the server's answer, does not exist: Play Integrity tokens are signed by
Google and validated server-side.

## Recognition

### Billing artefacts

- The dependency in the build file:
  `implementation 'com.android.billingclient:billing:7.1.1'` (versions 6.x and 7.x use
  `enablePendingPurchases()`; 8.x removed that call).
- A `BillingClient` instance built in code:

  ```java
  billingClient = BillingClient.newBuilder(context)
      .setListener(purchasesUpdatedListener)
      .enablePendingPurchases()
      .build();
  ```

- The listener implementing `PurchasesUpdatedListener.onPurchasesUpdated(BillingResult,
  List<Purchase>)`.
- The query:

  ```java
  billingClient.queryPurchasesAsync(QueryPurchasesParams.newBuilder()
      .setProductType(BillingClient.ProductType.INAPP)
      .build())
      .addListener(new BillingResponseListener() {
          public void onBillingResponse(BillingResult result, List<Purchase> list) { ... }
      }, executor);
  ```

- `Purchase.getPurchaseState()` returns `Purchases.PurchaseState.PURCHASED` (`1`),
  `PENDING` (`2`) or `UNSPECIFIED` (`0`); `Purchase.isAcknowledged()` returns whether the
  purchase was acknowledged through `acknowledgePurchase`.
- `Purchase.getPurchaseToken()`, `Purchase.getProducts()` and
  `Purchase.getOriginalPurchaseToken()` are the identifiers the app sends to its own backend.

### Cached entitlement artefacts

Look on the device (a debuggable build allows `adb shell run-as <package>`):

```bash
adb shell run-as com.vendor.app ls -R /data/data/com.vendor.app | head -60
adb shell run-as com.vendor.app ls shared_prefs files databases 2>/dev/null
adb shell run-as com.vendor.app cat shared_prefs/entitlement.xml
adb shell run-as com.vendor.app sqlite3 databases/app.db ".tables"
adb shell run-as com.vendor.app cat files/entitlement.json
```

Concrete shapes to expect:

| Location | Shape |
| --- | --- |
| `shared_prefs/*.xml` | `<boolean name="premium" value="true" />`, `<string name="entitlement">PRO</string>` |
| `databases/*.db` | Room entity `SubscriptionEntity(purchaseToken TEXT PRIMARY KEY, state INTEGER, isPro BOOLEAN)` |
| `files/datastore/*.preferences_pb` | DataStore protobuf with a `pro` key |
| `files/*.json`, `assets/*.json` | `{"plan":"free","entitlement":{"pro":false,"expiresAt":0}}` |
| DEX | `public static final boolean Pro = false;` in a `Config` or `FeatureFlags` class |

### Play Integrity artefacts

- The dependency `com.google.android.play:integrity:1.4.0`.
- `IntegrityManager.requestIntegrityToken(StandardIntegrityTokenRequest)` with
  `setRequestHash(sha256(serverNonce + payload))`.
- The token is a JWE; the decoded payload contains `appIntegrity`, `deviceIntegrity`,
  `accountDetails` and `environmentDetails`.
- The server-side check is a call to the Play Integrity API with the token and the
  expected package name and SHA-256 of the signing certificate.

## Method

### 1. Find where the entitlement is decided

```bash
cd /path/to/work
jadx -d jadx_out app_original.apk
grep -rn "queryPurchasesAsync\|isAcknowledged\|getPurchaseState\|BillingClient" jadx_out/sources | head -40
grep -rn "premium\|isPro\|entitlement\|Pro\b" jadx_out/sources | head -40
```

The class that reads the cached flag is the decision point. It usually looks like:

```java
public static boolean isPremium(Context ctx) {
    return ctx.getSharedPreferences("entitlement", MODE_PRIVATE).getBoolean("premium", false);
}
```

or

```java
public static boolean isPro() {
    return FeatureFlags.Pro;      // a static final boolean in the DEX
}
```

### 2. Observe the billing flow at runtime

`com.android.billing` is a system service and is not exposed as a Java class to hook. Hook
the Play Billing library classes instead, through the Java bridge.

Frida 17 does not bundle the bridges. Install `frida-java-bridge` and bundle it with
`frida-compile`:

```bash
cd /path/to/work
npm install frida-java-bridge
npx frida-compile agent.ts -o agent.js
```

The TypeScript source of the observer:

```ts
// agent.ts — npx frida-compile agent.ts -o agent.js
import Java from 'frida-java-bridge';

Java.perform(() => {
  const Purchase = Java.use('com.android.billingclient.api.Purchase');

  const getPurchaseState = Purchase.getPurchaseState.overload();
  getPurchaseState.implementation = function () {
    const state = getPurchaseState.call(this);
    console.log('[+] Purchase.getPurchaseState() = ' + state);
    return state;
  };

  const isAcknowledged = Purchase.isAcknowledged.overload();
  isAcknowledged.implementation = function () {
    console.log('[+] Purchase.isAcknowledged() = ' + isAcknowledged.call(this));
    return isAcknowledged.call(this);
  };

  const getPurchaseToken = Purchase.getPurchaseToken.overload();
  getPurchaseToken.implementation = function () {
    console.log('[+] Purchase.getPurchaseToken() = ' + getPurchaseToken.call(this));
    return getPurchaseToken.call(this);
  };

  const BillingClient = Java.use('com.android.billingclient.api.BillingClient');
  const query = BillingClient.queryPurchasesAsync.overload(
    'com.android.billingclient.api.QueryPurchasesParams');
  query.implementation = function (params) {
    console.log('[+] BillingClient.queryPurchasesAsync(' + params + ')');
    const ret = query.call(this, params);
    ret.addListener({
      onBillingResponse: function (result, purchases) {
        console.log('[+] purchases: ' + purchases.size());
        purchases.forEach(function (p) {
          console.log('    state=' + p.getPurchaseState() +
                      ' acknowledged=' + p.isAcknowledged() +
                      ' token=' + p.getPurchaseToken());
        });
      }
    }, Java.use('java.util.concurrent.Executor').$new());
    return ret;
  };
});
```

Run it:

```bash
frida -U -f com.vendor.app -l agent.js
```

The listener class passed to `addListener` must implement the interface; the snippet above
uses a plain object literal and works only because the billing library calls
`onBillingResponse` directly. If it throws `ClassCastException`, use `Java.registerClass` to
build a real implementation of `com.android.billingclient.api.BillingResponseListener`.

### 3. Fake the purchase result at the Java layer

Force the two accessors that carry the decision:

```ts
import Java from 'frida-java-bridge';

Java.perform(() => {
  const Purchase = Java.use('com.android.billingclient.api.Purchase');

  // PurchaseState.PURCHASED == 1
  Purchase.getPurchaseState.overload().implementation = function () {
    console.log('[+] getPurchaseState -> PURCHASED');
    return 1;
  };

  Purchase.isAcknowledged.overload().implementation = function () {
    console.log('[+] isAcknowledged -> true');
    return true;
  };

  // keep the token non-empty: some apps validate it before using it
  Purchase.getPurchaseToken.overload().implementation = function () {
    return 'fake-token-' + Date.now();
  };
});
```

Two caveats:

- `getPurchaseState` and `isAcknowledged` are called from inside the library as well as from
  the app. Overriding them changes the library's own behaviour, including acknowledgement
  bookkeeping. That is acceptable for a session, not for a durable state.
- The library validates the purchase signature in some code paths
  (`Purchase.getPurchaseState` does not, but the app's own verification of `Purchase` JSON
  does). If the app validates a signed JSON blob, hook the app's verification method rather
  than the library's accessors.

A variant that works even when the app receives an empty purchase list is to hook the
callback the app passes to the listener:

```ts
Java.perform(() => {
  const listener = Java.use('com.vendor.app.billing.BillingManager$1');
  listener.onPurchasesUpdated.implementation = function (result, purchases) {
    console.log('[+] onPurchasesUpdated with ' + purchases.size() + ' purchases');
    this.onPurchasesUpdated(result, purchases);
  };
});
```

### 4. Fake the cached entitlement

The cached value is the durable target. Three levels of effort.

**a. Write the flag directly** (debuggable build only):

```bash
adb shell run-as com.vendor.app cat shared_prefs/entitlement.xml
# <map><boolean name="premium" value="false" /></map>
```

Editing that file while the process is running is overwritten on the next write. Use the
hook instead:

```ts
import Java from 'frida-java-bridge';

Java.perform(() => {
  const Editor = Java.use('android.content.SharedPreferences$Editor');
  Editor.putBoolean.implementation = function (key, value) {
    console.log('[+] putBoolean ' + key + ' = ' + value);
    return this.putBoolean(key, true);
  };

  const Impl = Java.use('android.app.SharedPreferencesImpl');
  Impl.getBoolean.overload('java.lang.String', 'boolean').implementation = function (key, def) {
    const v = this.getBoolean(key, def);
    console.log('[+] getBoolean ' + key + ' = ' + v);
    return true;
  };
});
```

**b. Patch the Room or SQLite row.** Read the schema, then insert a plausible row:

```bash
adb shell run-as com.vendor.app sqlite3 databases/app.db \
  "select * from subscriptions;"
adb shell run-as com.vendor.app sqlite3 databases/app.db \
  "insert into subscriptions(purchaseToken,productId,state,isPro) values('fake','pro_monthly',1,1);"
```

**c. Patch the JSON config** in `assets/` or `files/` and rebuild:

```json
{"plan":"pro","entitlement":{"pro":true,"expiresAt":1893456000}}
```

### 5. Patch the flag in the DEX

The most durable option, because it survives a cache wipe and does not depend on runtime
instrumentation. The flag is usually a `static final boolean` in a config class:

```java
public final class FeatureFlags {
    public static final boolean Pro = false;
    public static boolean isPro(Context ctx) {
        return Pro || ctx.getSharedPreferences("entitlement", 0).getBoolean("premium", false);
    }
}
```

In smali the constant is folded into a `sget` at each use site:

```smali
    sget-boolean v0, Lcom/vendor/app/FeatureFlags;->Pro:Z
    if-eqz v0, :cond_0
```

The reliable edit is the initialiser in `<clinit>`, which changes every use at once:

```smali
.method static constructor <clinit>()V
    .locals 1

    const/4 v0, 0x1
    sput-boolean v0, Lcom/vendor/app/FeatureFlags;->Pro:Z

    return-void
.end method
```

The byte values: `const/4 v0, 0x1` is `12 10`, `sput-boolean v0, field` is `67 00` (format
21c with field index `0x0000`), `return-void` is `0e 00`.

When the field is `static final` and R8 has inlined it, the constant appears at every call
site as `const/4 v0, 0x0` (`12 00`). Replace each occurrence with `12 10`, or patch the
`isPro` method to return `1` outright as described in
[`dex-smali-licence-patching.md`](dex-smali-licence-patching.md).

Rebuild, align and sign:

```bash
cd /path/to/work
apktool b app_decoded -o build/app_built.apk
zipalign -P 16 -f 4 build/app_built.apk build/app_aligned.apk
apksigner sign --ks debug.keystore --ks-key-alias androiddebugkey \
  --ks-pass pass:android --key-pass pass:android \
  --out build/app_signed.apk build/app_aligned.apk
apksigner verify --verbose --print-certs build/app_signed.apk
adb install -r build/app_signed.apk
```

### 6. Play Integrity

`PlayIntegrity` is a separate signal from Play Billing. The client asks Google for a token
and the server validates it with the Play Integrity API.

Client side:

```java
StandardIntegrityTokenRequest request = StandardIntegrityTokenRequest.builder()
        .setRequestHash(sha256(nonce + payload))
        .build();
integrityManager.requestIntegrityToken(request)
        .addListener(result -> {
            if (result.isSuccess()) {
                sendToServer(result.get().getToken());
            }
        }, executor);
```

The verdict has three parts:

| Part | Field | Depends on |
| --- | --- | --- |
| app integrity | `appIntegrity.appRecognitionVerdict` (`PLAY_RECOGNIZED`), `appIntegrity.packageName`, `appIntegrity.versionCode`, `appIntegrity.certDigest` | The package name, version code and SHA-256 of the signing certificate must match the Play record |
| device integrity | `deviceIntegrity.deviceRecognitionVerdict` (`MEETS_DEVICE_INTEGRITY`, `MEETS_BASIC_INTEGRITY`, `MEETS_STRONG_INTEGRITY`) | Bootloader state, verified boot state, hardware attestation, ROM certified by the manufacturer |
| environment | `environmentDetails.playProtectVerdict` | Play Protect state |

The app-integrity part cannot be satisfied by a re-signed APK: the certificate digest is part
of the signed token, and Google issues it only for the package and certificate registered in
Play. A patched APK therefore either gets no token, or gets a token whose `appIntegrity`
verdict is not `PLAY_RECOGNIZED`.

The device-integrity part can be spoofed. The signals come from the hardware-backed
attestation chain (Keymaster/KeyMint), so they cannot be changed by patching the app; they
are changed by spoofing the TEE. That is what the Play Integrity Fix module does:

```text
Magisk / KernelSU / APatch module "PlayIntegrityFix"
  -> needs root and Zygisk (Magisk built-in, ZygiskNext, NeoZygisk, ReZygisk)
  -> patches the TEE key attestation response (injecting the device's real attestation into
     the spoofed hardware response) so the verdict reaches MEETS_DEVICE_INTEGRITY
```

Combined with a patched APK, the result is: device integrity passes, app integrity does not.
The app signature is not spoofable this way, and the Play Integrity API still validates the
package name and version code against the Play record.

## Variations

### Legacy licensing (LVL)

Older apps use `com.google.android.vending.licensing.ILicensingService` through the
`LicenseChecker` library. The service is a bound Android service (`com.android.vending.
licensing.ILicensingService`); the response string is `LICENSED` or `NOT_LICENSED`. The
decision can be observed by hooking the app's own `LicenseChecker.verify()` or by hooking
`Response.getResponseCode()`.

### Subscription state machine

An entitlement for a subscription depends on `purchases` being non-empty, every purchase
being `PURCHASED`, and the app's own expiry check on `expiryTime` from
`queryPurchasesAsync`. Faking only `getPurchaseState` leaves the expiry comparison in place.
The expiry is compared against the device clock, so a device with a wrong date produces a
not-entitled result.

### Purchases that are not in the query result

`queryPurchasesAsync` only returns purchases that the *account* on the device owns. On a
fresh device with a different Google account, the list is empty and no client-side hook on
`Purchase` fires. The fakes have to be applied to the empty-list branch instead, which is
the app's `if (purchases.isEmpty())` path — usually the same cached-flag read.

### Server-side entitlement APIs

Apps that use Google Play Developer API `purchases.subscriptionsv2.get` from their own
backend validate the token server-side. Faking the client changes nothing: the server calls
Google, gets the real state, and rejects. The only client-side lever is the request the app
makes (for example the account token it sends), which is a credential problem rather than a
patching problem.

### Hooking the store's own service

The Play Store app exposes `com.android.vending.licensing.ILicensingService`. Hooking the
binder in the Store process is possible but fragile: the Store process is a separate app
with its own integrity checks, and the hook has to be installed there, not in the target
app.

## Verification

1. Observation first. Run the observer script and confirm the purchase list and the
   `getPurchaseState` / `isAcknowledged` values are the ones the app sees. Without this the
   later hooks cannot be attributed.
2. Client-level check. `adb shell dumpsys package com.vendor.app | grep -A5 "signatures"` shows
   the signing certificate of the installed build. A re-signed package has a different
   digest, which is what Play Integrity compares against.
3. Cached-state check. After the app grants the entitlement, confirm the cache changed:
   `adb shell run-as com.vendor.app cat shared_prefs/entitlement.xml` shows
   `<boolean name="premium" value="true" />`.
4. Server-side check. Send the app's entitlement request to its own backend and read the
   response. A patched client with an unpatched server returns `403` or
   `{"entitled":false}`.
5. Negative test. Clear the app state and repeat: `adb shell pm clear com.vendor.app`. The
   cached flag is gone; a DEX-level patch still grants the entitlement, a cache-level patch
   does not. That difference is the proof of which layer was actually changed.
6. Negative test for the server. Reinstall the original APK, sign in, and confirm the
   entitlement is denied again.

## Pitfalls

- **The entitlement is server-side.** The client flag only controls the UI. Any app that
  gates premium API calls on a server response stays locked no matter what the client says.
- **Re-signing breaks the app-integrity verdict.** `appIntegrity.certDigest` is the SHA-256
  of the signing certificate Play knows. A debug-signed APK never reaches
  `PLAY_RECOGNIZED`.
- **Play Integrity Fix is not enough on its own.** It spoofs device integrity, not app
  integrity, and it needs root plus Zygisk.
- **Overriding the library accessors breaks the library's own logic.** The billing library
  uses `isAcknowledged` to decide whether to acknowledge; forcing `true` stops the app from
  ever acknowledging and can leave a purchase in `PENDING`.
- **The app validates the purchase signature.** `Purchase` objects can carry a signed JSON
  blob; the app verifies it before trusting the state. Hook the app's verification, not the
  library's accessor.
- **The cache is rewritten on every start.** A hook on `getBoolean` survives a restart only
  if the hook is re-attached; a file edit does not survive the next write.
- **`frida-java-bridge` is missing.** Frida 17 dropped the bundled bridges: a script using
  `Java.perform` fails with `TypeError: undefined is not an object`. Install the package and
  bundle with `frida-compile`.
- **Different billing library versions have different class shapes.** The method names
  (`queryPurchasesAsync`, `getPurchaseState`) changed between 5.x, 6.x, 7.x and 8.x. The
  overload lists must match the version in the APK or `overload()` throws.
- **A wrong device clock breaks subscription logic.** Expiry comparisons use the device time;
  set the clock back or the entitlement expires immediately.
- **Multiple Google accounts.** The query result is per-account. Signing out and back in
  changes the list, and the app may re-evaluate the entitlement at that point.

## References

- Google Play Billing Library reference:
  <https://developer.android.com/google/play/billing/reference>
- `Purchase` class: <https://developer.android.com/reference/com/android/billingclient/api/Purchase>
- `Purchases.PurchaseState`:
  <https://developer.android.com/reference/com/android/billingclient/api/Purchases.PurchaseState>
- Play Integrity overview and verdicts:
  <https://developer.android.com/google/play/integrity/overview>
- Play Integrity API (server side):
  <https://developer.android.com/google/play/integrity/verify>
- Frida bridges: <https://frida.re/docs/bridges/>
- Frida 17.x JavaScript API: <https://frida.re/docs/javascript-api/>
- PlayIntegrityFix: <https://github.com/KOWX712/PlayIntegrityFix>
- Sibling entries: [`apk-decode-rebuild-sign.md`](apk-decode-rebuild-sign.md),
  [`dex-smali-licence-patching.md`](dex-smali-licence-patching.md),
  [`android-native-library-licence.md`](android-native-library-licence.md)
