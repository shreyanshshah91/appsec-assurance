# Mobile applications (Android and iOS)

Scope: security of native and cross-platform mobile clients (Kotlin/Java,
Swift/Objective-C, React Native, Flutter, Xamarin/.NET MAUI, Ionic/Capacitor,
Cordova): platform component exposure, transport security and pinning,
WebViews and JS bridges, local storage, deep links and URL schemes, build
configuration, and secrets in binaries. Server-side APIs used by the app are
covered by the API and authorization checklists — the mobile client is always
an untrusted client.

**Applies when:** `AndroidManifest.xml`, `build.gradle(.kts)`, `Info.plist`,
`*.xcodeproj`/`*.entitlements`, `pubspec.yaml`, React Native/Expo config
(`app.json`, `app.config.*`), Capacitor/Cordova config exist.

**Standards:** OWASP MASVS v2 control groups (MASVS-STORAGE, -CRYPTO, -AUTH,
-NETWORK, -PLATFORM, -CODE, -RESILIENCE, -PRIVACY) and MASTG test guidance;
OWASP A02:2021, A05:2021, A07:2021; CWE-926, CWE-925, CWE-319, CWE-295,
CWE-749, CWE-312, CWE-922, CWE-489, CWE-798, CWE-939.

## Android
- **MOB-01 — Exported components** (high)  *MASVS-PLATFORM*
  - Verify: `android:exported="true"` (or intent-filters on pre-API-31 targets) on activities, services, receivers, providers; `permission` attributes with `protectionLevel="signature"` for internal IPC; `ContentProvider` `grantUriPermissions`, path permissions, SQL in `query()` (injection), `openFile` path traversal; `PendingIntent` mutability (`FLAG_IMMUTABLE`); implicit intents carrying sensitive data.
  - Fail: exported component performing privileged actions or returning data without permission checks; intent redirection (forwarding received `Intent` extras to `startActivity`).
- **MOB-02 — Cleartext traffic** (high)  *MASVS-NETWORK*
  - Verify: `android:usesCleartextTraffic="true"`, `network_security_config.xml` with `cleartextTrafficPermitted="true"` (globally or for prod domains), `http://` endpoints in code/config.
  - Fail: API or auth traffic over HTTP.
- **MOB-03 — Trust anchors and certificate validation** (critical if disabled)  *MASVS-NETWORK*
  - Verify: `<certificates src="user"/>` in release configs, custom `TrustManager`/`HostnameVerifier` accepting all, OkHttp `hostnameVerifier { _, _ -> true }`, WebView `onReceivedSslError` calling `handler.proceed()`.
  - Fail: MITM-able TLS.
- **MOB-04 — WebView configuration and JS bridges** (high; critical with remote content)  *MASVS-PLATFORM*
  - Verify: `setJavaScriptEnabled(true)` + `addJavascriptInterface` exposed to remote/untrusted URLs; `setAllowFileAccess`, `setAllowFileAccessFromFileURLs`, `setAllowUniversalAccessFromFileURLs` true; `loadUrl` from intent extras/deep links; `shouldOverrideUrlLoading` allowlists; RN `WebView` `originWhitelist={['*']}` with `onMessage` handlers; Capacitor/Cordova plugin exposure and `allow-navigation` `*`.
  - Fail: attacker-controlled page in WebView calls native bridge methods (token theft, file access).
- **MOB-05 — Insecure local storage** (high)  *MASVS-STORAGE*
  - Verify: tokens/PII in `SharedPreferences`, SQLite, Realm, files on external storage (`getExternalStorage*`), RN `AsyncStorage`, Flutter `shared_preferences`; use Android Keystore-backed encryption (Jetpack Security / Tink), `expo-secure-store`, `flutter_secure_storage`. Check `android:allowBackup`/`dataExtractionRules`/`fullBackupContent` excluding sensitive files; logs (`Log.d`) with sensitive data.
  - Fail: plaintext refresh tokens or PII readable via backup or rooted device; external storage use.
- **MOB-06 — Debuggable and release config** (high)  *MASVS-RESILIENCE / MASVS-CODE*
  - Verify: `android:debuggable="true"` in release, `buildTypes.release` with `debuggable true`, `minifyEnabled false` (info), test/staging endpoints or debug menus in release builds, `StrictMode`/Stetho/Flipper in release.
  - Fail: debuggable release build.
- **MOB-07 — Deep links and App Links** (medium–high)  *MASVS-PLATFORM*
  - Verify: intent-filters with custom schemes or `http(s)` hosts; `autoVerify="true"` + `assetlinks.json` for App Links; deep link handlers validating parameters and not performing state changes or auth (e.g. magic-link tokens) without confirmation; OAuth redirects via custom schemes require PKCE (SESS-14).
  - Fail: deep link triggers sensitive action or loads arbitrary URL into a privileged WebView.
- **MOB-08 — Platform permissions and SDKs** (low–medium)  *MASVS-PRIVACY*
  - Verify: requested permissions minimal; third-party SDKs' data collection; clipboard use for sensitive data; screenshots of sensitive screens (`FLAG_SECURE`).

## iOS
- **MOB-09 — App Transport Security exceptions** (high)  *MASVS-NETWORK*
  - Verify: `NSAppTransportSecurity` → `NSAllowsArbitraryLoads`, `NSAllowsArbitraryLoadsInWebContent`, `NSExceptionDomains` with `NSExceptionAllowsInsecureHTTPLoads`, `NSExceptionMinimumTLSVersion` < TLSv1.2.
  - Fail: global arbitrary loads or insecure exceptions for prod/API domains.
- **MOB-10 — Keychain and data protection** (high)  *MASVS-STORAGE*
  - Verify: tokens in Keychain with appropriate accessibility (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly` / `AfterFirstUnlockThisDeviceOnly`), not `kSecAttrAccessibleAlways`; no tokens in `UserDefaults`, plist files, Core Data/SQLite unencrypted, `NSCachesDirectory`; file Data Protection class (`NSFileProtectionComplete`) for sensitive files; excluded from backups where appropriate.
  - Fail: credentials in `UserDefaults`.
- **MOB-11 — URL schemes and Universal Links** (medium–high)  *MASVS-PLATFORM*
  - Verify: `CFBundleURLTypes` custom schemes (hijackable by other apps) used for auth callbacks; prefer Universal Links with `apple-app-site-association`; `application(_:open:options:)` / `onOpenURL` validating source and parameters.
  - Fail: OAuth code delivered via custom scheme without PKCE; scheme handler performs actions without validation.
- **MOB-12 — WKWebView and bridges** (high)  *MASVS-PLATFORM*
  - Verify: `WKScriptMessageHandler` exposed to untrusted origins (check `message.frameInfo` / origin), `allowFileAccessFromFileURLs`, `UIWebView` (deprecated) usage, `loadFileURL` with broad read access.
- **MOB-13 — iOS build and entitlements** (medium)  *MASVS-CODE*
  - Verify: `get-task-allow` only in debug, unnecessary entitlements (App Groups shared with untrusted extensions, keychain access groups), pasteboard of sensitive data, background snapshot of sensitive screens.

## Cross-platform and common
- **MOB-14 — Certificate pinning (where risk warrants)** (medium)  *MASVS-NETWORK*
  - Verify: pinning via network security config `<pin-set>` with backup pins and expiry, OkHttp `CertificatePinner`, TrustKit/`NSPinnedDomains`, Flutter/RN pinning plugins; pin rotation plan. Pinning is defense in depth for high-value apps, not a baseline requirement.
  - Fail: pinning implemented with a single pin and no rotation plan (outage risk) or bypassable fallback.
- **MOB-15 — Secrets in the binary** (high)  *MASVS-CODE*
  - Verify: API secrets, private keys, signing keys, backend admin tokens in source, `BuildConfig`, `strings.xml`, `Info.plist`, `.env` bundled by RN/Expo/Flutter (`flutter_dotenv` assets), JS bundles (`index.android.bundle`).
  - Fail: anything a client must not have; obfuscation is not protection.
- **MOB-16 — Client-side trust** (high)  *MASVS-AUTH*
  - Verify: authorization, pricing, feature entitlements, jailbreak/root checks, and biometric "unlock" not used as sole server-side trust signal; biometric auth bound to Keystore/Keychain keys (`setUserAuthenticationRequired`, `kSecAccessControlBiometryCurrentSet`) rather than a boolean callback.
  - Fail: `if (biometricSuccess) callApiWithStoredToken()` with token unprotected.
- **MOB-17 — Code-push and dynamic code** (medium)  *MASVS-CODE*
  - Verify: OTA updates (Expo Updates, CodePush) signed (code signing enabled), downloaded over TLS; no `DexClassLoader`/remote JS evaluation from untrusted sources.
- **MOB-18 — Resilience controls (risk-based)** (info–low)  *MASVS-RESILIENCE*
  - Verify: for high-value apps (banking, DRM), obfuscation (R8/ProGuard), integrity checks (Play Integrity, App Attest) verified server-side; absence is info unless the threat model requires it.

## Common false positives
- Exported launcher activity (`MAIN`/`LAUNCHER`) — must be exported.
- `NSAllowsArbitraryLoadsInWebContent` for apps whose WebView only browses public third-party content without bridges.
- Cleartext allowed only for `10.0.2.2`/`localhost` in a debug-only network security config.
- Google API keys restricted by package/signature (verify restrictions with the user).

## Safe validation ideas
- Static manifest/plist/config review is sufficient for most items; decompile only the user's own build artifacts (apktool/jadx) in an isolated directory.
- On an emulator/simulator with a debug build of the user's own app: `adb shell am start -d "<scheme>://appsec-canary-<rand>"` to observe deep link handling; inspect app sandbox storage for test-account tokens.
- Never test against store-published apps of third parties; never use real user accounts.
