# Mobile (Android, iOS, Flutter, React Native)

**Detector keys:** `android`, `ios`, `flutter`, `react-native`, `swift`, `dart`, `kotlin`/`java` (with Android manifest), `javascript`/`typescript` (React Native JS layer — also load [javascript-typescript.md](javascript-typescript.md))

Map findings to OWASP MASVS v2 control groups: MASVS-STORAGE, -CRYPTO, -AUTH,
-NETWORK, -PLATFORM, -CODE, -RESILIENCE, -PRIVACY. Treat the device and the app
binary as attacker-controlled: any secret shipped in the app is public, and any
client-side check must be re-enforced by the backend.

## Untrusted input sources

- Android: `Intent` extras/data received by exported `Activity`/`Service`/`BroadcastReceiver`, `ContentProvider` queries/URIs, deep links and App Links (`intent.data`), `PendingIntent`s from other apps, clipboard, `WebView` JS bridges, files on shared/external storage, push payloads, NFC/Bluetooth.
- iOS: URL schemes and Universal Links (`application(_:open:options:)`, `onOpenURL`, `NSUserActivity`), app extensions, pasteboard, `WKScriptMessageHandler` messages, push payloads, files from the Files app / AirDrop / document providers, keyboard extensions.
- Flutter: `MethodChannel`/`EventChannel` messages, `uni_links`/`app_links`/`go_router` deep links, `webview_flutter` JavaScript channels.
- React Native: `Linking` URLs, `react-native-webview` `onMessage`, native module arguments, CodePush/OTA bundles.
- All: every backend response (a compromised or MITM'd server), QR codes, local databases.

## Dangerous sinks

| Sink | Vulnerability class | CWE | Safe alternative |
|------|--------------------|-----|------------------|
| `SharedPreferences`, `NSUserDefaults`/`UserDefaults`, `AsyncStorage`, Flutter `shared_preferences`, plain SQLite/Realm files holding tokens/PII | Cleartext sensitive storage | CWE-312, CWE-922 | Android Keystore-wrapped keys + Tink (`EncryptedSharedPreferences` still common but its library is deprecated); iOS Keychain (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`); `flutter_secure_storage`; `react-native-keychain` |
| `getExternalStorageDirectory`, `MODE_WORLD_READABLE` | Insecure file exposure | CWE-276, CWE-552 | App-internal storage, scoped storage |
| `Log.d/v/i`, `print`, `NSLog`, `console.log` with secrets | Sensitive info in logs | CWE-532 | Strip logs in release (R8 rules, `#if DEBUG`) |
| `WebView.setJavaScriptEnabled(true)` + `addJavascriptInterface` loading untrusted URLs | Bridge abuse / RCE-equivalent | CWE-749 | No bridge for remote content; origin checks; `WebViewAssetLoader` |
| `setAllowFileAccess(true)`, `setAllowUniversalAccessFromFileURLs(true)` | Local file theft via WebView | CWE-200 | Disable; serve assets via `https://appassets.androidplatform.net` |
| `WebView.loadUrl(intent.data)`, `WKWebView.load(url_from_link)` | Open redirect / phishing / XSS in app context | CWE-601, CWE-79 | Host allowlist for navigation (`shouldOverrideUrlLoading`, `decidePolicyFor`) |
| `onReceivedSslError { handler.proceed() }`, `URLSession` delegate trusting any `serverTrust`, `badCertificateCallback = (...) => true` (Dart), `HostnameVerifier` returning true | Improper cert validation | CWE-295 | Default validation; pinning via Network Security Config / `NSPinnedDomains` |
| `android:exported="true"` components without permission; `<provider ... grantUriPermissions>` with broad paths | Improper export / access control | CWE-926, CWE-284 | `exported="false"`, `android:permission` with `signature` protection level |
| Implicit `Intent` with sensitive extras; mutable `PendingIntent` (`FLAG_MUTABLE`) with implicit base intent | Intent hijacking | CWE-927 | Explicit intents; `FLAG_IMMUTABLE` |
| Intent redirection: `startActivity(intent.getParcelableExtra("next"))` | Access to non-exported components | CWE-926 | Validate component/package; don't forward embedded intents |
| `ContentProvider.query` building SQL from `selection`/URI segments | SQL injection | CWE-89 | `selectionArgs`, `SQLiteQueryBuilder.setStrict(true)` |
| `openFile` / `FileProvider` paths from URI | Path traversal | CWE-22 | Canonicalize; restrict `file_paths.xml` |
| Hard-coded API keys, client secrets, private keys in code/`Info.plist`/`strings.xml`/`.env` bundled into JS | Hard-coded credentials | CWE-798 | Backend-issued, scoped, short-lived tokens; OAuth PKCE (no client secret) |
| `Cipher.getInstance("AES/ECB/...")`, static IV/key, `java.util.Random`, C `rand()` | Weak crypto | CWE-327, CWE-329, CWE-338 | AES-GCM via Keystore/CryptoKit; `SecureRandom`, `SecRandomCopyBytes` |
| `LAContext.evaluatePolicy` result used as a boolean gate only | Bypassable biometric auth | CWE-287 | Keychain item with `SecAccessControl` `.biometryCurrentSet`; Android `BiometricPrompt` with `CryptoObject` |
| `eval`/remote JS bundle loading, `DexClassLoader` from downloaded files | Code injection / unsigned code | CWE-494, CWE-829 | Signed updates only; no dynamic code from network |

## Framework pitfalls and insecure defaults

- **Android manifest:** `android:debuggable="true"`; `android:allowBackup="true"` (and missing `dataExtractionRules`/`fullBackupContent` exclusions) leaks app data via backup; `android:usesCleartextTraffic="true"` or `network_security_config` with `cleartextTrafficPermitted="true"` / `<certificates src="user"/>` in release (trusts user-installed CAs); components with `<intent-filter>` are exported by default on API < 31; `android:taskAffinity`/`launchMode` enabling task hijacking (StrandHogg); `android:protectionLevel="normal"` custom permissions guarding sensitive components.
- **Deep links:** App Links without `autoVerify="true"` and a valid `assetlinks.json` can be claimed by other apps; custom schemes (`myapp://`) are never exclusive on either platform — never deliver OAuth codes to custom schemes without PKCE; deep-link handlers that perform actions (payments, account changes) without confirmation.
- **iOS ATS:** `NSAllowsArbitraryLoads = YES`, `NSExceptionAllowsInsecureHTTPLoads`, `NSAllowsArbitraryLoadsInWebContent`; Keychain items with `kSecAttrAccessibleAlways` (deprecated) or without `ThisDeviceOnly`; `UIPasteboard.general` for secrets; screenshots of sensitive screens in the app switcher (blur in `sceneWillResignActive`); `UIWebView` (removed — flag if present); URL-scheme handlers not validating `sourceApplication`.
- **Pinning:** absent pinning is a missing control for high-risk apps (MASVS-NETWORK-2), not a vulnerability by itself; pinning implemented only in one HTTP client (e.g. OkHttp `CertificatePinner`) while WebViews or other clients bypass it; pin to SPKI hashes with backup pins.
- **Flutter:** Dart HTTP clients ignore Android Network Security Config and iOS ATS for some settings — pinning needs `SecurityContext` / `badCertificateCallback` logic; secrets in `--dart-define` are in the binary; `kDebugMode` checks; `webview_flutter` `JavaScriptMode.unrestricted` with remote content; obfuscation (`--obfuscate --split-debug-info`) is resilience, not security.
- **React Native:** JS bundle is trivially extractable (Hermes bytecode is decompilable); `react-native-config` values are public; `react-native-webview` `originWhitelist={['*']}`, `javaScriptEnabled` + `injectedJavaScript` with untrusted pages, `allowFileAccess`; OTA updates must be signed (Expo `updates.codeSigningCertificate`); Flipper/dev menu in release builds.
- **Root/jailbreak detection, anti-tamper, obfuscation** (MASVS-RESILIENCE) are defense in depth — report missing ones as `missing-control` only if the threat model requires them.
- Backend: any authorization performed only in the app (hidden buttons, client-side role checks, client-computed prices) is a backend finding.

## Authn/authz idioms to verify

- OAuth via system browser (`ASWebAuthenticationSession`, Android Custom Tabs / AppAuth) with PKCE; never embedded WebView login for third-party IdPs.
- Tokens: refresh tokens in Keychain/Keystore-backed storage, short access token lifetime, logout revokes server-side, biometric unlock bound to a key (not a boolean).
- Exported components protected with `signature` permissions; `checkCallingPermission`/`Binder.getCallingUid` checks in bound services.
- Server enforces every check the client does (rate limits on OTP, device binding, re-auth for sensitive actions).

## Useful grep patterns

```bash
rg -n 'android:(exported="true"|debuggable="true"|allowBackup="true"|usesCleartextTraffic="true")|cleartextTrafficPermitted="true"|<certificates src="user"' -g '*.xml'
rg -n 'addJavascriptInterface|setJavaScriptEnabled\(true\)|setAllowFileAccess(FromFileURLs)?\(true\)|setAllowUniversalAccessFromFileURLs\(true\)|handler\.proceed\(\)' -g '*.{java,kt}'
rg -n 'getSharedPreferences|MODE_WORLD_(READ|WRIT)ABLE|getExternalStorage|FLAG_MUTABLE|getParcelableExtra' -g '*.{java,kt}'
rg -n 'NSAllowsArbitraryLoads|NSExceptionAllowsInsecureHTTPLoads|kSecAttrAccessibleAlways|UIWebView|UserDefaults\.standard\.set|UIPasteboard\.general' -g '*.{swift,m,plist}'
rg -n 'evaluatePolicy\(|serverTrust|URLAuthenticationChallenge|\.useCredential' -g '*.{swift,m}'
rg -n 'badCertificateCallback|SharedPreferences\.getInstance|JavaScriptMode\.unrestricted|String\.fromEnvironment' -g '*.dart'
rg -n 'AsyncStorage\.setItem|originWhitelist=\{\[\s*["\x27]\*|allowFileAccess|injectedJavaScript|Linking\.(addEventListener|getInitialURL)' -g '*.{js,jsx,ts,tsx}'
rg -n '(api[_-]?key|client[_-]?secret|private[_-]?key)\s*[:=]' -i -g '*.{java,kt,swift,dart,js,ts,xml,plist,json}'
rg -n 'Log\.(d|v|i)\(|NSLog\(|print\(' -g '*.{java,kt,swift,dart}'
```

## Recommended tools

- MobSF (static + dynamic analysis of APK/AAB/IPA), apkleaks, jadx (decompile to review the shipped build), Android Lint security checks, Semgrep (`p/kotlin`, `p/java`, `p/swift`, `p/dart` where available), Frida + objection (dynamic testing in authorized environments only), OWASP MASTG test cases, OSV-Scanner (Gradle lockfiles, `Podfile.lock`, `Package.resolved`, `pubspec.lock`, JS lockfiles), Gitleaks.

## Secure code patterns

```kotlin
// Vulnerable: token in plain SharedPreferences
prefs.edit().putString("token", token).apply()
// Fixed (androidx.security:security-crypto is deprecated; prefer Keystore + Tink, shown conceptually)
val aead = keysetHandle.getPrimitive(Aead::class.java)   // keyset wrapped by an Android Keystore master key
prefs.edit().putString("token", Base64.encodeToString(aead.encrypt(token.toByteArray(), null), 0)).apply()

// Vulnerable: WebView accepts any TLS error
override fun onReceivedSslError(v: WebView, h: SslErrorHandler, e: SslError) = h.proceed()
// Fixed
override fun onReceivedSslError(v: WebView, h: SslErrorHandler, e: SslError) = h.cancel()
```

```xml
<!-- Vulnerable -->
<activity android:name=".TransferActivity" android:exported="true"/>
<!-- Fixed -->
<activity android:name=".TransferActivity" android:exported="false"/>
```

```swift
// Vulnerable: biometric boolean gate, token in UserDefaults
ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: r) { ok, _ in if ok { showAccount() } }
UserDefaults.standard.set(token, forKey: "token")
// Fixed: token in Keychain, released only after biometric check by the Secure Enclave
let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .biometryCurrentSet, nil)!
SecItemAdd([kSecClass: kSecClassGenericPassword, kSecAttrAccount: "token",
            kSecValueData: Data(token.utf8), kSecAttrAccessControl: ac] as CFDictionary, nil)
```

```dart
// Vulnerable
client.badCertificateCallback = (cert, host, port) => true;
// Fixed: remove the override; for pinning, use a SecurityContext with only the expected CA/cert
```
