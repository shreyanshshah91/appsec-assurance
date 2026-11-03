# Frontend and client-side security

Scope: security of code that runs in the user's browser and of what the build
ships to it: token and data storage, third-party scripts and Subresource
Integrity, cross-window messaging, client-side authorization illusions,
source maps and secrets in bundles, open redirects, clickjacking, and
client-side dependency and framework pitfalls. XSS specifics are in
xss-and-output-encoding.md; headers/CSP in csrf-cors-headers-csp.md.

**Applies when:** an SPA/SSR frontend (React, Next.js, Vue/Nuxt, Angular,
Svelte/SvelteKit, Remix, Astro, Solid), bundler config (Vite, webpack, esbuild,
Rollup, Turbopack), browser extensions, or Electron/Tauri apps are present.

**Standards:** OWASP A01:2021, A03:2021, A05:2021, A08:2021; ASVS V3 Web
Frontend Security; CWE-922, CWE-345, CWE-346, CWE-829, CWE-601, CWE-1021,
CWE-602, CWE-540, CWE-615, CWE-200.

## Items

- **FE-01 — Token and sensitive data storage** (medium)
  - Verify: grep `localStorage.setItem`, `sessionStorage`, IndexedDB wrappers, `document.cookie =` for tokens, refresh tokens, PII. Prefer HttpOnly cookies / BFF; in-memory access tokens; clear storage on logout.
  - Fail: long-lived refresh tokens or API secrets in Web Storage (any XSS → account takeover). See SESS-12.
- **FE-02 — Third-party scripts and SRI** (medium)
  - Verify: `<script src="https://cdn...">` and `<link rel=stylesheet>` from CDNs have `integrity="sha384-..."` and `crossorigin`; tag managers loading arbitrary vendor scripts on sensitive pages (login, checkout); vendor scripts restricted by CSP; self-host critical libraries.
  - Fail: unpinned CDN scripts without SRI on authenticated pages (CDN compromise = site compromise; cf. polyfill.io incident class).
- **FE-03 — postMessage origin validation** (high)
  - Verify: `addEventListener('message', ...)` handlers check `event.origin` against an exact allowlist before using `event.data`; `postMessage(data, '*')` sending sensitive data; `event.source` checks for iframe communication; OAuth popup flows.
  - Fail: no origin check → cross-origin attacker drives privileged actions or DOM XSS; tokens posted with `'*'` target.
- **FE-04 — Client-side authorization is not authorization** (high when server relies on it)
  - Verify: route guards, `v-if="isAdmin"`, hidden admin menus, feature flags evaluated in the browser — confirm each corresponding API enforces server-side (AUTHZ-10). Admin-only JS chunks shipped to all users reveal hidden endpoints.
  - Fail: API trusts the client's role claim or the absence of a UI button.
- **FE-05 — Source maps in production** (low–medium)
  - Verify: `productionSourceMap`, `devtool: 'source-map'`, Vite `build.sourcemap: true`, Next.js `productionBrowserSourceMaps`, `.map` files in deploy artifacts/public buckets; upload to error tracker privately instead (`hidden-source-map`).
  - Fail: public source maps exposing original source, comments, internal URLs (low on its own; raises severity of other findings).
- **FE-06 — Secrets and internal data in bundles** (high)
  - Verify: grep build output and client env usage (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `NUXT_PUBLIC_`, `PUBLIC_`, `import.meta.env`, `process.env` replaced by DefinePlugin) for secret-class values; Next.js server-only modules imported into client components (`'use client'` files importing DB clients); `getServerSideProps`/loader data returning full records serialized into HTML (`__NEXT_DATA__`).
  - Fail: secret keys, internal tokens or other users' data in shipped JS/HTML (see SEC-04).
- **FE-07 — Open redirects (client-side)** (medium)
  - Verify: `window.location = params.get('next')`, `location.href = returnUrl`, router `navigate(redirect)` with absolute URLs, `window.open(userUrl)`; validate as same-origin relative path (`new URL(x, location.origin).origin === location.origin`).
  - Fail: `?redirect=https://evil.example` after login (phishing, OAuth token leakage chains).
- **FE-08 — Clickjacking and UI redressing** (medium)
  - Verify: `frame-ancestors`/`X-Frame-Options` on HTML (WEB-11); JS frame-busting alone is insufficient; sensitive one-click actions require confirmation.
- **FE-09 — `target="_blank"` and window references** (low)
  - Verify: links to untrusted URLs with `target="_blank"` use `rel="noopener noreferrer"` (modern browsers default `noopener`, but `window.open` returns references); COOP header for sensitive apps.
- **FE-10 — Client-side input handling and DOM sinks** (high)
  - Verify: see XSS-03/XSS-04; also `eval`-like router configs, dynamic `import(userInput)`, `iframe.src = user`, unsafe URL construction.
- **FE-11 — Client-side template injection** (high)
  - Verify: AngularJS (1.x) `ng-app` regions rendering server-reflected text with `{{ }}`; Vue templates compiled at runtime from user data (`template:` string with user content, `v-html` of compiled templates).
  - Fail: `{{constructor.constructor(...)}}`-class execution in AngularJS apps.
- **FE-12 — Frontend dependencies and runtime libraries** (medium)
  - Verify: SCA for client deps; outdated jQuery (< 3.5 `htmlPrefilter`), lodash (prototype pollution), Angular/AngularJS EOL versions, moment (deprecated); polyfills from third-party CDNs.
- **FE-13 — Service workers and caching** (medium)
  - Verify: service worker scope minimal; doesn't cache authenticated API responses across users/logout; `importScripts` only from own origin; SW registered from a path attackers can't upload to.
  - Fail: cached personal data served after logout on shared devices.
- **FE-14 — WebView/Electron/extension specifics** (high where present)
  - Verify: Electron `nodeIntegration: false`, `contextIsolation: true`, `sandbox: true`, no `enableRemoteModule`, `webSecurity` not disabled, IPC handlers validate sender and args, `shell.openExternal` with allowlisted schemes, CSP set; browser extensions with minimal permissions and no remote code.
  - Fail: XSS in Electron renderer → RCE via Node integration.
- **FE-15 — Sensitive data in URLs and client telemetry** (medium)
  - Verify: tokens, emails, or IDs in query strings/fragments sent to analytics or third-party scripts via `document.referrer`/page URL; `Referrer-Policy` set (WEB-13); session replay masking (LOG-11).
- **FE-16 — Autocomplete and form hardening** (low)
  - Verify: `autocomplete="one-time-code"`/`new-password` used correctly; sensitive fields not cached; password fields not disabled for paste (hurts password managers).

## Common false positives
- Public, non-secret keys in bundles: Stripe publishable `pk_*`, Firebase web config, Google Maps keys with HTTP referrer restrictions, Sentry DSN (verify restrictions where applicable).
- Route guards for UX where the API enforces correctly.
- `postMessage` listeners that only handle messages from `window` itself with strict type checks and no sensitive effects.

## Safe validation ideas
- Build locally (if approved) and grep `dist/` for secret patterns and `.map` files — no deployment needed.
- postMessage: local HTML harness on another port that posts `{type:"appsec-canary-<rand>"}` to the locally served app in an iframe; observe handler behavior in the console.
- Open redirect: test `?next=//appsec-canary-<rand>.invalid` locally; a `.invalid` host never resolves, so nothing leaves the machine.
