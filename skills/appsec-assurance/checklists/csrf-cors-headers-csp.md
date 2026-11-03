# CSRF, CORS, security headers and CSP

Scope: browser-enforced protections and their server-side configuration:
cross-site request forgery defenses, CORS policy correctness, Content Security
Policy quality, HSTS, framing protections, other response headers, and caching
of sensitive responses.

**Applies when:** any HTTP endpoint is reachable from a browser, cookies or
HTTP auth are used, CORS middleware is configured, or the app serves HTML.

**Standards:** OWASP A01:2021 Broken Access Control (CSRF, CORS), A05:2021
Security Misconfiguration; API8:2023 Security Misconfiguration; ASVS V3 Web
Frontend Security, V4 API and Web Service, V13 Configuration; CWE-352, CWE-942,
CWE-346, CWE-1021, CWE-693, CWE-319, CWE-525, CWE-524.

## Items

### CSRF
- **WEB-01 — State-changing requests protected against CSRF** (high)
  - Verify: if auth is cookie-based (session or JWT-in-cookie), check synchronizer/double-submit tokens (Django `CsrfViewMiddleware`, Rails `protect_from_forgery`, Spring Security csrf, `csurf` replacement such as `csrf-csrf`, ASP.NET antiforgery), or strict Origin/`Sec-Fetch-Site` validation. Grep for `csrf_exempt`, `skip_before_action :verify_authenticity_token`, `csrf().disable()`, `IgnoreAntiforgeryToken`.
  - Fail: cookie-authenticated POST/PUT/PATCH/DELETE with no token or origin check; exemptions on sensitive routes.
- **WEB-02 — No state change on GET/HEAD** (high)
  - Verify: routes mapped to GET that mutate (logout is low; delete/transfer/role change is high). Check `app.all`, `@RequestMapping` without method, Rails `match ... via: :all`.
  - Fail: `GET /account/delete`, `GET /api/transfer?to=`.
- **WEB-03 — SameSite and cookie scoping** (medium)
  - Verify: session cookie `SameSite=Lax` or `Strict` (`None` requires justification and `Secure`); not set on parent domain unnecessarily (`Domain=.example.com` exposes to sibling subdomains).
  - Fail: `SameSite=None` for session cookies without CSRF tokens; Lax relied upon while GETs mutate.
- **WEB-04 — Content-type based CSRF** (medium)
  - Verify: JSON APIs using cookies also accept `text/plain`/form encodings (body parsers that ignore Content-Type). Simple requests bypass preflight.
  - Fail: server parses `text/plain` body as JSON on cookie-auth endpoints.
- **WEB-05 — Login and logout CSRF** (low–medium)
  - Verify: login form has CSRF protection (login CSRF enables session swap); OAuth callbacks use `state` (see session-jwt-oauth.md).

### CORS
- **WEB-06 — No origin reflection with credentials** (critical/high)
  - Verify: `Access-Control-Allow-Origin` set from request `Origin` without allowlist; `cors({origin: true, credentials: true})`, `origin: '*'` + `credentials`, Spring `allowedOriginPatterns("*")` + `allowCredentials(true)`, custom middleware echoing `req.headers.origin`.
  - Fail: arbitrary origin can read authenticated responses.
- **WEB-07 — Allowlist matching is exact** (high)
  - Verify: regexes and suffix checks: `endsWith('example.com')` matches `evilexample.com`; unescaped dots; `startsWith('https://example.com')` matches `https://example.com.evil.net`.
  - Fail: bypassable origin validation.
- **WEB-08 — `null` origin and insecure schemes** (high)
  - Verify: `null` in allowlist (sandboxed iframes, `file:`, redirects send `Origin: null`); `http://` origins trusted for an HTTPS app.
  - Fail: `Access-Control-Allow-Origin: null` with credentials.
- **WEB-09 — Preflight scope** (low)
  - Verify: `Access-Control-Allow-Methods`/`-Headers` not `*` with credentials; `Max-Age` reasonable; `Vary: Origin` present when ACAO is dynamic (cache poisoning).
  - Fail: missing `Vary: Origin` behind a CDN with dynamic ACAO.

### CSP and headers
- **WEB-10 — CSP present and meaningful** (medium; high if XSS sinks exist)
  - Verify: header or meta `Content-Security-Policy` (helmet, `django-csp`, `secure_headers`, Spring `contentSecurityPolicy`, nginx `add_header`). Evaluate: `script-src` without `'unsafe-inline'`/`'unsafe-eval'`, nonces or hashes with `'strict-dynamic'`, no wildcards or broad CDN hosts that serve user content/JSONP (e.g. whole `*.googleapis.com`), `object-src 'none'`, `base-uri 'none'` or `'self'`, `form-action` restricted.
  - Fail: no CSP; CSP only `Report-Only`; `default-src *`; `'unsafe-inline'` scripts; static nonce reused across responses.
- **WEB-11 — Framing protection** (medium)
  - Verify: CSP `frame-ancestors 'none'|'self'` (preferred) or `X-Frame-Options: DENY|SAMEORIGIN` on HTML responses, especially auth, settings and payment pages.
  - Fail: sensitive pages framable (clickjacking).
- **WEB-12 — HSTS** (medium)
  - Verify: `Strict-Transport-Security: max-age>=31536000; includeSubDomains` (preload only if all subdomains are HTTPS); set at app or edge; HTTP→HTTPS redirect.
  - Fail: absent, short max-age, or sent over HTTP only.
- **WEB-13 — Other headers** (low)
  - Verify: `X-Content-Type-Options: nosniff`; `Referrer-Policy: strict-origin-when-cross-origin` or stricter (tokens in URLs leak via Referer); `Permissions-Policy` disabling unused features; `Cross-Origin-Opener-Policy: same-origin` for apps handling sensitive windows; `Cross-Origin-Resource-Policy` for sensitive assets. Remove `X-Powered-By`/`Server` version banners. `X-XSS-Protection` should be `0` or absent (legacy auditor is harmful).
  - Fail: missing nosniff on user-content endpoints; verbose server banners.
- **WEB-14 — Cache-Control on sensitive responses** (medium)
  - Verify: authenticated pages and API responses with PII/tokens send `Cache-Control: no-store` (and are not cached by CDN rules keyed only on path). Check CDN/edge config (CloudFront behaviors, Cloudflare page rules, Varnish) and `Vary` headers.
  - Fail: account pages cacheable by shared caches; web cache deception via `/account/profile.css` path confusion.
- **WEB-15 — Headers applied consistently** (low)
  - Verify: headers set globally, including error pages, static files, and API gateway/edge responses, not only on the main route.

## Common false positives
- Pure bearer-token APIs (Authorization header, no cookies) do not need CSRF tokens; confirm no cookie fallback.
- `Access-Control-Allow-Origin: *` without credentials on genuinely public, non-sensitive data.
- Missing CSP on JSON-only APIs (low value; nosniff matters more).
- Headers absent in code but set by a reverse proxy/CDN — verify the proxy config before reporting.

## Safe validation ideas
- CORS: send a local request with `Origin: https://appsec-canary-<rand>.invalid` and `Origin: null` to an in-scope local instance; inspect ACAO/ACAC. No credentials of real users.
- CSRF: build a static local HTML form targeting a local test instance using a seeded test account; action should be a harmless profile field set to `appsec-canary-<rand>`.
- Headers: a single `curl -sI` against the in-scope local or staging URL; compare to expectations.
- Framing: local HTML page with `<iframe src=...>` and observe whether the browser blocks it.
