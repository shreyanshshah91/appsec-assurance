# Sessions, JWT and OAuth/OIDC

Scope: server-side sessions and cookies, self-contained tokens (JWT/JWS/JWE,
PASETO), token storage in browsers, and OAuth 2.x / OpenID Connect flows as
client, resource server or authorization server.

**Applies when:** session middleware, JWT libraries (`jsonwebtoken`, `jose`,
`PyJWT`, `python-jose`, `jjwt`, `nimbus-jose-jwt`, `golang-jwt`,
`System.IdentityModel.Tokens.Jwt`), OAuth/OIDC client libs, NextAuth/Auth.js,
Spring Security OAuth2, or custom token code are present.

**Standards:** OWASP A07:2021, A02:2021, A01:2021; API2:2023 Broken
Authentication; ASVS V7 Session Management, V9 Self-contained Tokens, V10 OAuth
and OIDC; CWE-384, CWE-613, CWE-614, CWE-1004, CWE-1275, CWE-347, CWE-345,
CWE-327, CWE-922, CWE-352, CWE-601.

## Items

### Sessions and cookies
- **SESS-01 — Session ID regenerated on authentication and privilege change** (high)
  - Verify: `session.regenerate()` (express-session), `request.session.cycle_key()`/Django login does it, `reset_session` (Rails), Spring `sessionFixation().migrateSession()`, PHP `session_regenerate_id(true)`.
  - Fail: same session ID before and after login (fixation) or after role elevation.
- **SESS-02 — Cookie flags** (medium)
  - Verify: `Secure`, `HttpOnly`, `SameSite=Lax|Strict`, narrow `Path`, no broad `Domain`; `__Host-` prefix for session cookies where possible.
  - Fail: session cookie readable by JS or sent over HTTP.
- **SESS-03 — Session expiry** (medium)
  - Verify: idle timeout and absolute lifetime enforced server-side (store TTL), not only via cookie `Max-Age`; shorter for admin/high-risk.
  - Fail: sessions valid indefinitely; expiry only client-side.
- **SESS-04 — Server-side invalidation** (medium)
  - Verify: logout, password change, MFA reset and account disable destroy sessions/refresh tokens across devices.
  - Fail: stolen session survives password reset.
- **SESS-05 — Session secret and store** (high)
  - Verify: session signing secret from secret store, long and random, not default (`keyboard cat`, `changeme`, `SECRET_KEY = 'django-insecure-...'`); signed cookie-sessions (Flask, Rails cookie store) contain no secrets and can't be replayed after logout without server state.
  - Fail: default or committed secret → session forgery.

### JWT
- **SESS-06 — Algorithm pinned on verification** (critical)
  - Verify: verify calls pass explicit `algorithms=[...]`; grep `jwt.decode(` without `algorithms`, `verify=False`, `options={"verify_signature": False}`, `jwt.decode` vs `jwt.verify` (jsonwebtoken `decode` does not verify), `ignoreExpiration`, `parseUnsecuredClaims`, `none`.
  - Fail: `alg: none` accepted; unverified decode used for authz decisions.
- **SESS-07 — Algorithm confusion (RS/HS)** (critical)
  - Verify: when RSA/EC public keys are used, HMAC algorithms are rejected; key objects typed (`jose` KeyLike) rather than raw strings passed to a generic verify.
  - Fail: public key usable as HMAC secret.
- **SESS-08 — Header-driven key selection (`kid`, `jku`, `x5u`, `jwk`)** (critical)
  - Verify: `kid` looked up in a fixed key set (no file paths, no SQL); `jku`/`x5u` ignored or matched against an exact allowlist; embedded `jwk` header never trusted.
  - Fail: `kid` used in file read or DB query; JWKS fetched from token-supplied URL.
- **SESS-09 — Claims validated** (high)
  - Verify: `exp` (short, ≤ 15–60 min for access tokens), `nbf`, `iat`, `iss` exact match, `aud` exact match for this service, `sub` mapped to an active user; clock skew small. For multi-tenant IdPs, validate tenant.
  - Fail: tokens for another audience accepted (cross-service replay); no `exp`.
- **SESS-10 — HMAC secret strength** (high)
  - Verify: HS256 secrets ≥ 256 bits random; not committed, not shared between environments.
  - Fail: short/dictionary secret (offline crackable), same secret in dev and prod.
- **SESS-11 — Revocation and sensitive content** (medium)
  - Verify: revocation strategy (short TTL + refresh, denylist by `jti`, token version on user); JWT payload has no secrets/PII beyond need (it is only encoded).
  - Fail: long-lived JWTs that can't be revoked; PII in tokens stored in logs/URLs.

### Browser token storage
- **SESS-12 — Token storage** (medium)
  - Verify: access/refresh tokens in `localStorage`/`sessionStorage`/IndexedDB are exposed to any XSS; prefer HttpOnly cookies or BFF pattern, in-memory access tokens. Tokens never in URLs (query/fragment) after the OAuth callback.
  - Fail: refresh tokens in `localStorage`; tokens in query strings (leak via logs/Referer).

### OAuth 2.x / OIDC
- **SESS-13 — `state` parameter (CSRF on callback)** (high)
  - Verify: unpredictable `state` generated per request, bound to user session, checked on callback.
  - Fail: missing or static `state`; callback accepts any code (login CSRF/account linking attack).
- **SESS-14 — PKCE** (high for public clients, medium for confidential)
  - Verify: `code_challenge_method=S256` used; server rejects missing/`plain` where policy requires.
  - Fail: SPA/mobile clients without PKCE; implicit flow (`response_type=token`) in use.
- **SESS-15 — OIDC `nonce` and ID token validation** (high)
  - Verify: `nonce` sent and checked; ID token signature, `iss`, `aud` (= client_id), `azp`, `exp` validated; `at_hash`/`c_hash` where applicable; userinfo matched to `sub`.
  - Fail: ID token decoded without verification; identity keyed on `email` instead of `iss`+`sub`.
- **SESS-16 — `redirect_uri` validation (authorization server side)** (critical)
  - Verify: exact string match against registered URIs; no wildcard subdomains, no prefix matching, no open redirect on registered hosts.
  - Fail: `startsWith` matching → code/token theft to attacker paths.
- **SESS-17 — Client-side redirect hygiene** (high)
  - Verify: post-login `returnTo`/`next` parameters restricted (see SSRF-11); open redirects on the client's own domain can leak codes when `redirect_uri` allows paths.
- **SESS-18 — Refresh token handling** (high)
  - Verify: rotation on each use with reuse detection (revoke family), sender-constrained (DPoP/mTLS) or bound to client, absolute lifetime, revoked on logout/password change; stored hashed server-side.
  - Fail: non-rotating, non-expiring refresh tokens.
- **SESS-19 — Client secrets and confidential client config** (high)
  - Verify: client secrets not in frontend/mobile bundles; `private_key_jwt` or mTLS for high-value clients; scopes minimal.
  - Fail: secret shipped in JS bundle; `offline_access`/admin scopes requested by default.
- **SESS-20 — Token endpoint and introspection on resource servers** (medium)
  - Verify: resource servers validate audience/scope per endpoint, not just signature; opaque tokens introspected with caching bounded by expiry.

## Common false positives
- `jwt.decode(..., verify=False)` used only to read `kid`/`iss` before a proper verified decode — confirm the verified decode follows.
- Long-lived tokens for machine clients with mTLS binding and rotation (assess separately).
- Missing PKCE for confidential server-side clients using client secrets (still recommended; medium/low).

## Safe validation ideas
- Unit-test the verify function with locally forged tokens: `alg: none`, HS256 signed with the public key PEM, wrong `aud`, expired `exp` — all generated in the scratchpad with throwaway keys. Never forge tokens against shared or production environments.
- Session fixation: on a local instance, capture the pre-login cookie for a seeded test user, log in, and compare.
- OAuth: on a local/dev IdP, alter `redirect_uri` to `https://appsec-canary-<rand>.invalid/cb` and confirm rejection; tamper `state` and confirm the callback fails.
