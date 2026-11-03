# Authentication

Scope: proving user and service identity: credential storage, login, sign-up,
MFA, password reset and change, account recovery, enumeration resistance,
brute-force and credential-stuffing defenses, remember-me, step-up auth,
service-to-service auth and SSO/federation integration.

**Applies when:** the repo contains a user model, login/register/reset routes,
auth libraries (Passport, Devise, Django auth, Spring Security, ASP.NET
Identity, NextAuth/Auth.js, Lucia, Keycloak/Auth0/Cognito/Okta SDKs), or API keys.

**Standards:** OWASP A07:2021 Identification and Authentication Failures,
A04:2021 Insecure Design, A02:2021 Cryptographic Failures (password storage);
API2:2023 Broken Authentication; ASVS V6 Authentication; CWE-287, CWE-306,
CWE-307, CWE-521, CWE-522, CWE-640, CWE-916, CWE-759, CWE-204, CWE-203,
CWE-308, CWE-620, CWE-290.

## Items

- **AUTHN-01 — Password hashing algorithm** (critical if plaintext/reversible, high if fast hash)
  - Verify: Argon2id, scrypt, bcrypt (cost ≥ 10–12; note 72-byte truncation), or PBKDF2-HMAC-SHA256 with high iteration count. Grep `md5(`, `sha1(`, `sha256(` near `password`, `createHash`, `MessageDigest`, `hashlib`, `crypt(`, `base64` of passwords, `encrypt(password`.
  - Fail: unsalted/fast hashes, encryption instead of hashing, homegrown schemes, per-app static salt only.
- **AUTHN-02 — Hash comparison and upgrade path** (medium)
  - Verify: library verify function (constant-time); rehash-on-login when parameters are upgraded; legacy hashes migrated.
  - Fail: `==` on hashes or tokens; legacy MD5 hashes still accepted indefinitely.
- **AUTHN-03 — Every non-public route requires authentication** (critical)
  - Verify: global auth middleware with explicit public allowlist vs per-route opt-in. List routes from inventory and check each; check alternate entry points (admin, internal, health/metrics, debug, GraphQL, WebSocket, gRPC, serverless handlers).
  - Fail: route with no auth decorator/middleware handling user data (CWE-306).
- **AUTHN-04 — Password policy** (medium)
  - Verify: minimum length ≥ 8 (≥ 12 or 15 for single-factor recommended), allow long passphrases (≥ 64), no forced composition rules or periodic rotation, breached-password check (k-anonymity HIBP or local list).
  - Fail: max length ≤ 16, silent truncation, no breach check on high-value apps.
- **AUTHN-05 — Brute force and credential stuffing** (high)
  - Verify: rate limiting per account and per IP/ASN on login, MFA verify, reset, sign-up and OTP endpoints (express-rate-limit, rack-attack, django-axes, Bucket4j, gateway/WAF rules). Progressive delays or CAPTCHA after failures. Check that limits cannot be reset via header spoofing (`X-Forwarded-For` trusted from any client).
  - Fail: unlimited attempts; limiter keyed on spoofable header; 6-digit OTP without attempt cap.
- **AUTHN-06 — Account enumeration** (medium)
  - Verify: login, reset and sign-up return identical messages, status codes and similar timing for existing vs non-existing users (dummy hash computation when user not found).
  - Fail: "user not found" vs "wrong password"; reset says "email not registered"; measurable timing difference.
- **AUTHN-07 — Password reset token quality** (high)
  - Verify: CSPRNG tokens ≥ 128 bits, stored hashed, single-use, short expiry (≤ 1 h), bound to user, invalidated on password change and after use; generated with `secrets`/`crypto.randomBytes`/`SecureRandom`.
  - Fail: `Math.random`, timestamps, sequential IDs, JWTs without single-use tracking, tokens never expire.
- **AUTHN-08 — Reset flow integrity** (high)
  - Verify: reset link host built from config, not the `Host` header (host header poisoning); user identified by token only (not a hidden `email`/`user_id` field); existing sessions revoked after reset; notification sent to the account owner.
  - Fail: `request.host` in reset URL; reset form accepts `user_id` parameter.
- **AUTHN-09 — MFA implementation** (high)
  - Verify: TOTP secrets stored encrypted; OTP verified server-side with replay prevention and attempt limits; MFA enforced on every login path (password login, API tokens, SSO fallback, "remember device"); recovery codes hashed and single-use; WebAuthn verification checks origin, RP ID, challenge, signature counter.
  - Fail: MFA step skippable by calling the post-MFA endpoint directly; MFA status checked only client-side; SMS as sole factor for admins.
- **AUTHN-10 — Credential change and sensitive actions require re-auth** (medium)
  - Verify: change password/email/MFA, add API key, delete account require current password or recent auth (step-up).
  - Fail: hijacked session can change email and take over account.
- **AUTHN-11 — Email/phone change and verification** (medium)
  - Verify: new email verified before becoming login identifier; old email notified; verification tokens follow AUTHN-07 rules; unverified accounts cannot claim pre-existing SSO identities.
  - Fail: pre-account takeover via unverified email registration.
- **AUTHN-12 — Remember-me / persistent login** (medium)
  - Verify: random long-lived token stored hashed server-side (selector/validator pattern), rotated on use, revocable, not the password or a reversible encoding of user ID.
  - Fail: `remember=base64(user:pass)`; non-revocable signed cookie with long life.
- **AUTHN-13 — SSO / federation integration** (high)
  - Verify: SAML: signature validated on assertion (not only response), XML signature wrapping protections, audience/recipient/NotOnOrAfter checked, library current. OIDC: see session-jwt-oauth.md. Account linking by verified email only; `email_verified` claim checked; tenant (`tid`/`iss`) checked for multi-tenant IdPs.
  - Fail: linking by unverified email; accepting tokens from any Azure AD tenant; SAML library with known wrapping issues.
- **AUTHN-14 — API keys and service credentials** (high)
  - Verify: API keys random, prefixed for scanning, stored hashed, scoped, expirable, revocable; service-to-service uses mTLS or signed tokens, not shared static secrets in headers alone.
  - Fail: keys stored plaintext; one global key for all clients.
- **AUTHN-15 — Default, test and backdoor accounts** (critical)
  - Verify: seeds/migrations creating `admin/admin`, hard-coded bypass (`if password == "master"`), debug login routes, `NODE_ENV !== 'production'` auth skips that can be toggled.
  - Fail: any such path reachable in deployed builds.
- **AUTHN-16 — Logout and session termination** (medium)
  - Verify: server-side session invalidation on logout; "log out all devices"; tokens revoked.
  - Fail: logout only clears client cookie.
- **AUTHN-17 — Sign-up abuse** (low–medium)
  - Verify: rate limits, email verification, disposable domain handling where business-relevant; no role/tenant fields accepted at sign-up (see AUTHZ mass assignment).

## Common false positives
- Delegated auth (Auth0/Cognito/Keycloak) — password storage and lockout are the IdP's; check integration items instead and mark others `n/a` with reason.
- Generic error messages but distinct HTTP codes only on internal admin tools behind SSO (lower severity).
- bcrypt with cost 10 on legacy systems: report low/medium, not high.

## Safe validation ideas
- Unit-test reset token generation for entropy source and expiry using a mocked clock.
- Enumeration: compare responses for a seeded test user vs `appsec-canary-<rand>@example.invalid` on a local instance (status, body, approximate timing over a handful of requests — not a timing attack campaign).
- Rate limiting: at most a small number (e.g. 10–15) of failed logins against a seeded test account on a local instance; never against real accounts, never credential lists.
- MFA bypass: with a test account, call the post-MFA endpoint with the pre-MFA session and check for 401/403.
