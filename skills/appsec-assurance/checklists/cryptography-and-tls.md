# Cryptography and TLS

Scope: choice and use of cryptographic primitives (hashing, symmetric and
asymmetric encryption, MACs, signatures), modes, IVs and nonces, randomness,
key derivation, key management and rotation, TLS configuration of servers and
clients, and certificate validation. Password hashing is in authentication.md.

**Applies when:** crypto imports (`crypto`, `cryptography`, `pycryptodome`,
`javax.crypto`, `System.Security.Cryptography`, `crypto/*` in Go, libsodium,
OpenSSL bindings), random token generation, TLS/HTTP client configuration,
certificate or key files, or KMS/Vault usage are present.

**Standards:** OWASP A02:2021 Cryptographic Failures; ASVS V11 Cryptography,
V12 Secure Communication; CWE-327, CWE-326, CWE-328, CWE-330, CWE-338, CWE-329,
CWE-323, CWE-321, CWE-295, CWE-297, CWE-319, CWE-757, CWE-208, CWE-347.

## Items

- **CRYPTO-01 — No broken or weak algorithms** (high; medium if non-security use)
  - Verify: grep `MD5`, `SHA1` (for signatures/integrity/password), `DES`, `3DES`/`DESede`, `RC4`, `Blowfish`, `RSA` < 2048, `ECB`, `PKCS1v15` encryption padding for new designs, `DSA`.
  - Fail: these used for confidentiality, integrity or authentication. MD5/SHA1 for non-security checksums (cache keys, ETags) is info.
- **CRYPTO-02 — Authenticated encryption** (high)
  - Verify: AES-GCM, ChaCha20-Poly1305, AES-GCM-SIV, or libsodium `secretbox`/`aead`; or encrypt-then-MAC with separate keys. Fernet is acceptable.
  - Fail: AES-CBC/CTR without MAC (padding oracle, malleability); `AES/ECB/PKCS5Padding` (Java default `Cipher.getInstance("AES")` is ECB).
- **CRYPTO-03 — IV/nonce generation and uniqueness** (critical for GCM reuse)
  - Verify: random 96-bit nonces per message for GCM (or a counter with guaranteed uniqueness), random unpredictable IV for CBC, no constant or zero IVs, no IV derived from key or reused with the same key.
  - Fail: `iv = b'\x00'*16`, hard-coded nonce, nonce reuse under one key (GCM forgery/keystream reuse).
- **CRYPTO-04 — CSPRNG for all security values** (high)
  - Verify: tokens, IDs used as secrets, salts, keys, nonces, reset codes, OTPs come from `secrets`, `os.urandom`, `crypto.randomBytes`/`crypto.getRandomValues`/`randomUUID`, `SecureRandom`, `RandomNumberGenerator`, `crypto/rand`. Grep `Math.random`, `random.random`/`random.randint`, `java.util.Random`, `System.Random`, `math/rand`, `rand()`, `mt_rand`, `uniqid`.
  - Fail: non-CSPRNG for security values; seeded RNG with time.
- **CRYPTO-05 — Hardcoded or weak keys** (critical)
  - Verify: literal keys/IVs/secrets in code, test keys used in prod config, keys derived from passwords with a single hash.
  - Fail: `key = "0123456789abcdef"`; JWT/HMAC/encryption keys committed (see secrets-management.md).
- **CRYPTO-06 — Key derivation** (medium)
  - Verify: passwords → keys via Argon2id/scrypt/PBKDF2 with salt and adequate cost; key separation via HKDF with distinct `info` per purpose.
  - Fail: same key for encryption and MAC; raw SHA-256(password) as AES key.
- **CRYPTO-07 — Key management and rotation** (medium–high)
  - Verify: keys held in KMS/HSM/Vault/cloud secret manager; envelope encryption for data keys; key IDs stored with ciphertext to enable rotation; documented rotation; least-privilege access to decrypt; separate keys per environment and tenant where required.
  - Fail: one static key forever with no versioning; app role has `kms:*`.
- **CRYPTO-08 — Signatures and MAC verification** (high)
  - Verify: HMAC/signature comparisons constant-time (`hmac.compare_digest`, `crypto.timingSafeEqual`, `MessageDigest.isEqual`, `subtle.ConstantTimeCompare`, `CryptographicOperations.FixedTimeEquals`); signatures verified before parsing/using data; Ed25519/ECDSA with library-managed nonces.
  - Fail: `==` on MACs (timing leak); verify result ignored.
- **CRYPTO-09 — Homegrown crypto** (high)
  - Verify: custom ciphers, XOR "encryption", base64 as "encryption", manual padding, hand-rolled JWT/HMAC.
  - Fail: any security reliance on such code.
- **CRYPTO-10 — TLS server configuration** (medium)
  - Verify: nginx/Apache/HAProxy/Envoy/ingress/ALB configs: TLS 1.2+ only (1.3 preferred), no SSLv3/TLS1.0/1.1, AEAD cipher suites with forward secrecy, no RSA key exchange/export/NULL/anon ciphers, OCSP stapling, cert key ≥ 2048 RSA or P-256. Cloud LB security policies (e.g. AWS `ELBSecurityPolicy-TLS13-1-2-2021-06`).
  - Fail: legacy protocol versions enabled; outdated LB policy.
- **CRYPTO-11 — TLS certificate validation in clients** (critical)
  - Verify: grep `verify=False`, `CERT_NONE`, `check_hostname = False`, `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `InsecureSkipVerify: true`, `TrustAllCerts`, custom `X509TrustManager` with empty `checkServerTrusted`, `HostnameVerifier` returning true, `ServerCertificateValidationCallback = ... => true`, `curl -k`/`--insecure`, `CURLOPT_SSL_VERIFYPEER 0`.
  - Fail: any of these in production code paths (MITM).
- **CRYPTO-12 — Cleartext transport** (high)
  - Verify: `http://` URLs to APIs/IdPs/webhooks, DB connections without TLS (`sslmode=disable`, `useSSL=false`, `encrypt=false`), SMTP without STARTTLS, Redis/AMQP/Kafka without TLS across networks, internal service mesh without mTLS where policy requires.
  - Fail: credentials or PII crossing untrusted networks in cleartext.
- **CRYPTO-13 — mTLS and private CA handling** (medium)
  - Verify: client certs validated against a specific CA (not system store) for service auth; private keys file permissions; cert expiry monitoring.
- **CRYPTO-14 — Encryption at rest for sensitive fields** (medium)
  - Verify: field-level encryption for high-sensitivity data (SSNs, tokens, TOTP secrets) where DB-level encryption is insufficient; deterministic encryption only where searchability is required and its leakage accepted.
- **CRYPTO-15 — Library and protocol currency** (medium)
  - Verify: OpenSSL/BoringSSL/crypto libs current; deprecated libraries (`pycrypto`, `crypto-js` for security-critical server code, `node-forge` old versions, `bleach`-style unmaintained) flagged; post-quantum migration noted as info for long-lived secrets.

## Common false positives
- MD5/SHA1 for content addressing, deduplication, cache keys, or legacy protocol interop (e.g. Git object IDs).
- `Math.random` for UI jitter, sampling, or non-secret IDs.
- `verify=False` in test files or against localhost test containers only — confirm it cannot reach prod config.
- TLS terminated at a managed load balancer — app-level TLS config may be `n/a`; review LB policy instead.

## Safe validation ideas
- Unit-test encryption helpers: encrypt the same plaintext `appsec-canary-<rand>` twice and assert ciphertexts/nonces differ; flip one ciphertext bit and assert decryption fails (authentication).
- Check TLS of an in-scope local/staging endpoint with a single `openssl s_client -connect host:443 -tls1_1` handshake (expect failure) — no scanning of third-party hosts.
- Cert validation: point the client at a local server with a self-signed cert in a test; it must fail.
