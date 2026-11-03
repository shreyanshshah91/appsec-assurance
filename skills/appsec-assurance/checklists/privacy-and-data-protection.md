# Privacy and data protection

Scope: technical controls protecting personal and sensitive data across its
lifecycle: inventory and classification, minimization, purpose-bound access,
encryption, retention and deletion, exports and data-subject requests, backup
security, disaster recovery objectives, data residency, consent and
third-party sharing. This checklist supports privacy engineering; it is **not
legal advice**. Reference GDPR/UK GDPR/CCPA-CPRA/HIPAA/PCI DSS only to flag
that a control is likely relevant, and recommend the user consult their
privacy/legal team for compliance determinations.

**Applies when:** the system stores or processes personal data (accounts,
emails, names, addresses, phone numbers, IPs, device IDs, location, payment,
health, biometrics, children's data), uses analytics/advertising SDKs, or has
backups/replicas.

**Standards:** OWASP A02:2021 Cryptographic Failures, A04:2021 Insecure Design,
A01:2021; API3:2023 (excessive data exposure); ASVS V14 Data Protection, V8
Authorization; CWE-359, CWE-200, CWE-201, CWE-212, CWE-311, CWE-312, CWE-313,
CWE-532, CWE-226.

## Items

- **PRIV-01 — Data inventory exists and matches code** (medium)
  - Verify: list models/tables/collections and fields that hold personal data (grep `email`, `phone`, `address`, `dob`, `ssn`, `passport`, `ip_address`, `lat`/`lng`, `gender`, `health`, `card`); compare with any data map/RoPA in docs. Note third-party processors receiving data (SDK and API calls).
  - Fail: no inventory; undocumented PII stores (search indexes, caches, analytics, logs).
- **PRIV-02 — Classification and handling tiers** (low–medium)
  - Verify: fields tagged by sensitivity (annotations, schema comments, data catalog); special-category data (health, biometrics, children's, precise location, financial) has stricter controls.
- **PRIV-03 — Minimization** (medium)
  - Verify: collection limited to what features need (sign-up forms, mobile permissions, SDK auto-collection); API responses return minimal fields (AUTHZ-06); analytics events don't carry raw PII; IP truncation/hashing where full IPs aren't needed.
  - Fail: full DOB/SSN collected "just in case"; PII in analytics event properties or URLs.
- **PRIV-04 — Access to personal data is purpose-bound and audited** (medium–high)
  - Verify: support/admin tools show masked data by default, require reason for unmasking, log access (LOG-03); production data access for engineers gated (break-glass); no prod PII in dev/test/staging (synthetic or masked datasets, seed scripts).
  - Fail: prod DB dumps copied into staging or committed fixtures with real PII.
- **PRIV-05 — Encryption of personal data** (medium–high)
  - Verify: in transit everywhere (CRYPTO-12); at rest for stores, backups, exports and object storage (DB-06, CLOUD-05); field-level encryption or tokenization for highest-sensitivity fields; PCI scope minimized (no PAN storage, use provider tokenization).
  - Fail: card numbers or government IDs stored plaintext.
- **PRIV-06 — Retention and deletion** (medium)
  - Verify: retention periods implemented as code (TTL indexes, scheduled purge jobs, S3 lifecycle rules); account deletion removes or anonymizes data across primary DB, replicas, search, caches, object storage, analytics and third parties (or documents backup expiry); soft-delete flags not mistaken for deletion.
  - Fail: "delete account" only sets `deleted=true`; no purge of uploads.
- **PRIV-07 — Data subject requests: access and portability** (low–medium)
  - Verify: export features authenticate and authorize strictly (re-auth, AUTHZ-12), generate files in private storage with short-lived links, include all data categories.
  - Fail: export endpoint is an IDOR — mass data breach vector.
- **PRIV-08 — Consent and preferences** (low–medium)
  - Verify: non-essential cookies/SDKs load only after consent (check script loading order, tag manager config); consent state stored and honored server-side for marketing emails/tracking; opt-out signals (e.g. Global Privacy Control) handled if applicable.
  - Fail: analytics/ads SDKs initialized before consent; consent recorded only in client.
- **PRIV-09 — Third-party sharing and SDKs** (medium)
  - Verify: list outbound data flows to processors (email, CRM, analytics, error tracking, LLM/AI APIs, session replay); PII scrubbing before sending; data processing agreements referenced (ask user); AI/LLM prompts not containing unnecessary personal data; vendor regions.
  - Fail: full user records sent to analytics or LLM providers without need.
- **PRIV-10 — Data residency and transfers** (low–medium)
  - Verify: regions configured in IaC for storage, DB, backups, logs and CDN logs match stated residency commitments; cross-region replication destinations; third-party processor regions.
  - Fail: EU-resident commitment but backups replicate to another region (flag for legal review, not a legal conclusion).
- **PRIV-11 — Backup security** (high)
  - Verify: backups encrypted with managed keys, access restricted to a backup role, stored in separate account/project, immutable/Object Lock against ransomware, not public (DB-09, CLOUD-10); backup restore access audited.
  - Fail: backups in the same account with the same admin credentials as prod; unencrypted dumps.
- **PRIV-12 — Disaster recovery objectives and controls** (medium)
  - Verify: documented RTO/RPO; backup frequency and point-in-time recovery consistent with RPO; multi-AZ/region design consistent with RTO; restore tests performed and recorded (ask user); runbooks exist; deletion protection on critical stores (CLOUD-14).
  - Fail: no tested restore (missing-control); RPO of 1 h claimed with daily backups.
- **PRIV-13 — Breach readiness** (low)
  - Verify: ability to determine affected users from logs/audit trails; contact paths; key and credential revocation procedures (ask user).
- **PRIV-14 — Pseudonymization and anonymization claims** (low–medium)
  - Verify: "anonymized" datasets for analytics/ML are not trivially re-identifiable (hashed emails without salt are pseudonymous, not anonymous; quasi-identifiers like ZIP+DOB+gender).
  - Fail: unsalted SHA-256(email) shared as "anonymous ID".
- **PRIV-15 — Children's and special-category data** (info–medium)
  - Verify: age gating/parental consent flows where the product targets children; extra controls on health/biometric data; flag for legal review.

## Common false positives
- Business contact data in B2B CRMs handled under documented legitimate interest — not a technical finding.
- IP addresses in security logs retained for a defined period — usually justified (LOG-09).
- Encrypted backups with restore testing handled by a managed provider — verify via provider config, then pass.

## Safe validation ideas
- Static: map PII fields to stores and outbound calls with file:line evidence; produce a data-flow table for the report.
- Locally, create a seeded test user with marker data (`appsec-canary-<rand>@example.invalid`), run the deletion flow, then grep local DB/search/cache/log outputs for the marker.
- Never access, copy or sample real user data to prove a finding; describe it from schema and code.
