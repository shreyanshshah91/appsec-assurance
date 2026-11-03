# Logging, monitoring and audit

Scope: whether security-relevant events are recorded with enough context to
detect and investigate attacks; whether logs avoid leaking sensitive data and
resist injection and tampering; whether alerting exists for high-signal
events; and whether administrative and data-access actions leave a durable
audit trail with appropriate retention.

**Applies when:** always for services and APIs; logging libraries (winston,
pino, bunyan, logging/structlog/loguru, log4j/logback/SLF4J, Serilog/NLog,
zap/zerolog/slog, Monolog, Rails logger), APM/error trackers (Sentry,
Datadog, New Relic, OpenTelemetry) present.

**Standards:** OWASP A09:2021 Security Logging and Monitoring Failures;
ASVS V16 Security Logging and Error Handling; CWE-778, CWE-223, CWE-117,
CWE-532, CWE-779, CWE-1295, CWE-209.

## Items

- **LOG-01 — Authentication events logged** (medium)
  - Verify: login success/failure, logout, MFA challenge/fail, password reset request/complete, account lockout, token refresh failures, SSO assertion failures — with user ID (or attempted identifier, hashed/truncated if sensitive), source IP, user agent, timestamp, outcome, request ID.
  - Fail: no failure logging (missing-control) — brute force invisible.
- **LOG-02 — Authorization failures and anomalies logged** (medium)
  - Verify: 403s with principal and target object, input-validation failures on sensitive endpoints, CSRF/CORS rejections, rate-limit hits, signature/webhook verification failures.
- **LOG-03 — Audit trail for privileged and sensitive actions** (high for admin/multi-tenant/regulated)
  - Verify: role/permission changes, user creation/deletion, impersonation ("login as"), API key creation, config/security setting changes, data exports, bulk deletes, payment/refund actions recorded in a dedicated audit log: actor, action, target, before/after, timestamp, source, reason/ticket for impersonation.
  - Fail: admin can change roles or export data with no record.
- **LOG-04 — Sensitive data excluded from logs** (high)
  - Verify: no passwords, tokens, session IDs, `Authorization`/`Cookie` headers, API keys, full card numbers/CVV, government IDs, health data, secrets from env, full request bodies on auth/payment routes; redaction configured (pino `redact`, structlog processors, logback masking, Serilog destructuring policies, Sentry `beforeSend`/`sendDefaultPii: false`); HTTP client debug logs disabled in prod.
  - Fail: `logger.info(req.body)` on login; `log.debug(f"token={token}")`.
- **LOG-05 — Log injection prevention** (low–medium)
  - Verify: structured (JSON) logging or CR/LF escaping of user input; log viewers escape HTML; Log4j 2 ≥ 2.17.1 (no message lookups); no `%m` formatting with attacker data in vulnerable versions.
  - Fail: forged entries; XSS in log dashboards (see INJ-14).
- **LOG-06 — Correlation and context** (low)
  - Verify: request/trace IDs propagated across services and included in logs and error responses; consistent UTC timestamps; service/version/environment fields.
- **LOG-07 — Centralization and protection** (medium)
  - Verify: logs shipped off-host (CloudWatch, Cloud Logging, Elastic, Splunk, Loki) promptly; app identities cannot delete/modify central logs; audit logs append-only or in WORM storage (S3 Object Lock, immutable buckets), optionally hash-chained/signed; access to logs restricted and itself audited.
  - Fail: audit records stored in the same DB table the app (and admins) can update/delete.
- **LOG-08 — Alerting on high-signal events** (medium)
  - Verify: alerts for spikes in auth failures, MFA failures, lockouts, 5xx, WAF blocks, privilege changes, new admin users, API key creation, access from new geographies for admins, cloud control-plane anomalies (GuardDuty/Defender/SCC). Alert routing to an owned on-call channel (ask user).
  - Fail: logs exist but nobody is notified (missing-control).
- **LOG-09 — Retention and deletion** (medium)
  - Verify: retention periods defined per log class (security/audit typically ≥ 1 year; operational shorter), meeting regulatory needs; PII in logs subject to deletion/minimization policy; lifecycle rules in IaC.
  - Fail: indefinite retention of PII-laden logs, or retention too short for investigation.
- **LOG-10 — Logging failures don't fail open** (low–medium)
  - Verify: audit write failures on critical actions handled (block or queue reliably); logging backpressure doesn't crash the app (DoS); disk-full behavior.
- **LOG-11 — Client and edge telemetry** (low–medium)
  - Verify: frontend error trackers and analytics don't capture tokens/PII (URL query strings, form values, session replay masking for inputs); CDN/WAF logs enabled.
  - Fail: session replay records password fields or payment forms.
- **LOG-12 — Security monitoring coverage of background systems** (low–medium)
  - Verify: workers, cron jobs, queue consumers, serverless functions and CI deploys emit security events too; deploy events recorded (who deployed what, when).
- **LOG-13 — Time synchronization and integrity of timestamps** (low)
  - Verify: hosts/containers use NTP/managed time; logs record server time, not client-provided time.
- **LOG-14 — Incident readiness** (info–low)
  - Verify: runbooks or documented process to search logs for a user/IP/token, revoke sessions, and preserve evidence (ask user; record as `untested` if not visible).

## Common false positives
- Logging of user IDs and IPs — normally necessary for security; assess against privacy policy rather than flagging by default.
- Debug-level logging of sensitive data where debug is provably disabled in all deployed configs (still low: risk of toggling).
- Centralized logging configured outside the repo (platform team) — mark `untested` with reason instead of `fail`.

## Safe validation ideas
- Unit/integration test: perform a failed login with a seeded test user locally and assert the log line contains outcome and request ID but not the password `appsec-canary-<rand>`.
- Grep captured local logs for the canary to prove (or disprove) sensitive-data logging.
- Log injection: submit `appsec-canary-<rand>\nFAKE ENTRY` in a test field locally and inspect the raw log output.
