# Secrets management

Scope: discovery and handling of credentials, keys and tokens in source,
configuration, git history, CI systems, container images, logs and client
bundles; and the presence of a proper secrets lifecycle (storage, access,
rotation, revocation).

**Hard rule:** secrets you find are reported **redacted** (first 4 characters +
length + type, e.g. `AKIA…(20, AWS access key ID)`), with file:line and commit
if from history. Never test, use, validate against a live API, decode-and-use,
or exfiltrate a discovered secret. Do not paste full secrets into reports,
logs, chat or tickets. Recommend rotation; do not rotate yourself.

**Applies when:** always.

**Standards:** OWASP A02:2021 Cryptographic Failures, A07:2021 Identification
and Authentication Failures, A05:2021; ASVS V13 Configuration, V11
Cryptography; CWE-798, CWE-259, CWE-321, CWE-312, CWE-532, CWE-540, CWE-615,
CWE-200, CWE-522.

## Items

- **SEC-01 — No hardcoded secrets in source** (critical for live prod credentials; high otherwise)
  - Verify: built-in rules + Gitleaks/TruffleHog (offline mode, no verification calls) when installed. Manual greps: `(?i)(api[_-]?key|secret|passw(or)?d|token|private[_-]?key|client[_-]?secret)\s*[:=]`, `-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY`, `AKIA[0-9A-Z]{16}`, `ghp_`, `github_pat_`, `glpat-`, `xox[abpr]-`, `sk_live_`, `AIza`, connection strings `://[^:]+:[^@]+@`.
  - Fail: real-looking credentials in code, config, tests, notebooks, docs.
- **SEC-02 — `.env` and local config files** (high)
  - Verify: `.env`, `.env.*`, `config/*.local.*`, `application-prod.yml`, `appsettings.Production.json`, `settings_local.py`, `credentials.json`, `service-account*.json`, `*.pem`, `*.p12`, `*.pfx`, `*.jks`, `id_rsa`, `.npmrc`/`.pypirc` with tokens, `.netrc`, `.docker/config.json` committed. Check `.gitignore` covers them; `.env.example` contains placeholders only.
  - Fail: committed env file with values; example file with real values.
- **SEC-03 — Git history** (high)
  - Verify: `git log -p -S'<pattern>'` / `gitleaks detect --log-opts=--all` (read-only); deleted files containing secrets; secrets in other branches and tags.
  - Fail: secret removed in a later commit but still in history — still compromised; remediation is rotation (history rewrite is optional hygiene and must be done by the user).
- **SEC-04 — Client bundles and mobile apps** (high)
  - Verify: frontend env exposure prefixes (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `NUXT_PUBLIC_`, `EXPO_PUBLIC_`) containing secret-class values; built `dist/`/`build/` files; source maps; mobile `strings.xml`, `Info.plist`, `google-services.json` (API key restrictions), embedded `.env` in RN/Flutter assets.
  - Fail: server secrets (DB, payment secret keys, admin tokens, OAuth client secrets) in anything shipped to clients. Publishable keys (Stripe `pk_`, Firebase web API key with restrictions) are info.
- **SEC-05 — CI/CD secrets hygiene** (high)
  - Verify: secrets stored in CI secret store, not in workflow YAML; scoped to environments with protection rules; not echoed (`set -x`, `echo $SECRET`, `env` dumps, `printenv`); not passed to untrusted PR builds (see cicd-pipelines.md); OIDC federation preferred over long-lived cloud keys.
  - Fail: plaintext secrets in pipeline files; long-lived cloud keys where OIDC is available.
- **SEC-06 — Secrets in container images and IaC** (high)
  - Verify: `ENV`/`ARG` with secrets in Dockerfiles (persist in layers/history), `COPY .env`, missing `.dockerignore`; Terraform variables defaults with secrets, `*.tfvars` committed, state files committed (`terraform.tfstate` contains plaintext secrets); K8s `Secret` manifests committed with base64 values (base64 ≠ encryption), Helm `values.yaml` with passwords.
  - Fail: any of the above; recommend BuildKit `--mount=type=secret`, Sealed Secrets/SOPS/External Secrets.
- **SEC-07 — Secrets in logs, errors and telemetry** (high)
  - Verify: logging of request headers (`Authorization`, `Cookie`), full request bodies on auth routes, connection strings in exceptions, debug dumps, APM/Sentry `sendDefaultPii`, HTTP client debug logging; redaction filters present.
  - Fail: tokens or passwords written to logs/error trackers.
- **SEC-08 — Secret storage at runtime** (medium)
  - Verify: secrets loaded from a manager (Vault, AWS Secrets Manager/SSM, GCP Secret Manager, Azure Key Vault, Doppler, 1Password Connect) or platform-injected; env vars acceptable but note exposure via `/proc`, crash dumps and child processes; file mounts with tight permissions.
  - Fail: secrets in world-readable files, in DB plaintext, or in shared config repos without encryption.
- **SEC-09 — Least privilege and scoping of credentials** (medium)
  - Verify: tokens scoped to required permissions; separate credentials per environment and per service; no personal developer tokens used by services.
  - Fail: one admin token shared across all services/environments.
- **SEC-10 — Rotation and revocation readiness** (medium)
  - Verify: documented rotation procedure, ability to run with two active versions during rotation, expiry dates on tokens, alerting on secret age.
  - Fail: secrets that cannot be rotated without downtime or code change (missing-control).
- **SEC-11 — Pre-commit and CI secret scanning** (low–medium)
  - Verify: gitleaks/trufflehog/detect-secrets pre-commit hook or CI job; GitHub push protection / GitLab secret detection enabled (ask user — not visible in repo).
  - Fail: no automated prevention (missing-control).
- **SEC-12 — Test fixtures and sample data** (low)
  - Verify: fixtures use obviously fake values (`test_`, `example`, `dummy`) and allowlist entries are justified; private keys in test dirs not reused elsewhere.
- **SEC-13 — Secrets in URLs** (medium)
  - Verify: API keys/tokens in query strings (`?api_key=`, `?token=`) — leak via logs, proxies, Referer, browser history.

## Rotation guidance to give the user (never perform it)
1. Treat any committed secret as compromised, regardless of repo visibility.
2. Revoke/rotate at the issuer first; deploy the new secret via the secret manager; confirm the old one is dead.
3. Review issuer audit logs for use of the old credential during the exposure window.
4. Then optionally purge history (`git filter-repo`) and force-push — coordinated by the user, as it rewrites history for all clones.
5. Add prevention (SEC-11) and an allowlist entry only for verified false positives.

## Common false positives
- Placeholders (`changeme`, `xxx`, `<your-key>`, `${VAR}`), documentation examples (AWS `AKIAIOSFODNN7EXAMPLE`), test keys from vendor docs.
- High-entropy strings that are hashes, UUIDs, integrity hashes (SRI, lockfile `integrity`), or public keys/certificates.
- Publishable/public client identifiers intended for browsers.

## Safe validation ideas
- Classify by format and context only (prefix, length, file purpose, environment). Do **not** call the issuer API to check validity.
- Check git metadata (`git log --format=%H,%ad -- <file>`) to establish exposure window, and whether the file is in `.gitignore` now.
- Record redacted value, type, location, first/last commit, and recommended rotation owner.
