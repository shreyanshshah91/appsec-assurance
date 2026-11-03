# Manual review checklists

These checklists drive Phase 5 (manual secure-code and configuration review) of
the AppSec Assurance workflow. Scanners find patterns; these checklists make the
reviewer trace data flows, look for **missing controls**, and record explicitly
what was and was not assessed.

## How to choose checklists

Use `stack.json` and `inventory.json` from the scan output. A checklist applies
when its trigger signal is present. When in doubt, apply it — an `n/a` with a
reason is cheap; a silently skipped domain is a coverage gap.

| File | Domain | Applies when (trigger) | Mapped standards |
|------|--------|------------------------|------------------|
| [injection.md](injection.md) | SQL/NoSQL/OS/LDAP/XPath/SSTI/CRLF/log/EL injection | Any DB access, shell exec, template engine, LDAP/XML libs in inventory | A03; API8; ASVS V1 Encoding and Sanitization; CWE-89, 78, 943, 90, 643, 1336, 113, 117, 917 |
| [xss-and-output-encoding.md](xss-and-output-encoding.md) | XSS, output encoding, sanitizers | Server-rendered HTML, SPA framework, markdown/rich-text rendering | A03; ASVS V1, V3 Web Frontend Security; CWE-79, 80, 83 |
| [csrf-cors-headers-csp.md](csrf-cors-headers-csp.md) | CSRF, CORS, CSP, security headers, caching | Any HTTP service consumed by browsers; cookie auth; CORS middleware | A01, A05; API8; ASVS V3; CWE-352, 942, 1021, 693, 525 |
| [ssrf-and-outbound.md](ssrf-and-outbound.md) | SSRF, webhooks, outbound fetches | Outbound HTTP clients, webhook config, URL preview, PDF/image renderers | A10; API7; ASVS V1, V13 Configuration; CWE-918, 601 |
| [authentication.md](authentication.md) | Login, passwords, MFA, reset, SSO | Auth code, user model, login/register routes | A07, A04; API2; ASVS V6 Authentication; CWE-287, 307, 521, 640, 916, 204 |
| [session-jwt-oauth.md](session-jwt-oauth.md) | Sessions, cookies, JWT, OAuth/OIDC | Session middleware, JWT libs, OAuth/OIDC client or server | A07, A02; API2; ASVS V7 Session Management, V9 Self-contained Tokens, V10 OAuth and OIDC; CWE-384, 613, 347, 614, 1004 |
| [authorization.md](authorization.md) | BOLA/IDOR, BFLA, mass assignment, tenancy | Any authenticated route, resolver, or multi-user data | A01; API1, API3, API5; ASVS V8 Authorization; CWE-639, 285, 862, 863, 915, 269 |
| [api-graphql-websocket.md](api-graphql-websocket.md) | REST/GraphQL/WebSocket/gRPC APIs | Routes, GraphQL schema, WS handlers, .proto files | API1–API10; A01, A04, A05; ASVS V4 API and Web Service; CWE-770, 1385, 799 |
| [file-handling-and-path-traversal.md](file-handling-and-path-traversal.md) | Uploads, archives, path traversal, serving files | Upload handlers, filesystem access with request data, archive libs | A01, A04; ASVS V5 File Handling; CWE-22, 434, 59, 400, 409 |
| [deserialization-and-parsers.md](deserialization-and-parsers.md) | Deserialization, XXE, prototype pollution | pickle/ObjectInputStream/BinaryFormatter/unserialize/yaml.load, XML parsers, deep merge | A08, A05; ASVS V1, V15 Secure Coding and Architecture; CWE-502, 611, 1321, 776 |
| [cryptography-and-tls.md](cryptography-and-tls.md) | Algorithms, randomness, keys, TLS | Crypto imports, TLS config, token generation, cert handling | A02; ASVS V11 Cryptography, V12 Secure Communication; CWE-327, 326, 330, 338, 295, 329, 323 |
| [secrets-management.md](secrets-management.md) | Hardcoded secrets, env files, CI secrets | Always | A02, A07; ASVS V13; CWE-798, 259, 312, 532, 540 |
| [business-logic-and-race-conditions.md](business-logic-and-race-conditions.md) | Workflows, races, numeric abuse | Payments, carts, credits, quotas, multi-step flows, invites | A04; API6; ASVS V2 Validation and Business Logic; CWE-362, 367, 840, 841, 190, 20 |
| [database-security.md](database-security.md) | DB privilege, exposure, RLS, backups | Any data store, migrations, connection strings | A05, A02, A01; ASVS V13, V14 Data Protection; CWE-250, 1188, 311, 284 |
| [supply-chain-and-malware.md](supply-chain-and-malware.md) | Dependencies, install scripts, malicious code, provenance | Always (any manifest/lockfile) | A06, A08; ASVS V15; CWE-1104, 1357, 494, 506, 829, 1395 |
| [containers-and-kubernetes.md](containers-and-kubernetes.md) | Dockerfile, K8s manifests, Helm | Dockerfile, compose, K8s YAML, Chart.yaml | A05; ASVS V13; CWE-250, 269, 732, 1188 |
| [cloud-and-iac.md](cloud-and-iac.md) | Terraform/CFN/Bicep/Pulumi | `*.tf`, CFN templates, `*.bicep`, Pulumi programs | A05, A01, A02, A09; CWE-284, 732, 311, 778 |
| [cicd-pipelines.md](cicd-pipelines.md) | GitHub Actions, GitLab CI, Jenkins | `.github/workflows`, `.gitlab-ci.yml`, Jenkinsfile, other CI config | A08, A05; ASVS V15; CWE-78, 829, 494, 250 |
| [logging-monitoring-and-audit.md](logging-monitoring-and-audit.md) | Security logging, audit trails, alerting | Always for services; logging libs | A09; ASVS V16 Security Logging and Error Handling; CWE-778, 117, 532, 223 |
| [privacy-and-data-protection.md](privacy-and-data-protection.md) | PII, retention, backups, DR, residency | Any personal data, backups, analytics SDKs | A02, A04; API3; ASVS V14 Data Protection; CWE-359, 200, 312, 212 |
| [frontend-and-client.md](frontend-and-client.md) | Browser-side security | SPA/SSR frontend, bundler config, third-party scripts | A01, A05, A08; ASVS V3; CWE-922, 601, 1021, 829, 345 |
| [mobile.md](mobile.md) | Android/iOS apps | AndroidManifest.xml, Info.plist, React Native/Flutter/Kotlin/Swift | OWASP MASVS; A02, A05, A07; CWE-926, 319, 749, 312, 295 |
| [error-handling-and-config.md](error-handling-and-config.md) | Debug modes, errors, defaults | Always for deployed services | A05; ASVS V13, V16; CWE-209, 489, 1188, 1392, 215 |

## Item ID scheme

Each item has a stable ID `<PREFIX>-<NN>` (e.g. `INJ-03`, `AUTHZ-07`). IDs are
never renumbered or reused; retired items are marked *(retired)* and new items
are appended. Reference the ID in findings (`checklist_refs`) and in the
checklist results section of `.appsec/manual-findings.json` so coverage can be
diffed across runs.

Prefixes: INJ, XSS, WEB, SSRF, AUTHN, SESS, AUTHZ, API, FILE, DESER, CRYPTO,
SEC, BIZ, DB, SC, CTR, CLOUD, CICD, LOG, PRIV, FE, MOB, CFG.

## Recording convention

For every applicable item record exactly one result:

| Result | Meaning | Required note |
|--------|---------|---------------|
| `pass` | Control present and verified in code/config | Where it is enforced (file:line) |
| `fail` | Weakness or missing control observed | Becomes a finding (see below) |
| `n/a` | Item cannot apply to this system | Why (e.g. "no XML parsing anywhere; grep for parsers returned none") |
| `untested` | Applies but was not assessed | Why (time, no access, needs runtime) — appears in report limitations |

Every `fail` becomes a finding with one of these statuses:

- `confirmed` — source→sink path or misconfiguration proven with file:line and, where approved, safe reproduction.
- `suspected` — strong indicators but a link in the chain is unverified (e.g. unclear whether input is user-controlled).
- `missing-control` — an expected defense is absent (no rate limit, no audit log, no CSP) even without a demonstrated exploit.

Severity in each item is a **default**; adjust for reachability, authentication
required, data sensitivity and compensating controls, and justify the change.
`untested` is never equivalent to `pass`.

## Safe validation baseline (applies to every checklist)

- Static proof first; unit-level proof in a scratch directory second; runtime
  proof only in `deep` mode, in scope, with user approval.
- Use benign unique markers: `appsec-canary-<random>`.
- No destructive payloads, no DoS or load, no brute force, no third-party
  targets, never use discovered credentials.
