# Error handling and secure configuration

Scope: runtime configuration and failure behavior of deployed services:
debug modes, error and stack trace disclosure, default credentials and
insecure framework defaults, exposed admin/management consoles, verbose
diagnostics endpoints, feature flags guarding unfinished or privileged
functionality, environment separation, and fail-open error paths.

**Applies when:** always for deployed services; especially when framework
config files (`settings.py`, `config/environments/*.rb`, `application*.yml`,
`appsettings*.json`, `.env*`, `next.config.*`, `nuxt.config.*`, `php.ini`,
`web.config`) or server configs (nginx, Apache, IIS, Tomcat) are present.

**Standards:** OWASP A05:2021 Security Misconfiguration, A04:2021; API8:2023
Security Misconfiguration, API9:2023; ASVS V13 Configuration, V16 Security
Logging and Error Handling; CWE-209, CWE-210, CWE-215, CWE-489, CWE-497,
CWE-1188, CWE-1392, CWE-16, CWE-636, CWE-756, CWE-548.

## Items

- **CFG-01 — Debug mode off in production** (high; critical where debug consoles allow code execution)
  - Verify: Django `DEBUG = True` (or driven by env with unsafe default), Flask `debug=True`/`FLASK_DEBUG=1` (Werkzeug debugger → RCE if PIN bypassed), Rails `config.consider_all_requests_local = true` in production, Laravel `APP_DEBUG=true` (Ignition), Spring `debug=true`/devtools in prod jar, ASP.NET `UseDeveloperExceptionPage` without environment guard, `customErrors mode="Off"`, Express `NODE_ENV` not `production`, PHP `display_errors=On`, Symfony `APP_ENV=dev`, Next.js/Nuxt dev server used in prod.
  - Fail: debug enabled or defaulting to on when env var is missing.
- **CFG-02 — Errors don't leak internals** (medium)
  - Verify: global error handlers return generic messages with a correlation ID; no stack traces, SQL errors, file paths, framework versions, internal hostnames, or exception messages from DB drivers in responses; GraphQL `formatError`/`maskedErrors`, `includeStacktraceInErrorResponses: false`; gRPC status details.
  - Fail: `res.status(500).send(err.stack)`, `return str(e)`, Spring `server.error.include-stacktrace=always`.
- **CFG-03 — Fail closed** (high)
  - Verify: exceptions in authn/authz, signature checks, rate limiters, feature flag lookups and external policy calls deny by default; `try { verify() } catch { /* ignore */ }`; `except Exception: pass` around security checks; default branches in permission switches returning allow.
  - Fail: auth service timeout → request allowed.
- **CFG-04 — Default credentials and sample accounts** (critical)
  - Verify: `admin/admin`, `changeme`, `password` in seeds, configs, compose, Helm values; vendor console defaults (Tomcat manager `tomcat-users.xml`, Jenkins setup, Grafana `admin/admin`, RabbitMQ `guest/guest`, MinIO `minioadmin`, Keycloak bootstrap admin); default Django/Rails secret keys.
  - Fail: any default credential reachable in a deployed environment.
- **CFG-05 — Management and admin consoles not exposed** (high; critical if unauthenticated)
  - Verify: Spring Boot Actuator (`management.endpoints.web.exposure.include=*`, `/actuator/env`, `/heapdump`, `/jolokia`, `/gateway`), Django admin at default path without restrictions, Laravel Telescope/Horizon, Rails `/rails/info`, Flask-Admin, phpMyAdmin/Adminer, H2 console (`spring.h2.console.enabled`), Swagger UI with "try it" against prod, Prometheus `/metrics` with sensitive labels, `pprof` (`net/http/pprof` imported in main), Node `--inspect` bound to `0.0.0.0`, JMX/RMI ports, Kubernetes dashboard.
  - Fail: heap dumps or env endpoints accessible → secret disclosure; consoles with code execution reachable.
- **CFG-06 — Diagnostic and test endpoints removed** (medium)
  - Verify: routes like `/debug`, `/test`, `/phpinfo.php`, `/_status` with env dumps, `/server-status` (Apache), `/elmah.axd`, `/trace.axd`, seed/reset-database endpoints, "login as any user" dev helpers — guarded by environment checks that can't be toggled by request.
  - Fail: `if (req.query.debug)` enables extra output.
- **CFG-07 — Insecure framework defaults reviewed** (medium)
  - Verify per detected framework (see `stacks/`): Django `ALLOWED_HOSTS = ['*']`, `SECURE_*` settings, `SESSION_COOKIE_SECURE`; Rails `config.force_ssl`, `config.hosts`; Express `trust proxy` correctness, `x-powered-by`; Spring Security defaults overridden (`permitAll` broad patterns); ASP.NET `AllowedHosts: *`, `UseHsts`; Laravel `APP_KEY` set and unique; Next.js `images.remotePatterns` wildcards (SSRF/abuse), `dangerouslyAllowSVG`; PHP `allow_url_include`, `expose_php`.
  - Fail: host header poisoning via `ALLOWED_HOSTS=*`; insecure settings in production profile.
- **CFG-08 — Environment separation** (medium)
  - Verify: separate configs, credentials, and data for dev/test/staging/prod; staging not using prod databases or prod secrets; non-prod environments not publicly indexable and protected by auth; prod config is the secure default (insecure options only in explicit dev profiles).
  - Fail: missing env var falls back to dev settings in prod.
- **CFG-09 — Feature flags** (medium)
  - Verify: flags gating unreleased or admin features evaluated server-side; flag values not client-overridable (`?feature=beta`, cookies, headers); flag service credentials (LaunchDarkly server SDK key, Unleash admin tokens) not in client bundles; stale flags with dangerous branches removed; kill switches for risky features.
  - Fail: client can enable an unfinished feature that lacks authorization checks.
- **CFG-10 — Directory listing and static file exposure** (medium)
  - Verify: nginx `autoindex on`, Apache `Options Indexes`, express/static serving project root, `.git/`, `.env`, `.DS_Store`, backup files (`*.bak`, `*.old`, `*~`), `composer.json`/`package.json` in web root.
  - Fail: `/.git/config` or `/.env` downloadable.
- **CFG-11 — Version and banner disclosure** (low)
  - Verify: `Server`, `X-Powered-By`, `X-AspNet-Version`, framework error pages, `generator` meta tags; nginx `server_tokens off`.
- **CFG-12 — Resource and request limits** (medium)
  - Verify: body size, header size, request timeout, upload limits, regex timeouts (ReDoS-prone patterns on user input), connection limits configured at proxy and app.
  - Fail: catastrophic-backtracking regex (`(a+)+$`) on user input (CWE-1333).
- **CFG-13 — Secure configuration of the HTTP server/proxy** (medium)
  - Verify: proxy forwards correct client IP headers and app trusts only the proxy (`trust proxy`, `ForwardedHeadersOptions.KnownProxies`, `USE_X_FORWARDED_HOST`); HTTP methods limited; request smuggling-prone combinations (mixed proxies, old versions, `Transfer-Encoding` handling) noted.
  - Fail: `X-Forwarded-For` spoofing bypasses IP allowlists or rate limits.
- **CFG-14 — Unhandled exceptions and crash behavior** (low–medium)
  - Verify: process-level handlers (`unhandledRejection`, `uncaughtException`) log and exit/restart safely; crash dumps/core files not written to web-accessible or shared locations; panics recovered per request in Go servers without leaking state.
- **CFG-15 — Configuration validation at startup** (low)
  - Verify: app refuses to start in production with missing/weak secrets, debug flags, or insecure settings (config schema validation, e.g. pydantic-settings, envalid, `@ConfigurationProperties` + `@Validated`).
  - Fail: silent fallback to defaults (missing-control).

## Common false positives
- `DEBUG = True` in `settings/dev.py` or test configs not used by deployment manifests — verify which settings module production loads.
- Actuator `health`/`info` exposed with no sensitive details.
- Verbose errors on internal-only tooling behind SSO (lower severity).
- `/metrics` restricted to the cluster network by NetworkPolicy.

## Safe validation ideas
- Determine effective production config statically: trace env var defaults through Dockerfile, Helm values, IaC and CI deploy steps.
- On a local instance in production mode: trigger a handled error with input `appsec-canary-<rand>` (e.g. malformed JSON) and confirm the response is generic and the log has the detail.
- For exposed endpoints on in-scope staging: a single GET to `/actuator` or `/.git/HEAD`-style paths only with user approval; never download heap dumps or env contents — stop at status code and record.
