# APIs, GraphQL, WebSockets and gRPC

Scope: API-specific weaknesses beyond the general web checks: OWASP API
Security Top 10 2023 coverage, GraphQL introspection/complexity/batching,
WebSocket handshake and message authorization, gRPC service exposure, API
inventory (versioning, shadow and zombie APIs), rate limiting and safe
consumption of third-party APIs.

**Applies when:** REST routes, OpenAPI specs, GraphQL schemas/resolvers
(Apollo, graphql-yoga, Hot Chocolate, graphene, Strawberry, gqlgen, graphql-java),
WebSocket/Socket.IO/SignalR/ActionCable handlers, `.proto` files or gRPC servers exist.

**Standards:** OWASP API1–API10:2023; A01:2021, A04:2021, A05:2021; ASVS V4 API
and Web Service, V8 Authorization; CWE-770, CWE-799, CWE-1385, CWE-284,
CWE-200, CWE-400, CWE-918, CWE-20.

## OWASP API Top 10 2023 mapping
| ID | Risk | Primary checklist items |
|----|------|------------------------|
| API1 | Broken Object Level Authorization | AUTHZ-01, AUTHZ-02, AUTHZ-12, API-03 |
| API2 | Broken Authentication | AUTHN-*, SESS-*, API-08 |
| API3 | Broken Object Property Level Authorization | AUTHZ-05, AUTHZ-06, API-03 |
| API4 | Unrestricted Resource Consumption | API-04, API-05, API-11 |
| API5 | Broken Function Level Authorization | AUTHZ-03, AUTHZ-08 |
| API6 | Unrestricted Access to Sensitive Business Flows | BIZ-*, API-11 |
| API7 | Server Side Request Forgery | SSRF-* |
| API8 | Security Misconfiguration | WEB-*, CFG-*, API-02 |
| API9 | Improper Inventory Management | API-12, API-13 |
| API10 | Unsafe Consumption of APIs | API-14 |

## Items

- **API-01 — Schema validation on every request** (medium)
  - Verify: OpenAPI/JSON Schema request validation (express-openapi-validator, FastAPI/pydantic, Spring `@Valid`), `additionalProperties: false` on writes, size and array-length limits.
  - Fail: unvalidated free-form JSON passed into business logic.
- **API-02 — GraphQL introspection and dev tooling in production** (low–medium)
  - Verify: `introspection: process.env.NODE_ENV !== 'production'`, GraphiQL/Playground/Apollo Sandbox disabled in prod, field suggestions ("Did you mean") disabled where schema secrecy matters.
  - Fail: introspection + playground enabled publicly (aids attack; not itself a vulnerability — rate as low unless schema exposes hidden admin ops).
- **API-03 — GraphQL authorization per resolver** (high) — see AUTHZ-11; also check `node`/`nodes` interfaces, union types, and federation `_entities` resolvers that bypass gateway auth.
- **API-04 — GraphQL depth, complexity and cost limits** (medium)
  - Verify: `graphql-depth-limit`, `graphql-query-complexity`, Apollo/Envelop cost plugins, Hot Chocolate cost analysis; pagination caps (`first` ≤ N); timeouts; persisted queries/allowlist for first-party clients.
  - Fail: recursive relations (`user.friends.friends...`) unbounded.
- **API-05 — GraphQL batching and aliasing abuse** (medium–high on auth ops)
  - Verify: array batching and alias multiplication limited (`login` aliased 1000× in one request bypasses per-request rate limits). Rate limit by operation cost, not HTTP request.
  - Fail: OTP/login mutations brute-forceable through aliases.
- **API-06 — GraphQL CSRF and GET mutations** (medium)
  - Verify: mutations not allowed over GET; Apollo `csrfPrevention: true`; content-type enforcement for cookie-authenticated GraphQL.
- **API-07 — WebSocket origin validation** (high with cookie auth)
  - Verify: handshake checks `Origin` against an allowlist (`verifyClient`, Socket.IO `cors.origin`, Spring `setAllowedOrigins`, ActionCable `allowed_request_origins`, gorilla `CheckOrigin` not returning `true` blindly).
  - Fail: `CheckOrigin: func(r) bool { return true }` with cookie auth → cross-site WebSocket hijacking.
- **API-08 — WebSocket authentication and per-message authorization** (high)
  - Verify: auth at handshake (token/cookie) and re-checked for channel/room subscribe and each action; token expiry honored on long-lived connections; tokens not passed in URL query if avoidable (logged).
  - Fail: any client can `join` any room ID; auth only on connect while role changes mid-session.
- **API-09 — WebSocket message handling** (medium)
  - Verify: schema validation of messages, max frame/message size, per-connection rate limits, broadcast data not echoed into DOM unsafely.
- **API-10 — gRPC exposure** (medium–high)
  - Verify: server reflection disabled in prod (`reflection.Register`), TLS/mTLS configured (no `insecure.NewCredentials()` across trust boundaries), auth interceptors on all services (unary *and* streaming), gRPC-gateway/grpc-web proxies enforce the same auth, message size limits.
  - Fail: internal admin service reachable without interceptor auth.
- **API-11 — Rate limiting and resource consumption** (medium; high on auth/costly flows)
  - Verify: per-user/per-key/per-IP limits at gateway or app; pagination maximums; upload/body size limits; timeouts; cost-heavy operations (SMS, email, AI calls, exports, report generation) quota'd. Check `X-Forwarded-For` trust configuration.
  - Fail: unbounded `limit=100000`; SMS send endpoint without limit (toll fraud).
- **API-12 — Inventory: versions, shadow and zombie APIs** (medium)
  - Verify: compare routes in code with published OpenAPI spec; old versions (`/v1`) still routed with weaker controls; debug/test/internal routes (`/test`, `/internal`, `/_debug`) deployed; staging hosts exposing prod data.
  - Fail: deprecated version lacking new authz fixes.
- **API-13 — API documentation exposure** (low)
  - Verify: Swagger UI/Redoc/spec files exposed publicly with internal endpoints or example credentials.
- **API-14 — Unsafe consumption of third-party APIs** (medium–high)
  - Verify: responses from partners/SaaS validated and treated as untrusted (schemas, size limits, timeouts, TLS verification on), redirects not blindly followed, data from them not passed to SQL/HTML/shell sinks, webhook/callback authenticity verified.
  - Fail: partner response rendered as HTML; `verify=False` on integration clients.
- **API-15 — Error and response hygiene** (low–medium)
  - Verify: consistent error format without stack traces; 404 vs 403 policy to avoid object existence leaks; no internal IDs/hostnames in responses.
- **API-16 — HTTP method and content negotiation** (low)
  - Verify: unexpected methods return 405; `TRACE` disabled; XML accepted only if intended (XXE surface); `_method` overrides disabled for APIs.

## Common false positives
- Introspection enabled on an internal-only, authenticated GraphQL endpoint.
- Lack of depth limiting when persisted-query allowlisting is enforced.
- WebSocket without origin check when auth is token-in-first-message (not cookie) — CSWSH not applicable; still validate.

## Safe validation ideas
- Diff the code route inventory against the OpenAPI spec offline — no traffic needed.
- On a local instance only: send a single GraphQL query with depth just above the configured limit and confirm rejection; never send large amplification queries to shared environments.
- CSWSH: from a local HTML page served on a different port, open a WebSocket to the local app using a seeded test session and see whether the handshake succeeds; send only `appsec-canary-<rand>` messages.
- Aliasing: one request with 3–5 aliased benign queries to confirm counting behavior, not hundreds.
