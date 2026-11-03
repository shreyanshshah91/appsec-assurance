# Authorization

Scope: enforcement of who may do what to which object: object-level (BOLA/IDOR),
function-level (BFLA), property-level (mass assignment and excessive data
exposure), tenant isolation, admin surfaces, default-deny, server-side
enforcement and privilege escalation, including GraphQL resolvers and background
jobs. This is the highest-priority manual review area: trace from route to data
access; do not trust middleware names or decorators you haven't read.

**Applies when:** any authenticated route, resolver, RPC or job touches data
owned by a user, organization or tenant, or roles/permissions exist.

**Standards:** OWASP A01:2021 Broken Access Control; API1:2023 BOLA, API3:2023
Broken Object Property Level Authorization, API5:2023 BFLA; ASVS V8
Authorization; CWE-285, CWE-639, CWE-862, CWE-863, CWE-915, CWE-269, CWE-284,
CWE-425, CWE-566, CWE-213.

## Method
Build a route × role matrix from the inventory. For each route: identify the
authn check, the authz check (role/permission), the object ownership/tenant
check, and the fields read/written. Absence of any column for a sensitive route
is a finding candidate.

## Items

- **AUTHZ-01 — Object ownership checked on every object access (BOLA/IDOR)** (high; critical for PII/financial or cross-tenant)
  - Verify: handlers taking `:id`, `?id=`, body IDs, GraphQL `id` args. Look for queries scoped by owner/tenant (`where(user_id: current_user.id)`, `Model.objects.filter(owner=request.user)`, policy calls like Pundit `authorize`, CanCanCan `load_and_authorize_resource`, Spring `@PreAuthorize` with object expression, OPA/Cedar/Casbin checks). Watch for `findById(req.params.id)` followed by no comparison.
  - Fail: lookup by ID alone; check performed after the data is already returned or side effect done.
- **AUTHZ-02 — Writes, deletes and nested resources** (high)
  - Verify: update/delete endpoints and nested routes (`/orgs/:org/projects/:p`) verify that `:p` belongs to `:org` *and* the user belongs to `:org`.
  - Fail: parent checked, child not (`/orgs/mine/projects/theirs`).
- **AUTHZ-03 — Function-level authorization (BFLA)** (high)
  - Verify: admin/staff/internal endpoints enforce roles server-side; HTTP method variants (`PUT` vs `PATCH`, `DELETE`) all protected; same controller exposed under multiple routes/versions.
  - Fail: role checked in UI only; `/api/v1/admin/*` protected but `/api/v2/admin/*` not; `X-HTTP-Method-Override` bypass.
- **AUTHZ-04 — Default deny** (high)
  - Verify: global policy denies unless explicitly allowed (Spring `anyRequest().authenticated()`/`denyAll()`, ASP.NET fallback policy, NestJS global guard, Django REST `DEFAULT_PERMISSION_CLASSES`). New routes must opt *out*, not in.
  - Fail: `AllowAny` default; permission decorators per route with gaps.
- **AUTHZ-05 — Mass assignment / over-posting** (high; critical if role/tenant fields)
  - Verify: ORM create/update from raw request: `Model.create(req.body)`, `update(**request.data)`, `params.permit!`, `attr_accessible` absent, `@ModelAttribute` binding entities, `TryUpdateModelAsync` without include list, Mongoose `new Model(req.body)`. Look for DTOs/serializers with explicit allowed fields.
  - Fail: user can set `role`, `is_admin`, `tenant_id`, `owner_id`, `balance`, `email_verified`, `price`.
- **AUTHZ-06 — Excessive data exposure (property-level read)** (medium–high)
  - Verify: serializers returning full entities (`res.json(user)`, `to_json` without `only`), password hashes, tokens, internal flags, other users' emails in list endpoints; GraphQL types exposing sensitive fields.
  - Fail: client-side filtering of fields the API returns.
- **AUTHZ-07 — Multi-tenant isolation** (critical)
  - Verify: tenant ID derived from authenticated context, never from request body/header alone; every query scoped (ORM default scopes, Hibernate filters, Postgres RLS with `SET app.tenant_id`, separate schemas); caches, search indexes, file storage prefixes, queues and analytics also tenant-keyed.
  - Fail: `X-Tenant-Id` header trusted; cache key without tenant; S3 key `uploads/<file>` shared across tenants.
- **AUTHZ-08 — Admin and internal surfaces** (high)
  - Verify: Django admin, Rails admin, Spring Actuator, Laravel Telescope/Horizon, Flower, Sidekiq Web, Bull Board, Swagger UI, GraphiQL, Kibana links — authenticated, role-restricted, ideally network-restricted.
  - Fail: reachable without admin role or exposed to internet unauthenticated.
- **AUTHZ-09 — Privilege escalation paths** (critical)
  - Verify: role change, invite, user creation, permission grant and API-key scope endpoints prevent granting more than the actor holds; self-approval blocked; org owner transfer protected.
  - Fail: member can invite as admin; user can edit own role via profile update.
- **AUTHZ-10 — Server-side enforcement only** (high)
  - Verify: no reliance on hidden fields, disabled buttons, client route guards, JWT claims the client can set, or `isAdmin` in localStorage.
  - Fail: authorization decision made from client-supplied flags.
- **AUTHZ-11 — GraphQL field- and resolver-level authorization** (high)
  - Verify: authz in resolvers or a directive/shield layer (`graphql-shield`, `@auth` directives, Pothos scope auth) for every type and field, including nested relations (`user { orders { ... } }`), node/`node(id:)` global lookups, mutations, and subscriptions.
  - Fail: only top-level query protected; `node(id)` returns any object.
- **AUTHZ-12 — Indirect object access** (medium–high)
  - Verify: exports, reports, search, autocomplete, file download URLs, signed URL generation, webhooks and notification preferences referencing other users' objects; predictable IDs (sequential ints) increase impact. UUIDs are not authorization.
  - Fail: `/export?account=123` exports anyone's data.
- **AUTHZ-13 — Background jobs, queues and event consumers** (medium)
  - Verify: jobs enqueued with user-provided IDs re-check permissions at execution time, or carry the authorized principal.
  - Fail: worker trusts job payload object IDs from an API that didn't verify them.
- **AUTHZ-14 — Authorization decision consistency** (medium)
  - Verify: one policy engine/module, not ad-hoc checks scattered; tests exist for negative cases (user A cannot access B's resource).
  - Fail: no negative authz tests (missing-control, low/medium).
- **AUTHZ-15 — Path and method normalization bypasses** (medium)
  - Verify: authz middleware matching paths by string/regex vs router normalization (trailing slash, case, `%2e`, `;jsessionid`, double slashes); reverse proxy path rules vs app routing.
  - Fail: `/admin/` blocked but `/Admin` or `/admin;x` routed.
- **AUTHZ-16 — Ownership-changing state** (medium)
  - Verify: after removal from org/team, revoked access is enforced immediately (cached permissions, long-lived tokens carrying roles).
  - Fail: removed member's JWT with `role: admin` valid for days.

## Common false positives
- Public-by-design resources (published posts, public profiles) — confirm intent in docs/product.
- Ownership enforced by a query scope defined elsewhere (default scope, RLS) — read it before reporting.
- Admin endpoints reachable only on an internal network with SSO at the proxy — downgrade, still note defense in depth.

## Safe validation ideas
- Create two seeded test users (and two tenants) in a local/dev instance; attempt cross-access to user B's resource with user A's session and record status codes. Use only data you created (`appsec-canary-<rand>` names).
- Mass assignment: on a local instance, include `"role":"appsec-canary"` or `"is_admin":true` on your own test account's profile update and check whether persisted; revert afterwards.
- Write a throwaway integration test asserting 403/404 for cross-user access; it doubles as the regression test.
