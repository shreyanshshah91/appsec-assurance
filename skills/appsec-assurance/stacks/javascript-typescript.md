# JavaScript / TypeScript (Node, Express, NestJS, Next.js, front-end frameworks)

**Detector keys:** `javascript`, `typescript`, `express`, `nestjs`, `nextjs`, `react`, `vue`, `angular`, `svelte`, `graphql` (Node servers), `react-native` (JS layer)

## Untrusted input sources

- Express: `req.query` (can be nested objects/arrays via `qs`), `req.body`, `req.params`, `req.headers`, `req.cookies`, `req.files`, `req.ip` behind a misconfigured `trust proxy`.
- NestJS: `@Body()`, `@Query()`, `@Param()`, `@Headers()`, `@UploadedFile()`, GraphQL `@Args()`, WebSocket `@MessageBody()`.
- Next.js: route handler `request` (`nextUrl.searchParams`, `json()`, `formData()`), page `params`/`searchParams`, **Server Action arguments** (callable by anyone via POST, regardless of UI), `cookies()`, `headers()`, middleware `NextRequest`.
- Browser: `location.*`, `document.referrer`, `postMessage` data, `localStorage`, URL fragments, `window.name`, third-party script data.
- GraphQL args, WebSocket/Socket.IO messages, queue payloads, webhooks, `process.argv`.

## Dangerous sinks

| Sink | Vulnerability class | CWE | Safe alternative |
|------|--------------------|-----|------------------|
| `child_process.exec/execSync`, `spawn(..., {shell:true})` | OS command injection | CWE-78 | `execFile`/`spawn` with arg array, no shell |
| `eval`, `new Function`, `setTimeout(string)`, `vm.runIn*Context` | Code injection | CWE-95 | JSON.parse, explicit dispatch maps; `vm` is **not** a sandbox |
| `prisma.$queryRawUnsafe`, `$executeRawUnsafe`, `Prisma.raw()` | SQL injection | CWE-89 | `` prisma.$queryRaw`... ${x}` `` (tagged template), `Prisma.sql` |
| `sequelize.query(str)` with interpolation, `Sequelize.literal()` | SQL injection | CWE-89 | `replacements`/`bind` options |
| `knex.raw(str)`, `whereRaw` with interpolation | SQL injection | CWE-89 | `knex.raw("?", [x])`, `??` for identifiers |
| TypeORM `query()`, `createQueryBuilder().where(\`...${x}\`)` | SQL injection | CWE-89 | `.where("id = :id", { id })` |
| Mongoose/MongoDB `find(req.body)`, `$where`, `$expr` from input | NoSQL injection | CWE-943 | Cast to primitives, `mongo-sanitize`/`sanitizeFilter: true`, schema validation |
| `_.merge`, `_.set`, `Object.assign` deep, custom recursive merge of input | Prototype pollution | CWE-1321 | Reject `__proto__`/`constructor`/`prototype`; `Object.create(null)`; `Map` |
| `res.send(userHtml)`, template `<%- %>` (EJS), `{{{ }}}` (Handlebars), `!=` (Pug) | XSS | CWE-79 | Escaped interpolation; DOMPurify for rich HTML |
| `dangerouslySetInnerHTML`, `v-html`, `[innerHTML]` + `bypassSecurityTrustHtml`, Svelte `{@html}`, `innerHTML`, `document.write` | DOM XSS | CWE-79 | Framework escaping; DOMPurify; Trusted Types |
| `href={userUrl}` (`javascript:` URLs) | XSS | CWE-79 | Allowlist `https:`/`mailto:` schemes |
| `fetch/axios/got(userUrl)` server-side | SSRF | CWE-918 | Host allowlist, block private IPs post-resolution, disable redirects |
| `res.sendFile/fs.readFile(path.join(base, input))` | Path traversal | CWE-22 | `path.resolve` then prefix check; `root` option of `sendFile` |
| `res.redirect(req.query.next)` | Open redirect | CWE-601 | Relative-path allowlist |
| `jwt.verify(t, key)` without `algorithms`; `jwt.decode` used for auth | Auth bypass | CWE-347 | `jwt.verify(t, key, { algorithms:["RS256"], audience, issuer })`; `jose.jwtVerify` |
| `new RegExp(input)`, catastrophic regex on input | ReDoS | CWE-1333 | Escape input; linear-time engines (`re2`); length limits |
| `Math.random()` for tokens | Weak PRNG | CWE-338 | `crypto.randomBytes`, `crypto.randomUUID` |
| `node-serialize.unserialize`, `serialize-javascript` output eval'd, `js-yaml` < 4 `load` | Unsafe deserialization | CWE-502 | JSON + schema (zod/ajv) |
| `rejectUnauthorized:false`, `NODE_TLS_REJECT_UNAUTHORIZED=0` | Improper cert validation | CWE-295 | Default TLS; custom `ca` |

## Framework pitfalls and insecure defaults

- **Express:** no security headers by default (use `helmet`); `x-powered-by` enabled; no CSRF protection (`csurf` is deprecated — use SameSite cookies + a maintained token library such as `csrf-csrf`); `cors({ origin: true, credentials: true })` reflects any origin; `express.static` serving the project root or dotfiles; error handler leaking stacks when `NODE_ENV` ≠ `production`; `app.set("trust proxy", true)` makes `req.ip` spoofable, breaking rate limits; `express-session` with `MemoryStore` or default secret; body parser without size limits.
- **Query-parser type confusion:** `?id[$ne]=x` or `?role[]=a` yields objects/arrays; validate with zod/joi/class-validator before use.
- **NestJS:** guards are not global unless registered with `APP_GUARD`; a `@Public()` decorator pattern means every new route is protected only if the global guard reflects metadata correctly; `ValidationPipe` needs `whitelist: true, forbidNonWhitelisted: true` to stop mass assignment; `transform: true` with implicit conversion can surprise.
- **Next.js:** middleware `config.matcher` that omits paths (API routes, `/_next/data`, trailing slash/locale variants, new route groups) leaves them unauthenticated — authorize in each route handler/Server Action/data-access layer, never only in middleware (cf. CVE-2025-29927 `x-middleware-subrequest` bypass; ensure patched version). **Server Actions** are public POST endpoints: re-check session and ownership inside every action and validate arguments. Closed-over variables in actions are encrypted but still client-round-tripped; do not rely on them for authz. Avoid leaking secrets via `NEXT_PUBLIC_*` env vars or props passed to Client Components; use `server-only` and React taint APIs. `next/image` `remotePatterns` wildcard → SSRF/proxy abuse. `rewrites` to internal hosts.
- **React:** escaped by default; risk is `dangerouslySetInnerHTML`, `href`/`src` with `javascript:`, SSR `JSON.stringify` of state into `<script>` without escaping `</script>`.
- **Vue:** `v-html`, runtime-compiled templates from user input (`template:` string) = full XSS/template injection; Nuxt `useState` serializing secrets.
- **Angular:** sanitizes by default; `bypassSecurityTrust*`, `ElementRef.nativeElement.innerHTML`, `Renderer2.setProperty(..., 'innerHTML')` bypass it; JIT-compiling user templates.
- **Svelte/SvelteKit:** `{@html}`; `+server.js` endpoints and form actions need their own auth; `csrf.checkOrigin` should stay enabled.
- **Supply chain:** `preinstall`/`install`/`postinstall` scripts run on `npm install` — review new ones, use `npm ci --ignore-scripts` in CI where feasible, commit lockfiles, watch for typosquats and dependency confusion on scoped/internal names (`.npmrc` registry mapping).
- **GraphQL (Apollo/Yoga/Mercurius):** introspection on in prod, no depth/complexity limits, batching enables brute force, resolver-level authz missing on nested fields.

## Authn/authz idioms to verify

- Express: middleware order (`app.use(auth)` must precede routers it protects; routers mounted earlier stay public); per-route `requireRole` on admin routes; ownership check after loading each resource.
- NestJS: `@UseGuards(AuthGuard('jwt'), RolesGuard)`, global `APP_GUARD`, `@Roles()` metadata read via `Reflector`; resolvers with `@UseGuards` too.
- Next.js: `auth()`/`getServerSession()` inside route handlers, Server Components that fetch data, and every Server Action; Auth.js `callbacks.authorized` only covers middleware-matched paths.
- Passport strategies: verify callback rejects unknown users; `session: false` for APIs; state parameter on OAuth.
- JWT: algorithm pinning, `exp`/`nbf`/`aud`/`iss` checks, key rotation via JWKS (`jose.createRemoteJWKSet`), no `none` algorithm, no secrets in client bundles.
- Cookies: `httpOnly`, `secure`, `sameSite`, `__Host-` prefix for session cookies.

## Useful grep patterns

```bash
rg -n 'child_process|\bexec(Sync)?\(|spawn\([^)]*shell:\s*true'
rg -n '\beval\(|new Function\(|vm\.(runIn|Script|compileFunction)|setTimeout\(\s*["\x27`]'
rg -n '\$(query|execute)RawUnsafe|Prisma\.raw\(|sequelize\.query\(|Sequelize\.literal\(|\.(raw|whereRaw|orderByRaw)\(\s*`|\.query\(\s*`'
rg -n '\.(find|findOne|updateOne|deleteMany|aggregate)\(\s*req\.(body|query)|\$where'
rg -n '__proto__|_\.(merge|set|defaultsDeep|setWith)\(|Object\.assign\(\s*\{\}\s*,\s*req'
rg -n 'dangerouslySetInnerHTML|v-html|bypassSecurityTrust|\{@html|\.innerHTML\s*=|document\.write\('
rg -n 'jwt\.(verify|decode)\(|algorithms\s*:|ignoreExpiration'
rg -n 'rejectUnauthorized:\s*false|NODE_TLS_REJECT_UNAUTHORIZED|Math\.random\(\)'
rg -n '"use server"|export const config\s*=\s*\{[^}]*matcher' --type-add 'web:*.{js,jsx,ts,tsx,mjs,cjs}' -t web
rg -n '"(pre|post)?install"\s*:' -g 'package.json'
rg -n 'cors\(\{[^}]*origin:\s*(true|["\x27]\*)|res\.redirect\(\s*req\.'
```

## Recommended tools

- Semgrep (`p/javascript`, `p/typescript`, `p/react`, `p/nextjs`, `p/express`, `p/nodejsscan`), eslint-plugin-security, eslint-plugin-no-unsanitized, `npm audit` / `pnpm audit` / `yarn npm audit`, OSV-Scanner, retire.js (front-end bundles), Gitleaks, CodeQL (where licence permits), `lockfile-lint`.

## Secure code patterns

```ts
// Vulnerable: Prisma raw SQL
await prisma.$queryRawUnsafe(`SELECT * FROM "User" WHERE email = '${email}'`);
// Fixed
await prisma.$queryRaw`SELECT * FROM "User" WHERE email = ${email}`;

// Vulnerable: Mongoose operator injection  ({"password":{"$ne":null}})
await User.findOne({ email: req.body.email, password: req.body.password });
// Fixed
const { email, password } = z.object({ email: z.string().email(), password: z.string() }).parse(req.body);
const user = await User.findOne({ email }); // then bcrypt.compare(password, user.hash)

// Vulnerable: Server Action without authz
"use server";
export async function deletePost(id: string) { await db.post.delete({ where: { id } }); }
// Fixed
"use server";
export async function deletePost(id: string) {
  const session = await auth(); if (!session) throw new Error("unauthorized");
  await db.post.delete({ where: { id: z.string().uuid().parse(id), authorId: session.user.id } });
}

// Vulnerable: command injection
exec(`git log ${branch}`);
// Fixed
execFile("git", ["log", "--", branch]);

// Vulnerable: prototype pollution
function merge(t, s) { for (const k in s) typeof s[k] === "object" ? merge(t[k] ??= {}, s[k]) : (t[k] = s[k]); }
// Fixed: skip dangerous keys and own-property check
for (const k of Object.keys(s)) { if (k === "__proto__" || k === "constructor" || k === "prototype") continue; /* ... */ }
```
