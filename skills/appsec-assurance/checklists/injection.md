# Injection

Scope: every place where untrusted data is concatenated into an interpreter's
command or query language — SQL, NoSQL query objects, shell, LDAP filters,
XPath, server-side templates, HTTP headers, log lines, expression languages and
ORM escape hatches. Trace each sink back to its sources (request params, body,
headers, cookies, path segments, queue messages, webhook payloads, file
contents, DB values written earlier by users = second-order).

**Applies when:** inventory shows DB access, ORM usage, `exec`/`spawn`/`system`,
template engines, LDAP/XML/XPath libraries, or header/log writes with request data.

**Standards:** OWASP A03:2021 Injection; API8:2023 (misconfiguration enabling
injection) and API10:2023 when third-party data reaches sinks; ASVS V1 Encoding
and Sanitization, V2 Validation and Business Logic; CWE-89, CWE-943, CWE-78,
CWE-77, CWE-88, CWE-90, CWE-643, CWE-1336, CWE-94, CWE-113, CWE-93, CWE-117, CWE-917.

## Items

- **INJ-01 — SQL built by string concatenation/interpolation** (default: critical if pre-auth/reachable, high otherwise)
  - Verify: grep `execute\(.*(\+|%|f"|\.format\(|\$\{)`, `query\(\s*\``, `"SELECT .*" \+`, `String.format\(.*SELECT`, `Sprintf\(.*(SELECT|WHERE)`, `cursor.execute(f"`. Confirm the interpolated value is attacker-influenced.
  - Fail: any user-derived value placed in SQL text instead of a bound parameter.
- **INJ-02 — ORM raw-query escape hatches** (high)
  - Verify: `.raw(`, `.extra(`, `RawSQL`, `text(` (SQLAlchemy) with f-strings, `Sequelize.literal`, `sequelize.query(` without `replacements`/`bind`, `$queryRawUnsafe`/`$executeRawUnsafe` (Prisma), `whereRaw`/`orderByRaw`/`DB::raw` (Laravel/Knex), `find_by_sql`, `where("... #{`)` (Rails), `createNativeQuery`/`createQuery` with `+` (JPA/HQL).
  - Fail: interpolation inside raw fragments; tagged-template helpers (`$queryRaw\`...\``, `sql\`...\``) are safe only when used as tagged templates, not as function calls on a prebuilt string.
- **INJ-03 — Identifiers and keywords from input** (high)
  - Verify: dynamic `ORDER BY`, column names, table names, `ASC/DESC`, `LIMIT` built from params. These cannot be bound — look for an allowlist map.
  - Fail: `order_by(request.args['sort'])` or `"ORDER BY " + sort` with no allowlist.
- **INJ-04 — Second-order SQL** (high)
  - Verify: values read from DB/cache/files that originated from users and are later concatenated into queries (reports, admin search, stored filters).
  - Fail: "trusted because it came from our DB" reasoning.
- **INJ-05 — NoSQL operator injection** (high)
  - Verify: Mongo `find(req.body)`, `findOne({user: req.body.user})` where body is JSON and can carry `{"$ne": null}`; `$where`, `$function`, `mapReduce` with strings; Express `qs` parsing `a[$gt]=`. Check for `mongo-sanitize`, schema casting (Mongoose `strictQuery`, `sanitizeFilter`), or explicit `typeof x === 'string'`.
  - Fail: request objects passed directly as query filters; JS evaluated server-side from input.
- **INJ-06 — OS command injection** (critical)
  - Verify: `os.system`, `subprocess.*(..., shell=True)`, `popen`, backticks, `child_process.exec`/`execSync`, `Runtime.exec(String)`, `ProcessBuilder("sh","-c",...)`, `exec.Command("sh","-c",...)`, PHP `system/passthru/shell_exec/proc_open`, Ruby `` `...` ``/`%x`/`system(string)`.
  - Fail: user data in a shell string. Prefer argv arrays without a shell.
- **INJ-07 — Argument injection** (high)
  - Verify: argv-array calls where a user value can begin with `-` (e.g. `git`, `curl`, `tar`, `ffmpeg`, `convert`, `ssh`, `rsync`). Look for `--` end-of-options separator and value validation.
  - Fail: `["git","clone", userUrl]` allowing `--upload-pack=...`; `["curl", url]` allowing `-o`.
- **INJ-08 — LDAP injection** (high)
  - Verify: filters built with `"(uid=" + user + ")"`; DN construction from input. Look for RFC 4515 filter escaping (`ldap.filter.escape_filter_chars`, `LdapEncoder.filterEncode`, `ldap_escape`).
  - Fail: unescaped `*`, `(`, `)`, `\`, NUL in filters; auth bypass via `*)(uid=*`.
- **INJ-09 — XPath / XQuery injection** (high)
  - Verify: `xpath(` / `selectNodes(` / `evaluate(` with concatenated strings. Look for parameterized XPath (variable resolvers) or strict allowlists.
  - Fail: user input inside quoted XPath literals.
- **INJ-10 — Server-side template injection (SSTI)** (critical)
  - Verify: user input used as the *template source*: `render_template_string(user)`, `Template(user).render`, `Environment().from_string`, `ejs.render(userTemplate)`, `Handlebars.compile(user)`, `new Function`, Velocity/Freemarker/Thymeleaf with user-built template names or `__${...}__` preprocessing, Twig `createTemplate`. Check for sandboxed environments and whether "custom email templates" features exist.
  - Fail: any attacker-controlled template text rendered by a non-sandboxed, logic-capable engine.
- **INJ-11 — Expression language / dynamic evaluation** (critical)
  - Verify: SpEL `parseExpression(` with input, OGNL, MVEL, JEXL, JSF EL, `eval`, `exec`, `Function(`, `vm.runInNewContext` (not a sandbox), `ScriptEngine.eval`, Python `eval(`/`exec(`, `ast.literal_eval` is fine.
  - Fail: evaluation of user strings; `vm`/`vm2` used as a security boundary.
- **INJ-12 — HTTP header / CRLF injection and response splitting** (medium)
  - Verify: `setHeader`, `res.header`, `Response.headers[...]`, `Location`, `Set-Cookie`, `Content-Disposition` filename built from input; SMTP headers (`To`, `Subject`) from input.
  - Fail: no rejection of `\r`/`\n`; framework does not already block it (modern Node/Java/Go reject CRLF in header values — confirm version).
- **INJ-13 — Email header and SMTP injection** (medium)
  - Verify: raw SMTP construction or mail libraries fed user-controlled `from`/`subject`/`cc`.
  - Fail: additional recipients injectable; contact forms usable as spam relays.
- **INJ-14 — Log injection / forging** (low–medium)
  - Verify: request values logged with string formatting into line-based logs; log viewers that render HTML. Look for structured logging (JSON) or newline escaping.
  - Fail: forged log lines via `%0a`; stored XSS in log dashboards. (Log4Shell-style lookups: check Log4j 2 version and `formatMsgNoLookups`.)
- **INJ-15 — Input validation strategy** (medium)
  - Verify: schema validation at boundaries (pydantic, zod, Joi, Bean Validation, JSON Schema), type coercion, length limits. Validation is defense-in-depth, not a substitute for parameterization.
  - Fail: denylist filtering (stripping `'` or `<script`) used as the primary control.
- **INJ-16 — GraphQL / search DSL passthrough** (high)
  - Verify: user strings passed into Elasticsearch `query_string`, Lucene syntax, Solr `q`, Cypher/Gremlin/SPARQL built by concatenation.
  - Fail: query DSL injection exposing other tenants' docs or scripts (`script` fields in ES).
- **INJ-17 — Stored procedures and dynamic SQL inside the DB** (medium)
  - Verify: `EXEC(@sql)`, `EXECUTE IMMEDIATE`, `sp_executesql` with concatenation inside procedures/migrations.
  - Fail: parameterized call into a procedure that itself concatenates.

## Common false positives
- Concatenation of constant fragments or allowlisted identifiers only.
- Tagged templates (`sql\`\``, Prisma `$queryRaw\`\``, slonik) — these bind values.
- `subprocess.run([...])` with a fixed binary and validated, `--`-separated args.
- Template *variables* rendered by auto-escaping engines (that is an XSS question, not SSTI).
- Values that are strictly typed integers after parsing (`int(x)`) before reaching SQL.

## Safe validation ideas
- Unit-test the sink with `appsec-canary-<rand>'` and assert the query text sent to a mocked driver contains the quote (proves concatenation) — no live DB needed.
- For SQL against a disposable local DB: compare `id=1` vs `id=1 AND 1=1` vs `id=1 AND 1=2` responses; never use `DROP`, `UPDATE`, `SLEEP`/time-based payloads, or stacked queries.
- NoSQL: send `{"username":"appsec-canary-x","password":{"$ne":"appsec-canary-y"}}` to a local instance with a seeded test user only.
- Command injection: inject `;echo appsec-canary-<rand>` / argv `--version` in a local container and look for the marker; never `rm`, network callbacks or reverse shells.
- SSTI: use arithmetic `{{7*191}}` → expect `1337`; stop there. Never read files or execute commands.
- CRLF: `%0d%0aX-Appsec-Canary: <rand>` and check whether the header appears.
