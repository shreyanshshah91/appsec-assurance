# Rust (actix-web, axum, sqlx, Diesel, serde, FFI)

**Detector keys:** `rust`, `actix`, `axum`, `graphql` (async-graphql / juniper)

Rust's type system removes most memory-safety bugs in safe code, so review
effort shifts to `unsafe`, FFI, logic flaws, injection through string-built
queries/commands, panics and resource exhaustion, and dependency risk.

## Untrusted input sources

- axum extractors: `Path<T>`, `Query<T>`, `Json<T>`, `Form<T>`, `TypedHeader<T>` / `HeaderMap`, `RawQuery`, `Multipart` (field `file_name()`), `Bytes`/`String` bodies, `ConnectInfo` (spoofable behind proxies when combined with forwarded headers), `WebSocketUpgrade` messages.
- actix-web: `web::Path`, `web::Query`, `web::Json`, `web::Form`, `web::Bytes`, `HttpRequest::headers()`, `connection_info().realip_remote_addr()` (trusts `Forwarded`/`X-Forwarded-For`), `actix-multipart`.
- tonic gRPC requests and metadata, async-graphql resolver args, message-queue consumers, CLI `std::env::args`, files and network sockets parsed with custom code (`nom`, manual byte parsing).

## Dangerous sinks

| Sink | Vulnerability class | CWE | Safe alternative |
|------|--------------------|-----|------------------|
| `sqlx::query(&format!(...))`, `query_as(&format!(...))` | SQL injection | CWE-89 | `sqlx::query("... WHERE id = $1").bind(id)` or compile-time `sqlx::query!` |
| Diesel `sql_query(format!(...))`, `diesel::dsl::sql::<T>(user)` | SQL injection | CWE-89 | Query DSL; `sql_query(...).bind::<Text, _>(x)` |
| `QueryBuilder::push(user)` (sqlx) | SQL injection | CWE-89 | `push_bind(user)` |
| `Command::new("sh").arg("-c").arg(x)` | OS command injection | CWE-78 | `Command::new(fixed_bin).arg(x)`; validate; `--` separator |
| `unsafe { ... }` (raw pointer deref, `from_raw_parts`, `transmute`, `get_unchecked`, `set_len`, `assume_init`) | Memory corruption | CWE-787, CWE-125, CWE-416, CWE-119 | Safe abstractions; document invariants (`// SAFETY:`); Miri |
| `unsafe impl Send/Sync` on types with interior mutability | Data race | CWE-362 | Correct sync primitives |
| `extern "C"` / `bindgen` FFI, `CString::from_raw`, `Box::from_raw` | Memory safety across FFI, double free | CWE-415, CWE-416, CWE-787 | Ownership-clear wrappers; fuzz the boundary |
| `.unwrap()`, `.expect()`, indexing `v[i]`, `/` by zero, `RefCell::borrow_mut` on request paths | Panic → DoS (and poisoned mutexes) | CWE-248, CWE-400 | `?`, `get(i)`, `checked_*`, explicit error responses; `catch_panic` layer |
| Integer arithmetic on lengths/amounts (`as` casts, wrapping in release) | Integer overflow / truncation | CWE-190, CWE-681 | `checked_add`, `try_from`, `u64::saturating_*` |
| `Json<T>` / `Bytes` without body limit, unbounded `Vec::with_capacity(len_from_input)` | Resource exhaustion | CWE-400, CWE-789 | `DefaultBodyLimit`, `web::JsonConfig::limit`, cap allocations |
| `PathBuf::from(base).join(user)` + `fs::read` | Path traversal | CWE-22 | `canonicalize` + `starts_with(base)`; reject `..`/absolute components; `tower_http::services::ServeDir` |
| `reqwest::get(user_url)` | SSRF | CWE-918 | Host allowlist, `redirect::Policy::none()`, IP filtering |
| `danger_accept_invalid_certs(true)`, `danger_accept_invalid_hostnames(true)`, rustls `dangerous()` custom verifier | Improper cert validation | CWE-295 | Default verifiers; `add_root_certificate` |
| `rand::thread_rng()` is a CSPRNG, but `SmallRng`/`StdRng::seed_from_u64` for tokens | Weak PRNG | CWE-338 | `OsRng` / `rand::rngs::ThreadRng`; `getrandom` |
| `==` on MACs/tokens | Timing attack | CWE-208 | `subtle::ConstantTimeEq`, `ring::constant_time` / `hmac::Mac::verify_slice` |
| `Html(format!("<p>{}</p>", user))` | XSS | CWE-79 | Askama/Maud/Tera autoescaping; never `\|safe` / `PreEscaped` on input |
| Tera `Tera::one_off(user_template, ...)` | SSTI | CWE-1336 | Static templates |
| `serde_yaml`/`bincode`/`rmp-serde` on untrusted data without limits | DoS / unexpected types | CWE-502, CWE-400 | Size limits (`bincode::Options::with_limit`), typed structs |

## Framework pitfalls and insecure defaults

- **`sqlx::query` vs `query!`:** the macro checks SQL at compile time against the schema and forces binding; the function accepts any `&str`, so `format!` sneaks in. Grep both.
- **serde pitfalls:** `#[serde(untagged)]` enums pick the *first* variant that parses — attacker-shaped input can select a more privileged variant or bypass validation; `#[serde(flatten)]` + `deny_unknown_fields` doesn't work together; missing `deny_unknown_fields` on request DTOs enables silent extra fields (mass-assignment-like when the struct is later merged); `#[serde(default)]` on security flags can default to permissive values; deserializing directly into DB models exposes `is_admin`/`owner_id` (CWE-915). Validate with `validator`/`garde` after deserialization.
- **Extractor rejection:** axum returns detailed rejection messages (fine) but custom `FromRequestParts` auth extractors must reject, not default to an anonymous user; ensure handlers requiring auth actually take the auth extractor (a route without it is public). Layer ordering in `Router::layer` vs `route_layer` — `route_layer` only applies to matched routes; layers added before `.route()` calls don't cover routes added after.
- **actix-web:** guards and `wrap` middleware are per scope — routes registered on `App` outside the protected `web::scope` bypass it; `web::PayloadConfig` default limit (256 KiB) vs custom large limits; `HttpServer::workers` and blocking calls in async handlers (use `web::block`) → DoS.
- **CORS:** `tower_http::cors::CorsLayer::permissive()` / `very_permissive()`, `actix_cors::Cors::permissive()` in production.
- **Async:** holding a `std::sync::Mutex` guard across `.await`; `tokio::spawn` without timeouts; unbounded channels from network input.
- **`unsafe` hygiene:** check `#![forbid(unsafe_code)]` in crates that should not need it; every `unsafe` block should carry a `// SAFETY:` justification; review `unsafe` in dependencies via cargo-geiger.
- **Supply chain:** `build.rs` and proc-macros run arbitrary code at build time; `[patch]`/git dependencies; yanked crates; `cargo install` without `--locked`.
- **Release profile:** `overflow-checks = false` (default in release) — arithmetic wraps silently; `panic = "abort"` turns any reachable panic into a process kill.

## Authn/authz idioms to verify

- axum: auth via extractor (`AuthUser` implementing `FromRequestParts`) or `middleware::from_fn` / `tower` layer applied with `route_layer` on protected routers; check every `Router::merge`/`nest` keeps the layer.
- actix: `web::scope("/admin").wrap(AdminGuard)`; `actix-web-httpauth` `HttpAuthentication::bearer(validator)`; validator must return an error on failure.
- JWT (`jsonwebtoken`): `Validation::new(Algorithm::RS256)` with `set_audience`/`set_issuer`; never `insecure_disable_signature_validation()`; `validate_exp` left on.
- Password hashing via `argon2`/`password-hash` with `verify_password`; sessions via `tower-sessions`/`actix-session` with `secure`, `http_only`, `same_site` and a strong key (`Key::generate`, not hard-coded).
- Object-level checks: queries include `AND owner_id = $2` bound to the authenticated principal.

## Useful grep patterns

```bash
rg -n --type rust 'sqlx::query(_as|_scalar)?\(\s*&?format!|sql_query\(\s*&?format!|dsl::sql::<|\.push\(\s*&?format!'
rg -n --type rust 'unsafe\s*(\{|fn|impl)|transmute|from_raw_parts|get_unchecked|set_len\(|assume_init|Box::from_raw|CString::from_raw'
rg -n --type rust 'extern\s+"C"|#\[no_mangle\]|bindgen'
rg -n --type rust 'Command::new\(\s*"(sh|bash|cmd)"|\.arg\(\s*"-c"\s*\)'
rg -n --type rust '\.unwrap\(\)|\.expect\(|panic!\(|unreachable!\(' -g '!**/tests/**'
rg -n --type rust 'serde\(untagged\)|serde\(flatten\)|serde\(default'
rg -n --type rust 'danger_accept_invalid_(certs|hostnames)|dangerous\(\)|insecure_disable_signature_validation'
rg -n --type rust 'CorsLayer::(very_)?permissive|Cors::permissive|PreEscaped|\|\s*safe'
rg -n --type rust 'SmallRng|seed_from_u64|PathBuf::from\([^)]*\)\.join\('
rg -n 'overflow-checks\s*=\s*false|^\s*\[patch|git\s*=\s*"' -g 'Cargo.toml'
```

## Recommended tools

- cargo-audit (RustSec advisories), cargo-deny (advisories, licences, sources, bans), Clippy (`-W clippy::unwrap_used -W clippy::indexing_slicing -W clippy::arithmetic_side_effects`), cargo-geiger (unsafe usage), Miri (UB detection in tests), cargo-fuzz / afl.rs, Semgrep (`p/rust`), OSV-Scanner (`Cargo.lock`), cargo-vet (supply-chain audits), Gitleaks.

## Secure code patterns

```rust
// Vulnerable: SQLi
let q = format!("SELECT * FROM users WHERE email = '{}'", email);
let user = sqlx::query_as::<_, User>(&q).fetch_one(&pool).await?;
// Fixed
let user = sqlx::query_as!(User, "SELECT * FROM users WHERE email = $1", email)
    .fetch_one(&pool).await?;

// Vulnerable: panic on attacker input (DoS)
let n: usize = params.get("n").unwrap().parse().unwrap();
let item = &items[n];
// Fixed
let n: usize = params.get("n").and_then(|s| s.parse().ok()).ok_or(ApiError::BadRequest)?;
let item = items.get(n).ok_or(ApiError::NotFound)?;

// Vulnerable: untagged enum lets input pick a privileged shape
#[derive(Deserialize)] #[serde(untagged)]
enum Cmd { Admin { grant: String }, User { name: String } }
// Fixed: explicit tag + server-side role check
#[derive(Deserialize)] #[serde(tag = "type", deny_unknown_fields)]
enum Cmd { Admin { grant: String }, User { name: String } }
// ...and reject Cmd::Admin unless auth.is_admin()

// Vulnerable: path traversal
let p = PathBuf::from("/srv/files").join(&name); fs::read(p)?;
// Fixed
let base = Path::new("/srv/files").canonicalize()?;
let p = base.join(&name).canonicalize()?;
if !p.starts_with(&base) { return Err(ApiError::Forbidden); }

// Unsafe hygiene
// SAFETY: `idx < buf.len()` is checked on the line above; buf is not aliased.
let b = unsafe { *buf.get_unchecked(idx) };
```
