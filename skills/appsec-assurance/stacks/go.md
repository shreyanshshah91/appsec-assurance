# Go (net/http, gin, echo, fiber)

**Detector keys:** `go`, `gin`, `echo`, `fiber`, `graphql` (gqlgen / graphql-go)

## Untrusted input sources

- net/http: `r.URL.Query()`, `r.FormValue`, `r.PostFormValue`, `r.Form`, `r.Body`, `r.Header`, `r.Cookie`, `r.PathValue` (Go 1.22+ mux), `r.MultipartForm` / `FileHeader.Filename`, `r.Host`, `r.RemoteAddr` (proxy-dependent).
- gin: `c.Query`, `c.Param`, `c.PostForm`, `c.GetHeader`, `c.Bind*`/`c.ShouldBind*` (JSON, form, query, URI), `c.FormFile`, `c.ClientIP()` (trusts `X-Forwarded-For` unless `SetTrustedProxies` configured).
- echo: `c.QueryParam`, `c.Param`, `c.FormValue`, `c.Bind`, `c.RealIP()`.
- fiber: `c.Query`, `c.Params`, `c.FormValue`, `c.BodyParser`, `c.Get` (header), `c.IP()`/`c.IPs()`. Note fiber values are backed by reused buffers — copying matters.
- gRPC request messages and metadata, gqlgen resolver args, NATS/Kafka messages, `os.Args`, `os.Getenv` in multi-tenant runners.

## Dangerous sinks

| Sink | Vulnerability class | CWE | Safe alternative |
|------|--------------------|-----|------------------|
| `db.Query/Exec/QueryRow(fmt.Sprintf(...))`, `"..."+x` | SQL injection | CWE-89 | Placeholders: `db.Query("... WHERE id = $1", id)` |
| GORM `db.Raw(s)`, `db.Where(fmt.Sprintf(...))`, `db.Order(userInput)`, `db.Exec` with concat | SQL injection | CWE-89 | `db.Where("name = ?", n)`; allowlist sort columns |
| sqlx `Select/Get` with concat; `sqlx.In` misuse | SQL injection | CWE-89 | Bind vars, `sqlx.Named` |
| `exec.Command("sh", "-c", x)`, `exec.Command(userBin, ...)` | OS command injection | CWE-78 | Fixed binary, arg slice, validate; `--` before user args |
| `text/template` producing HTML; `template.HTML(x)`, `template.JS(x)`, `template.URL(x)` casts | XSS | CWE-79 | `html/template` with no unsafe casts |
| `template.New("").Parse(userInput)` | SSTI (method calls on data) | CWE-1336 | Static templates only |
| `filepath.Join(base, userPath)` then `os.Open` | Path traversal | CWE-22 | `os.Root`/`OpenInRoot` (Go 1.24+), `filepath.IsLocal`, or `Clean` + `Rel` prefix check |
| `http.ServeFile(w, r, userPath)` | Path traversal | CWE-22 | `http.FileServer(http.Dir(root))` / `http.FS` with fixed root |
| `archive/zip`, `archive/tar` entry `Name` joined to dest | Zip slip | CWE-22 | Reject names failing `filepath.IsLocal` |
| `http.Get(userURL)`, `http.Client` default | SSRF | CWE-918 | Allowlist + custom `net.Dialer.Control` rejecting private IPs |
| `tls.Config{InsecureSkipVerify: true}` | Improper cert validation | CWE-295 | Default; `RootCAs` pool for private CAs |
| `tls.Config{MinVersion: tls.VersionTLS10}` | Weak TLS | CWE-326 | `tls.VersionTLS12` minimum |
| `math/rand` for tokens/keys/nonces | Weak PRNG | CWE-338 | `crypto/rand` (`rand.Read`, `rand.Text` in 1.24+) |
| `md5`, `sha1`, `des`, `rc4` for security | Broken crypto | CWE-327 | `crypto/sha256`, AES-GCM, `golang.org/x/crypto/argon2`/`bcrypt` |
| `encoding/gob` from untrusted peers, `yaml.Unmarshal` into `interface{}` with huge aliases | Unsafe deserialization / DoS | CWE-502, CWE-776 | Typed structs, size limits |
| `ioutil.ReadAll(r.Body)` without limit | Resource exhaustion | CWE-400 | `http.MaxBytesReader` |
| `http.Redirect(w, r, r.URL.Query().Get("next"), ...)` | Open redirect | CWE-601 | Relative path allowlist |
| `unsafe.Pointer`, cgo | Memory corruption | CWE-787, CWE-416 | Avoid; isolate and fuzz |
| Shared maps/slices across goroutines without sync | Race condition | CWE-362 | `sync.Mutex`, `sync.Map`, channels; `go test -race` |
| `==` / `bytes.Equal` on MACs/tokens | Timing side channel | CWE-208 | `subtle.ConstantTimeCompare`, `hmac.Equal` |

## Framework pitfalls and insecure defaults

- **`http.ListenAndServe` / `http.Server{}` without timeouts** → Slowloris (CWE-400). Set `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, `IdleTimeout`, `MaxHeaderBytes`.
- **Default `http.Client`** has no timeout and follows up to 10 redirects (SSRF via redirect). Set `Timeout` and `CheckRedirect`.
- **gin:** `gin.Default()` logs everything (possible secret logging); `ShouldBindJSON` into structs containing privileged fields → mass assignment (CWE-915); `c.ClientIP()` spoofable unless `SetTrustedProxies`; `gin.SetMode(gin.DebugMode)` in prod; `c.File(userPath)`.
- **echo:** `middleware.CORSWithConfig` with `AllowOrigins: ["*"]` + `AllowCredentials`; `c.Bind` binds path, query and body into the same struct — query params can override body fields; `HideBanner` irrelevant, but `Debug=true` leaks errors.
- **fiber:** values from `c.Params()`/`c.Query()` are only valid within the handler (zero-copy) — storing them in goroutines/caches causes data mixing across requests; set `Immutable: true` or copy. `BodyParser` mass assignment; `EnableTrustedProxyCheck` off by default.
- **Error handling:** ignored `err` on auth/crypto calls (`token, _ := jwt.Parse(...)`) silently passes; `defer resp.Body.Close()` missing (leak).
- **Goroutine races:** handlers mutating package-level state (counters, caches, config) — check with `-race`; TOCTOU on balances without DB transactions/`SELECT ... FOR UPDATE`.
- **Context:** `context.Background()` in handlers loses cancellation — DoS amplification.
- **`pprof`** imported (`_ "net/http/pprof"`) registers `/debug/pprof` on `DefaultServeMux` — exposed if that mux is served publicly.
- **Module supply chain:** `replace` directives pointing to forks/local paths, `GOFLAGS=-insecure`, `GONOSUMDB`/`GONOSUMCHECK`/`GOPRIVATE` misconfiguration, `go generate` directives running tools.

## Authn/authz idioms to verify

- Middleware wrapping: `mux.Handle("/admin/", authMW(adminHandler))` — confirm every route group (`r.Group("/api", auth)`) includes it and that routes registered on the root engine aren't missed.
- golang-jwt: `jwt.Parse` keyfunc must check `token.Method` (e.g. `*jwt.SigningMethodRSA`) or use `jwt.WithValidMethods([]string{"RS256"})`; verify `exp`, `aud`, `iss` (`jwt.WithAudience`, `jwt.WithIssuer`); check `token.Valid` and the returned error.
- Object-level checks after loading by ID; tenant ID from the authenticated context, not from the request.
- gRPC: unary *and* stream interceptors both enforce auth; reflection service disabled in prod.
- CSRF for cookie-session apps (`gorilla/csrf`, `net/http.CrossOriginProtection` in Go 1.25+).

## Useful grep patterns

```bash
rg -n --type go '\.(Query|QueryRow|Exec|QueryContext|ExecContext|Raw|Where|Order|Select|Get)\(\s*(fmt\.Sprintf|"[^"]*"\s*\+)'
rg -n --type go 'exec\.Command(Context)?\(\s*"(sh|bash|cmd)"|exec\.Command(Context)?\(\s*[a-z]\w*\s*[,)]'
rg -n --type go '"text/template"|template\.(HTML|JS|URL|CSS|HTMLAttr)\('
rg -n --type go 'InsecureSkipVerify:\s*true|tls\.VersionTLS1[01]\b'
rg -n --type go '"math/rand"|"crypto/(md5|sha1|des|rc4)"'
rg -n --type go 'filepath\.Join\([^)]*(Param|Query|FormValue|Filename)|http\.ServeFile\(|c\.File\('
rg -n --type go 'http\.ListenAndServe\(|&http\.Server\{|http\.(Get|Post)\(|http\.DefaultClient'
rg -n --type go '_ "net/http/pprof"|"unsafe"|import "C"'
rg -n --type go 'jwt\.Parse(WithClaims)?\(|, _ :?= jwt\.'
rg -n '^\s*replace\s' -g 'go.mod'
```

## Recommended tools

- gosec (`gosec -fmt sarif ./...`), govulncheck (reachability-aware), staticcheck, `go vet`, `go test -race`, native fuzzing (`go test -fuzz`), Semgrep (`p/golang`, `p/gosec`), OSV-Scanner, Trivy (binaries in images), Gitleaks.

## Secure code patterns

```go
// Vulnerable: SQLi
rows, _ := db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name))
// Fixed
rows, err := db.QueryContext(ctx, "SELECT * FROM users WHERE name = $1", name)

// Vulnerable: path traversal
f, _ := os.Open(filepath.Join(uploadDir, c.Param("name")))
// Fixed (Go 1.24+)
root, err := os.OpenRoot(uploadDir); if err != nil { return err }
f, err := root.Open(c.Param("name")) // rejects escapes, incl. via symlinks

// Vulnerable: XSS via wrong package
import "text/template"
// Fixed
import "html/template" // and never wrap input in template.HTML

// Vulnerable: token from math/rand
tok := fmt.Sprintf("%d", rand.Int63())
// Fixed
b := make([]byte, 32); if _, err := cryptorand.Read(b); err != nil { return err }
tok := base64.RawURLEncoding.EncodeToString(b)

// Vulnerable: no server timeouts
http.ListenAndServe(":8080", mux)
// Fixed
srv := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 5 * time.Second,
    ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
log.Fatal(srv.ListenAndServe())
```
