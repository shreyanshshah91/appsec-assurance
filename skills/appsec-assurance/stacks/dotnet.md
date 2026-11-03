# .NET / C# (ASP.NET Core, MVC, Razor Pages, Minimal APIs, Blazor)

**Detector keys:** `csharp`, `aspnet`, `graphql` (Hot Chocolate / GraphQL.NET)

## Untrusted input sources

- Model binding: `[FromQuery]`, `[FromRoute]`, `[FromBody]`, `[FromForm]`, `[FromHeader]`, implicit binding of complex types (binds every public settable property), Minimal API parameters, `IFormFile` (`FileName`, `ContentType` attacker-controlled).
- `HttpContext.Request.Query/Form/Headers/Cookies/Body`, `Request.Host`, `Request.Path`, `RouteData`, `X-Forwarded-*` via `ForwardedHeadersMiddleware` (spoofable if `KnownProxies`/`KnownNetworks` cleared).
- SignalR hub method arguments, gRPC messages, Blazor component parameters (`[Parameter]`, `[SupplyParameterFromQuery]`) and JS interop callbacks, Azure Functions triggers, Service Bus/queue messages, Hot Chocolate resolver args.

## Dangerous sinks

| Sink | Vulnerability class | CWE | Safe alternative |
|------|--------------------|-----|------------------|
| `FromSqlRaw($"...{x}")`, `ExecuteSqlRaw("..." + x)`, `SqlQueryRaw` | SQL injection | CWE-89 | `FromSql($"...{x}")` / `FromSqlInterpolated` (parameterized), `SqlParameter` |
| `SqlCommand("..." + x)`, Dapper `Query("..." + x)` | SQL injection | CWE-89 | `cmd.Parameters.AddWithValue`, Dapper anonymous params `new { id }` |
| Dynamic LINQ (`System.Linq.Dynamic.Core`) `Where(userString)`, `OrderBy(userString)` | Expression/code injection | CWE-917 | Allowlist fields; typed expressions |
| `Process.Start("cmd.exe", "/c " + x)`, `ProcessStartInfo { UseShellExecute = true }` | OS command injection | CWE-78 | Fixed executable, `ArgumentList.Add(x)`, `UseShellExecute = false` |
| `BinaryFormatter`, `SoapFormatter`, `NetDataContractSerializer`, `LosFormatter`, `ObjectStateFormatter`, `JavaScriptSerializer` with `SimpleTypeResolver` | Unsafe deserialization | CWE-502 | `System.Text.Json`; `BinaryFormatter` removed in .NET 9 — do not re-enable via compat package |
| Json.NET `TypeNameHandling` ≠ `None` (`Auto`, `Objects`, `All`) | Polymorphic deserialization | CWE-502 | `TypeNameHandling.None`; custom `ISerializationBinder` allowlist |
| `DataContractSerializer` with `KnownTypes` from input, `XmlSerializer(Type.GetType(input))` | Unsafe deserialization | CWE-502 | Fixed types |
| `Html.Raw(x)`, `new HtmlString(x)`, `MarkupString` (Blazor), `@((MarkupString)x)` | XSS | CWE-79 | Razor `@x` autoencoding; HtmlSanitizer for rich text |
| `XmlDocument` with `XmlResolver` set, `XmlReaderSettings { DtdProcessing = Parse }`, `XmlTextReader` on .NET Framework < 4.5.2 | XXE | CWE-611 | `DtdProcessing.Prohibit`, `XmlResolver = null` (default on .NET Core) |
| `Path.Combine(root, input)` / `File.ReadAllText`, `PhysicalFile(input)` | Path traversal | CWE-22 | `Path.GetFullPath` + `StartsWith(root + Path.DirectorySeparatorChar)`; `Path.GetFileName` |
| `HttpClient.GetAsync(userUrl)` | SSRF | CWE-918 | `IHttpClientFactory` named client with allowlisted base address; `SocketsHttpHandler.ConnectCallback` IP filter |
| `Redirect(returnUrl)` | Open redirect | CWE-601 | `LocalRedirect(returnUrl)` / `Url.IsLocalUrl` |
| `ServerCertificateCustomValidationCallback = (...) => true`, `DangerousAcceptAnyServerCertificateValidator` | Improper cert validation | CWE-295 | Default validation |
| `System.Random` for tokens | Weak PRNG | CWE-338 | `RandomNumberGenerator.GetBytes` / `GetHexString` |
| `MD5`, `SHA1`, `DES`, `TripleDES`, `RijndaelManaged` with `CipherMode.ECB` | Weak crypto | CWE-327 | `AesGcm`; `PasswordHasher<T>` or `Rfc2898DeriveBytes.Pbkdf2` with high iterations |
| `DirectorySearcher.Filter = "(uid=" + x + ")"` | LDAP injection | CWE-90 | Encode per RFC 4515 |
| `Regex(userPattern)` without timeout | ReDoS | CWE-1333 | `RegexOptions.NonBacktracking` or `matchTimeout` |
| Razor `RazorEngine`/`RazorLight` compiling user templates | SSTI → RCE | CWE-1336 | Static templates |

## Framework pitfalls and insecure defaults

- **Authorization attributes:** `[Authorize]` on a controller is overridden by `[AllowAnonymous]` on any action (and `AllowAnonymous` wins over everything); no `FallbackPolicy` means new endpoints are public by default — set `options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build()`; Minimal APIs need `.RequireAuthorization()` or a fallback policy; middleware order must be `UseRouting` → `UseAuthentication` → `UseAuthorization` → endpoints; role checks by string (`[Authorize(Roles="Admin")]`) without resource-based `IAuthorizationService.AuthorizeAsync(User, resource, policy)` leaves IDOR.
- **Antiforgery:** MVC views get tokens automatically, but API controllers with cookie auth need `[ValidateAntiForgeryToken]`/`AutoValidateAntiforgeryTokenAttribute` globally; `[IgnoreAntiforgeryToken]` on state-changing actions; Minimal API form endpoints need `app.UseAntiforgery()` (.NET 8+) and `.DisableAntiforgery()` should be justified.
- **Data Protection keys:** default key ring is per-machine/container filesystem — in containers or farms keys are lost or inconsistent; persisting to a shared store (`PersistKeysToFileSystem`, `PersistKeysToAzureBlobStorage`, `PersistKeysToDbContext`) must also encrypt them at rest (`ProtectKeysWithCertificate`/`ProtectKeysWithAzureKeyVault`); leaked keys allow forging auth cookies and antiforgery tokens. Same concern for `machineKey` in classic ASP.NET `web.config` (ViewState MAC forgery → RCE).
- **Over-posting:** binding EF entities directly (`[Bind]` omitted, `TryUpdateModelAsync` without property list) exposes `IsAdmin`, `TenantId` (CWE-915) — use DTOs/view models.
- **Errors and dev surfaces:** `UseDeveloperExceptionPage` / `ASPNETCORE_ENVIRONMENT=Development` in prod; Swagger UI exposed; `appsettings.json` with connection strings and secrets (use user-secrets/Key Vault); `IncludeErrorDetails` in JWT bearer.
- **Cookies/sessions:** `CookieSecurePolicy.None`, `SameSiteMode.None` without need, long `ExpireTimeSpan` with `SlidingExpiration`, `HttpOnly = false`.
- **CORS:** `AllowAnyOrigin()` with credentials is blocked, but `SetIsOriginAllowed(_ => true).AllowCredentials()` is not.
- **JWT bearer:** `TokenValidationParameters` with `ValidateIssuer/ValidateAudience/ValidateLifetime/ValidateIssuerSigningKey = false`, `RequireSignedTokens = false`, `SignatureValidator` returning the token unchecked, `RequireHttpsMetadata = false` outside dev.
- **Blazor Server:** all component logic runs server-side, but authorization must be checked in event handlers too (`AuthorizeView` is UI only); circuit state shared via static fields leaks across users.
- **Classic ASP.NET:** `ValidateRequest="false"`, `customErrors mode="Off"`, `EnableViewStateMac="false"`, `debug="true"` in `web.config`.
- NuGet: `nuget.config` with additional feeds and no `packageSourceMapping` → dependency confusion; MSBuild `.targets` in packages execute at build.

## Authn/authz idioms to verify

- `services.AddAuthorization(o => { o.FallbackPolicy = ...; o.AddPolicy("CanEdit", p => p.Requirements.Add(...)); })` and custom `AuthorizationHandler<TRequirement, TResource>` doing ownership checks.
- Every controller/page/endpoint group: `[Authorize]`, `RequireAuthorization`, `[Authorize(Policy=...)]`; Razor Pages conventions `AuthorizeFolder`.
- Identity: `PasswordOptions`, `LockoutOptions` (`AllowedForNewUsers`), `SignInManager.PasswordSignInAsync(..., lockoutOnFailure: true)`, email confirmation, `SecurityStamp` validation interval.
- Tenant filters: EF Core global query filters (`HasQueryFilter(e => e.TenantId == _tenant)`) and `IgnoreQueryFilters()` usage.

## Useful grep patterns

```bash
rg -n --type cs '(FromSqlRaw|ExecuteSqlRaw|ExecuteSqlRawAsync|SqlQueryRaw)\(\s*(\$"|"[^"]*"\s*\+)|new SqlCommand\(\s*(\$"|"[^"]*"\s*\+)'
rg -n --type cs 'BinaryFormatter|SoapFormatter|NetDataContractSerializer|LosFormatter|ObjectStateFormatter|TypeNameHandling\.(Auto|All|Objects|Arrays)|SimpleTypeResolver'
rg -n 'Html\.Raw\(|new HtmlString\(|MarkupString' -g '*.{cs,cshtml,razor}'
rg -n --type cs 'Process\.Start\(|UseShellExecute\s*=\s*true'
rg -n --type cs 'AllowAnonymous|IgnoreAntiforgeryToken|DisableAntiforgery|FallbackPolicy|RequireAuthorization'
rg -n --type cs 'Validate(Issuer|Audience|Lifetime|IssuerSigningKey)\s*=\s*false|RequireSignedTokens\s*=\s*false|RequireHttpsMetadata\s*=\s*false'
rg -n --type cs 'ServerCertificateCustomValidationCallback|DangerousAcceptAnyServerCertificateValidator|RemoteCertificateValidationCallback'
rg -n --type cs 'DtdProcessing\.Parse|XmlResolver\s*=\s*new|new Random\(|MD5\.Create|SHA1\.Create|CipherMode\.ECB'
rg -n --type cs 'Redirect\(\s*(returnUrl|url|Request)|Path\.Combine\([^)]*(Request|FileName)'
rg -n --type cs 'PersistKeysTo|ProtectKeysWith|SetIsOriginAllowed|UseDeveloperExceptionPage'
rg -n 'machineKey|customErrors\s+mode="Off"|debug="true"|ValidateRequest="false"' -g '*.config'
```

## Recommended tools

- .NET built-in Roslyn analyzers (`CA2300`–`CA2330` deserialization, `CA3001`–`CA3012` injection, `CA5350`–`CA5403` crypto; enable `AnalysisMode=All`), Semgrep (`p/csharp`), `dotnet list package --vulnerable --include-transitive`, OSV-Scanner (`packages.lock.json`), Trivy, Gitleaks, CodeQL (where licence permits).

## Secure code patterns

```csharp
// Vulnerable: EF Core SQLi (string interpolation evaluated before the call)
db.Users.FromSqlRaw($"SELECT * FROM Users WHERE Email = '{email}'");
// Fixed (FormattableString -> DbParameter)
db.Users.FromSql($"SELECT * FROM Users WHERE Email = {email}");

// Vulnerable: Json.NET polymorphism
JsonConvert.DeserializeObject<object>(body, new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All });
// Fixed
JsonSerializer.Deserialize<OrderDto>(body);

// Vulnerable: open redirect
return Redirect(returnUrl);
// Fixed
return Url.IsLocalUrl(returnUrl) ? LocalRedirect(returnUrl) : RedirectToAction("Index", "Home");

// Vulnerable: IDOR
var doc = await db.Docs.FindAsync(id); return Ok(doc);
// Fixed
var doc = await db.Docs.FindAsync(id);
if (doc is null) return NotFound();
var authz = await _authz.AuthorizeAsync(User, doc, "DocOwner");
return authz.Succeeded ? Ok(doc) : Forbid();

// Fixed: secure-by-default authorization
builder.Services.AddAuthorization(o => o.FallbackPolicy =
    new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());
```
