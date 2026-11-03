# PHP (Laravel, Symfony, plain PHP, WordPress-style code)

**Detector keys:** `php`, `laravel`, `symfony`, `graphql` (Lighthouse / API Platform / webonyx)

## Untrusted input sources

- Superglobals: `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES` (`name`, `type` are attacker-controlled), `$_SERVER` (`HTTP_*`, `PHP_SELF`, `REQUEST_URI`, `HTTP_HOST`), `php://input`, `getallheaders()`.
- Laravel: `$request->input/query/post/all/json/header/cookie/file`, `request()`, route parameters, implicit model binding IDs, `Request::merge`d data, queued job payloads, Livewire public properties (client-modifiable).
- Symfony: `$request->query`, `->request`, `->attributes`, `->headers`, `->cookies`, `->files`, `getContent()`, `#[MapRequestPayload]`/`#[MapQueryString]` DTOs, Messenger messages.
- Session data written from input, uploaded file contents, `phar://`-reachable files, CLI `$argv`.

## Dangerous sinks

| Sink | Vulnerability class | CWE | Safe alternative |
|------|--------------------|-----|------------------|
| `mysqli_query($c, "...$x")`, `$pdo->query("...".$x)`, `PDO::exec` | SQL injection | CWE-89 | `$pdo->prepare("... = ?")->execute([$x])` |
| Laravel `DB::raw`, `whereRaw`, `selectRaw`, `orderByRaw`, `havingRaw`, `DB::statement`/`DB::select` with interpolation; `orderBy($request->sort)` | SQL injection | CWE-89 | Bindings: `whereRaw('x = ?', [$v])`; allowlist columns |
| Doctrine `$em->createQuery("...$x")`, DBAL `executeQuery` with concat | DQL/SQL injection | CWE-89 | `setParameter`, query builder with `:param` |
| `system`, `exec`, `shell_exec`, `passthru`, `popen`, `proc_open`, backticks | OS command injection | CWE-78 | `proc_open([...array])` (PHP 7.4+), Symfony `Process([...])`, `escapeshellarg` as last resort |
| `eval`, `assert($string)` (PHP < 8), `create_function`, `preg_replace` `/e` (PHP < 7) | Code injection | CWE-95 | Remove; explicit dispatch |
| `include/require(_once)($x)` | LFI / RFI | CWE-98, CWE-22 | Map of allowed files; `allow_url_include=Off` |
| `unserialize($x)` | Object injection (POP chains) | CWE-502 | `json_decode`; `unserialize($x, ['allowed_classes' => false])` |
| `file_exists/fopen/getimagesize/...` on `phar://` paths (PHP < 8 auto-deserializes metadata) | Deserialization via phar | CWE-502 | Reject stream wrappers; PHP 8+ |
| `echo $x`, `<?= $x ?>`, Blade `{!! $x !!}`, Twig `\|raw`, `{% autoescape false %}` | XSS | CWE-79 | `htmlspecialchars($x, ENT_QUOTES \| ENT_SUBSTITUTE, 'UTF-8')`; `{{ }}` |
| Twig `createTemplate($input)`, Blade `Blade::render($input)`, Smarty `{php}`/`fetch('string:'.$x)` | SSTI | CWE-1336 | Static templates; Twig sandbox extension |
| `==`, `in_array` without strict, `switch` on mixed types, `strcmp` returning `null` on arrays | Type juggling auth bypass | CWE-1024, CWE-697 | `===`, `in_array($x, $arr, true)`, `hash_equals` |
| `md5($p) == $hash` (magic hashes `0e...`) | Auth bypass / weak hash | CWE-916 | `password_hash` / `password_verify` |
| `file_get_contents($url)`, `curl_exec` with user URL, `SoapClient` WSDL from input | SSRF | CWE-918 | Allowlist host; `CURLOPT_PROTOCOLS` HTTP(S) only; no redirects |
| `move_uploaded_file($_FILES['f']['tmp_name'], $dir.$_FILES['f']['name'])` | Unrestricted upload / RCE | CWE-434, CWE-22 | Random name, extension allowlist, store outside webroot, no exec |
| `header("Location: ".$x)`, Laravel `redirect($x)`/`redirect()->away($x)` | Open redirect | CWE-601 | `redirect()->intended()` with relative paths; allowlist |
| `simplexml_load_string`, `DOMDocument::loadXML($x, LIBXML_NOENT)` | XXE | CWE-611 | No `LIBXML_NOENT`/`LIBXML_DTDLOAD` (libxml ≥ 2.9 safe by default) |
| `extract($_REQUEST)`, `parse_str($x)` without result arg | Variable overwrite | CWE-621, CWE-914 | Explicit assignment |
| `rand`, `mt_rand`, `uniqid` for tokens | Weak PRNG | CWE-338 | `random_bytes`, `random_int`, `Str::random` (uses random_bytes) |
| `mail()` with user-controlled headers/5th param | Header / argument injection | CWE-93, CWE-88 | Symfony Mailer / framework mailers |

## Framework pitfalls and insecure defaults

- **Laravel mass assignment:** `$guarded = []`, `Model::unguard()`, `$fillable` including `is_admin`/`role`/`team_id`; `$model->forceFill($request->all())`; `create($request->all())` — use `$request->validated()` / `->only([...])` (CWE-915).
- **Laravel config:** `APP_DEBUG=true` in production (Ignition error pages leak env; older Ignition had RCE CVE-2021-3129); committed `.env`; leaked `APP_KEY` → forged encrypted cookies/signed URLs and, with `unserialize` of decrypted payloads, RCE; `VerifyCsrfToken::$except` entries / `validateCsrfTokens(except: [...])` in Laravel 11; Telescope/Horizon dashboards without a gate in production; `Route::any` on state-changing actions; signed routes without `signed` middleware.
- **Laravel authorization:** policies registered but `$this->authorize()`/`Gate::authorize()`/`can` middleware not called; implicit route model binding loads any ID — scope via `->scopeBindings()` or policy; `Gate::before` returning `true` for broad roles.
- **Symfony:** `APP_ENV=dev` / `APP_DEBUG=1` exposes the profiler (`/_profiler`) with request data and env; `framework.secret` default/committed (fragment `/_fragment` URL signing → RCE when known); `security.yaml` `access_control` order is first-match and uses regexes — unanchored paths or ordering mistakes leave routes open; firewalls with `security: false`; `#[IsGranted]` missing on new controllers; voters that abstain everywhere with `allow_if_all_abstain: true`.
- **php.ini:** `display_errors=On`, `allow_url_include=On`, `expose_php=On`, missing `open_basedir`/`disable_functions` hardening, `session.cookie_httponly/secure/samesite` unset, `session.use_strict_mode=0`.
- **Uploads:** trusting `$_FILES[..]['type']` or `getClientOriginalExtension()`/`getClientMimeType()`; storing in `public/` where `.php`, `.phtml`, `.phar` or `.htaccess` can execute; image libraries (ImageMagick) processing hostile files. Use `$file->hashName()`, `store()` on a non-public disk, `mimes:`/`mimetypes:` validation plus server-side content sniffing.
- **Composer:** `scripts` (`post-install-cmd`, `post-update-cmd`) run on install; `minimum-stability: dev`; VCS repositories; plugins (`allow-plugins`).

## Authn/authz idioms to verify

- Laravel: `auth`/`auth:sanctum` middleware on route groups; `Route::middleware(['auth', 'can:update,post'])`; `$this->authorize('update', $post)`; Sanctum token abilities (`tokenCan`); `throttle:` on login and password reset; `Password::defaults()`.
- Symfony: `access_control` + `#[IsGranted('ROLE_ADMIN')]` + voters for object-level checks; `password_hashers` set to `auto`; login throttling (`login_throttling`).
- Session regeneration on login (`session()->regenerate()`, `session_regenerate_id(true)`), `hash_equals` for token comparisons, JWT libraries (`firebase/php-jwt`) called with an explicit `Key($k, 'RS256')`.

## Useful grep patterns

```bash
rg -n --type php '(mysqli_query|->query|->exec|DB::(select|statement|unprepared)|whereRaw|selectRaw|orderByRaw|havingRaw|DB::raw)\([^)]*(\$|\.\s*\$)'
rg -n --type php '\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(|`[^`]*\$'
rg -n --type php '\b(eval|assert|create_function)\s*\(|preg_replace\s*\(\s*["\x27].*/e'
rg -n --type php '\b(include|require)(_once)?\s*\(?\s*\$'
rg -n --type php '\bunserialize\s*\(|phar://'
rg -n '\{!!|\|\s*raw\b|autoescape\s+false|<\?=\s*\$' -g '*.{php,twig}'
rg -n --type php '[^=!]==\s*[^=]|in_array\([^)]*\)\s*(?:\)|&&|\|\|)|strcmp\(|md5\('
rg -n --type php 'move_uploaded_file|getClientOriginalExtension|getClientMimeType'
rg -n --type php '\$guarded\s*=\s*\[\s*\]|unguard\(|forceFill\(|->all\(\)\s*\)'
rg -n 'APP_DEBUG\s*=\s*true|APP_ENV\s*=\s*(local|dev)|display_errors\s*=\s*On|allow_url_include' -g '*.{env,ini,example}' -g '.env*'
rg -n --type php 'extract\(\s*\$_|parse_str\(\s*[^,]+\)|\b(rand|mt_rand|uniqid)\('
```

## Recommended tools

- Semgrep (`p/php`, `p/laravel`, `p/symfony`), Psalm with taint analysis (`--taint-analysis`), PHPStan (+ strict rules), Progpilot, `composer audit`, Roave SecurityAdvisories (blocks vulnerable installs), OSV-Scanner (`composer.lock`), Enlightn (Laravel), Gitleaks.

## Secure code patterns

```php
// Vulnerable: SQLi
$rows = DB::select("SELECT * FROM users WHERE email = '$email'");
// Fixed
$rows = DB::select('SELECT * FROM users WHERE email = ?', [$email]);

// Vulnerable: type juggling ("0e123" == "0e456" is true; [] bypasses strcmp)
if ($token == $user->reset_token) { ... }
// Fixed
if (is_string($token) && hash_equals($user->reset_token, $token)) { ... }

// Vulnerable: object injection
$prefs = unserialize($_COOKIE['prefs']);
// Fixed
$prefs = json_decode($_COOKIE['prefs'] ?? '{}', true, 8, JSON_THROW_ON_ERROR);

// Vulnerable: LFI
include "pages/" . $_GET['page'] . ".php";
// Fixed
$pages = ['home' => 'pages/home.php', 'about' => 'pages/about.php'];
include $pages[$_GET['page'] ?? 'home'] ?? $pages['home'];

// Vulnerable: mass assignment + upload
User::create($request->all());
$request->file('avatar')->move(public_path('uploads'), $request->file('avatar')->getClientOriginalName());
// Fixed
User::create($request->validated());
$path = $request->file('avatar')->store('avatars', 'private'); // random hashName, non-public disk
```
