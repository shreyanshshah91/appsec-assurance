# Python (Django, Flask, FastAPI)

**Detector keys:** `python`, `django`, `flask`, `fastapi`

## Untrusted input sources

- Django: `request.GET`, `request.POST`, `request.body`, `request.FILES`, `request.COOKIES`, `request.META` (incl. `HTTP_*` headers, `HTTP_HOST`), URL kwargs, DRF `request.data`, `request.query_params`, serializer `initial_data`.
- Flask: `request.args`, `request.form`, `request.values`, `request.json`/`get_json()`, `request.files`, `request.headers`, `request.cookies`, view args, `request.environ`.
- FastAPI/Starlette: path/query/header/cookie/body parameters, `Request.query_params`, `await request.json()`, `UploadFile.filename`, WebSocket `receive_*`.
- Celery task arguments (anyone who can publish to the broker controls them), message-queue payloads, webhooks, `sys.argv`, env vars in multi-tenant contexts, files read from uploads or object storage.

## Dangerous sinks

| Sink | Vulnerability class | CWE | Safe alternative |
|------|--------------------|-----|------------------|
| `cursor.execute(f"...{x}")`, `%`/`.format` into SQL | SQL injection | CWE-89 | `cursor.execute("... %s", [x])` |
| Django `.raw()`, `.extra()`, `RawSQL()` with interpolation | SQL injection | CWE-89 | ORM filters; `params=` argument |
| SQLAlchemy `text(f"...")`, `session.execute("..."+x)` | SQL injection | CWE-89 | `text("... :id")` + bound params |
| `os.system`, `subprocess.*(shell=True)`, `os.popen` | OS command injection | CWE-78 | `subprocess.run([...], shell=False)`; allowlist args |
| `eval`, `exec`, `compile` on input | Code injection | CWE-95 | `ast.literal_eval`, explicit parsers |
| `pickle.loads`, `dill`, `joblib.load`, `shelve`, `jsonpickle.decode`, `torch.load` (without `weights_only=True`) | Unsafe deserialization | CWE-502 | JSON + schema; signed data; `weights_only=True` / safetensors |
| `yaml.load` without `SafeLoader`, `yaml.unsafe_load`, `yaml.full_load` (older PyYAML) | Unsafe deserialization | CWE-502 | `yaml.safe_load` |
| `Template(user).render()`, `render_template_string(user)`, `Environment().from_string(user)` | SSTI → RCE | CWE-1336 | Static templates; pass input only as context; `SandboxedEnvironment` as defense in depth |
| `Markup(x)`, `\|safe`, `mark_safe`, `{% autoescape off %}`, `format_html` misuse | XSS | CWE-79 | Autoescaping; `format_html("{}", x)` |
| `requests.get(user_url)`, `urllib.request.urlopen`, `httpx` | SSRF | CWE-918 | Scheme/host allowlist, resolve-and-pin IP, block private ranges |
| `verify=False`, `ssl._create_unverified_context`, `CERT_NONE` | Improper cert validation | CWE-295 | Default verification; `verify="/path/ca.pem"` |
| `open(os.path.join(base, user))`, `send_file(user)` | Path traversal | CWE-22 | `send_from_directory`, `safe_join`, `Path.resolve().is_relative_to(base)` |
| `tarfile.extractall`, `zipfile.extractall` on untrusted archives | Zip slip | CWE-22 | `extractall(filter="data")` (3.12+/backports); validate members |
| `lxml.etree.parse` with `resolve_entities=True`, `xml.sax`, `xml.dom.pulldom` | XXE / billion laughs | CWE-611, CWE-776 | `defusedxml` |
| `redirect(request.args["next"])` | Open redirect | CWE-601 | `url_has_allowed_host_and_scheme` (Django) / relative-path allowlist |
| `random.random/choice` for tokens | Weak PRNG | CWE-338 | `secrets.token_urlsafe`, `secrets.compare_digest` |
| `hashlib.md5/sha1` for passwords | Weak password hash | CWE-916 | Django hashers, `argon2-cffi`, `bcrypt` |
| `logging.info(f"...{password}")` | Sensitive data in logs | CWE-532 | Redaction filters |

## Framework pitfalls and insecure defaults

- **Django:** `DEBUG = True` in production leaks settings and stack traces (CWE-489); `ALLOWED_HOSTS = ["*"]` enables Host-header poisoning of password-reset links; hard-coded `SECRET_KEY` allows session/signing forgery (and RCE on old `PickleSerializer` sessions); `@csrf_exempt` on state-changing views; `CSRF_COOKIE_SECURE`/`SESSION_COOKIE_SECURE`/`SECURE_SSL_REDIRECT`/`SECURE_HSTS_SECONDS` unset; `X_FRAME_OPTIONS` overridden; run `manage.py check --deploy`.
- **DRF:** `DEFAULT_PERMISSION_CLASSES` defaults to `AllowAny` if not set; per-view `permission_classes = []` silently disables auth; `has_object_permission` is only called via `get_object()` — custom `get_queryset`/list actions bypass it, so scope querysets by owner; `ModelSerializer` with `fields = "__all__"` or writable `is_staff`/`owner` fields → mass assignment (CWE-915); missing throttling on auth endpoints.
- **Flask:** `app.run(debug=True)` exposes the Werkzeug debugger console (RCE if PIN leaked/guessable); default client-side session is signed, not encrypted — never store secrets in it; weak `SECRET_KEY`; no CSRF by default (use Flask-WTF `CSRFProtect`); `send_file` with user paths.
- **FastAPI:** auth is opt-in per route via `Depends`; routers included without the dependency are public. `CORSMiddleware(allow_origins=["*"], allow_credentials=True)` is a misconfiguration. Pydantic models used for both input and output can leak fields (`response_model` missing) or accept privileged fields. `/docs` and `/openapi.json` are exposed by default.
- **SQLAlchemy:** ORM is safe; `text()`, `literal_column()`, `.order_by(user_str)` and `func` names from input are not.
- **Celery:** `pickle` serializer (`task_serializer`/`accept_content` incl. `pickle`) → RCE for anyone who can write to the broker; unauthenticated Redis/RabbitMQ brokers; Flower exposed without auth.
- **Jinja2 outside Flask:** `Environment()` has `autoescape=False` by default — use `select_autoescape()`.
- Dependency confusion via `--extra-index-url`; unpinned `requirements.txt`; `setup.py` executes code at install.

## Authn/authz idioms to verify

- Django: `@login_required`, `@permission_required`, `LoginRequiredMixin`, `UserPassesTestMixin`, `LoginRequiredMiddleware` (5.1+); confirm every object lookup filters by `request.user` (`get_object_or_404(Doc, pk=pk, owner=request.user)`).
- DRF: `permission_classes`, `authentication_classes`, `get_queryset` scoping, `@action(permission_classes=...)`, `throttle_classes`.
- Flask: `@login_required` (Flask-Login) ordering — it must be *below* `@app.route`; custom decorators that forget `functools.wraps` or return early.
- FastAPI: `Depends(get_current_user)`, `Security(..., scopes=[...])`, router-level `dependencies=[...]`; JWT decode with explicit `algorithms=[...]` and audience/issuer (PyJWT `jwt.decode(..., algorithms=["RS256"], audience=...)`); never `options={"verify_signature": False}`.
- Password reset tokens: Django `PasswordResetTokenGenerator`; custom ones must be single-use, expiring, constant-time compared.

## Useful grep patterns

```bash
rg -n --type py 'execute\(\s*f["\x27]|execute\([^)]*(%|\.format\(|\+)' 
rg -n --type py '\.(raw|extra)\(|RawSQL\(|text\(\s*f["\x27]'
rg -n --type py 'shell\s*=\s*True|os\.system\(|os\.popen\(|subprocess\.(call|run|Popen|check_output)\('
rg -n --type py '\b(eval|exec)\(|pickle\.loads?\(|yaml\.(load|unsafe_load|full_load)\(|marshal\.loads|jsonpickle|torch\.load\('
rg -n --type py 'render_template_string\(|from_string\(|Template\(|mark_safe\(|Markup\(|\|\s*safe'
rg -n --type py 'verify\s*=\s*False|_create_unverified_context|CERT_NONE|check_hostname\s*=\s*False'
rg -n --type py 'DEBUG\s*=\s*True|ALLOWED_HOSTS\s*=\s*\[\s*["\x27]\*|SECRET_KEY\s*=\s*["\x27]|csrf_exempt|debug\s*=\s*True'
rg -n --type py 'permission_classes\s*=\s*\[\s*\]|AllowAny|fields\s*=\s*["\x27]__all__'
rg -n --type py 'extractall\(|send_file\(|os\.path\.join\([^)]*request'
rg -n --type py 'random\.(random|randint|choice)\(|hashlib\.(md5|sha1)\('
```

## Recommended tools

- Bandit (`bandit -r . -f sarif`), Semgrep (`p/python`, `p/django`, `p/flask`), pip-audit, OSV-Scanner, Safety (DB licence terms apply), `python manage.py check --deploy`, Pyright/mypy (types help find tainted `Any`), Gitleaks, CodeQL (where licence permits).

## Secure code patterns

```python
# Vulnerable: SQLi
cur.execute(f"SELECT * FROM users WHERE email = '{email}'")
# Fixed
cur.execute("SELECT * FROM users WHERE email = %s", (email,))

# Vulnerable: command injection
subprocess.run(f"convert {fname} out.png", shell=True)
# Fixed
subprocess.run(["convert", "--", fname, "out.png"], check=True)

# Vulnerable: SSTI
return render_template_string("Hello " + request.args["name"])
# Fixed
return render_template_string("Hello {{ name }}", name=request.args["name"])

# Vulnerable: IDOR in DRF
class DocViewSet(ModelViewSet):
    queryset = Doc.objects.all()
# Fixed
class DocViewSet(ModelViewSet):
    permission_classes = [IsAuthenticated]
    def get_queryset(self):
        return Doc.objects.filter(owner=self.request.user)

# Vulnerable: YAML / TLS
cfg = yaml.load(body)            ; requests.get(url, verify=False)
# Fixed
cfg = yaml.safe_load(body)       ; requests.get(url, timeout=10)
```
