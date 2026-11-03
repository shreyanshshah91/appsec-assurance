"""Attack-surface inventory: entry points, sensitive operations, trust-boundary
hints. Regex-based and intentionally over-inclusive; Claude extends it by
reading the code (SKILL.md phase 2)."""

import os
import re
from typing import Dict, List

from .walker import iter_lines, read_text

PY = (".py",)
JS = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")
JV = (".java", ".kt")
GO = (".go",)
RB = (".rb",)
PHP = (".php",)
CS = (".cs",)
RS = (".rs",)
CODE = PY + JS + JV + GO + RB + PHP + CS + RS

# (kind, extensions, regex)
PATTERNS = [
    ("http-route", PY, r"@\w+\.(route|get|post|put|patch|delete|api_route|websocket)\(\s*['\"]"),
    ("http-route", PY, r"\b(re_)?path\(\s*r?['\"][^'\"]*['\"]\s*,"),
    ("http-route", JS, r"\b(app|router|server|fastify)\.(get|post|put|patch|delete|all|use|route)\(\s*['\"`/]"),
    ("http-route", JS, r"@(Get|Post|Put|Patch|Delete|All)\(\s*['\"]?"),
    ("http-route", JS, r"export\s+(async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b"),
    ("http-route", JS, r"['\"]use server['\"]"),
    ("http-route", JV, r"@(Get|Post|Put|Patch|Delete|Request)Mapping\b"),
    ("http-route", GO, r"\.(HandleFunc|Handle|GET|POST|PUT|PATCH|DELETE|Any|Group)\(\s*\""),
    ("http-route", RB, r"^\s*(get|post|put|patch|delete|resources?|match)\s+['\":]"),
    ("http-route", PHP, r"Route::(get|post|put|patch|delete|any|match|resource)\("),
    ("http-route", CS, r"\[(Http(Get|Post|Put|Patch|Delete)|Route)\b|\.Map(Get|Post|Put|Delete)\("),
    ("http-route", RS, r"#\[(get|post|put|delete|patch)\(|\.route\(\s*\""),
    ("graphql", CODE + (".graphql", ".gql"), r"\b(type\s+(Query|Mutation|Subscription)\b|ApolloServer|graphqlHTTP|GraphQLSchema|strawberry\.type|graphene\.ObjectType|@Resolver|@QueryMapping)"),
    ("websocket", CODE, r"\b(WebSocketServer|new\s+WebSocket\(|socket\.io|io\.on\(|@WebSocketGateway|websocket\.Upgrader|@app\.websocket|WebSocketHandler|ws\.on\()"),
    ("file-upload", CODE, r"\b(multer|formidable|busboy|UploadFile|request\.files|FileField|MultipartFile|IFormFile|move_uploaded_file|\$_FILES|FormFile\()"),
    ("auth", CODE, r"\b(passport\.|jwt\.(sign|verify|decode)|jsonwebtoken|jose\.|login_required|@login_required|authenticate\(|check_password|bcrypt|argon2|scrypt|pbkdf2|@PreAuthorize|@Secured|\[Authorize|before_action\s+:authenticate|Auth::|session\[|req\.session|getServerSession|next-auth|OAuth|oauth2|oidc)"),
    ("authorization", CODE, r"\b(is_admin|isAdmin|role\s*==|hasRole|has_permission|permission_classes|can\?|authorize\(|Gate::|@Roles|policy|ability)"),
    ("db-query", CODE, r"\b(execute|executemany|raw|query|\$queryRaw\w*|\$executeRaw\w*|createQuery|prepareStatement|QueryRow|Exec\(|find_by_sql|whereRaw|DB::(select|statement|raw)|FromSqlRaw|cursor\(\))\s*\("),
    ("nosql-query", CODE, r"\.(find|findOne|aggregate|updateOne|updateMany|deleteMany|\$where)\s*\(\s*(req\.|request\.|\{)"),
    ("outbound-http", CODE, r"\b(requests\.(get|post|put|request)|httpx\.|urllib\.request|urlopen|fetch\(|axios(\.\w+)?\(|got\(|http\.Get|http\.NewRequest|HttpClient|RestTemplate|WebClient|Net::HTTP|curl_exec|Guzzle|reqwest::)"),
    ("subprocess", CODE, r"\b(subprocess\.|os\.system|os\.popen|child_process|execSync|spawn\(|exec\.Command|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|system\(|shell_exec|passthru|proc_open|Process\.Start|std::process::Command)"),
    ("deserialization", CODE, r"\b(pickle\.loads?|yaml\.load|marshal\.loads|ObjectInputStream|readObject|BinaryFormatter|unserialize\(|Marshal\.load|YAML\.load|node-serialize|serialize-javascript|jsonpickle)"),
    ("template-render", CODE, r"\b(render_template_string|Template\(|Environment\(|res\.render|dangerouslySetInnerHTML|v-html|\[innerHTML\]|innerHTML\s*=|html_safe|raw\(|Html\.Raw|\{!!|\|\s*safe\b|template\.HTML)"),
    ("crypto", CODE, r"\b(hashlib\.|Crypto\.|cryptography\.|createCipheriv|createHash|crypto\.subtle|MessageDigest|Cipher\.getInstance|crypto/(aes|cipher|md5|sha1)|openssl_|RNGCryptoServiceProvider|SecureRandom|Math\.random|random\.)"),
    ("file-access", CODE, r"\b(open\(|send_file|sendFile|res\.download|readFile|createReadStream|os\.Open|ioutil\.ReadFile|Files\.read|File\.read|file_get_contents|fopen|include\s|require_once|File\.ReadAll|path\.join\(.*req)"),
    ("redirect", CODE, r"\b(redirect\(|res\.redirect|HttpResponseRedirect|sendRedirect|redirect_to|Redirect\(|header\(\s*['\"]Location)"),
    ("cors", CODE, r"\b(cors\(|Access-Control-Allow-Origin|CORS_ALLOW|CORSMiddleware|@CrossOrigin|AllowAnyOrigin|enableCors)"),
    ("rate-limit", CODE, r"\b(rate.?limit|express-rate-limit|slowapi|throttle|Throttle|RateLimiter|limiter\.)"),
    ("logging", CODE, r"\b(logger\.|logging\.|console\.(log|error)|log\.(Print|Info|Error)|Log\.(Info|Error|Warn)|winston|pino|structlog)"),
    ("payment", CODE, r"\b(stripe|paypal|braintree|adyen|checkout|refund|charge\()"),
]

_COMPILED = [(k, exts, re.compile(rx, re.I if k in ("payment",) else 0)) for k, exts, rx in PATTERNS]

CONFIG_KINDS = [
    ("env-file", re.compile(r"(^|/)\.env(\.[\w-]+)?$")),
    ("dockerfile", re.compile(r"(^|/)(Dockerfile(\.[\w-]+)?|[\w.-]+\.Dockerfile)$")),
    ("compose", re.compile(r"(^|/)(docker-)?compose\.ya?ml$")),
    ("ci-pipeline", re.compile(r"(^\.github/workflows/.+\.ya?ml$|(^|/)\.gitlab-ci\.yml$|(^|/)Jenkinsfile$|^\.circleci/|azure-pipelines\.yml$|bitbucket-pipelines\.yml$)")),
    ("terraform", re.compile(r"\.tf$")),
    ("web-server-config", re.compile(r"(nginx\.conf|\.htaccess|httpd\.conf|Caddyfile)$")),
    ("private-key-file", re.compile(r"\.(pem|key|p12|pfx)$|(^|/)id_(rsa|ed25519|ecdsa)$")),
    ("migration", re.compile(r"(^|/)(migrations?|db/migrate|alembic)/")),
    ("openapi-spec", re.compile(r"(openapi|swagger)[\w.-]*\.(json|ya?ml)$", re.I)),
]

MAX_PER_KIND = 400


def build(root: str, files: List[str], redactor=None) -> Dict:
    items: Dict[str, List[Dict]] = {}
    truncated: Dict[str, int] = {}

    def add(kind: str, rec: Dict) -> None:
        lst = items.setdefault(kind, [])
        if len(lst) >= MAX_PER_KIND:
            truncated[kind] = truncated.get(kind, 0) + 1
            return
        lst.append(rec)

    for rel in files:
        for kind, rx in CONFIG_KINDS:
            if rx.search(rel):
                add(kind, {"path": rel})
        ext = os.path.splitext(rel)[1].lower()
        applicable = [(k, r) for k, exts, r in _COMPILED if ext in exts]
        if not applicable:
            continue
        try:
            text = read_text(root, rel)
        except (OSError, ValueError):
            continue
        for ln, line in iter_lines(text):
            if len(line) > 2000:
                continue
            for kind, rx in applicable:
                if rx.search(line):
                    code = line.strip()[:200]
                    add(kind, {"path": rel, "line": ln, "code": redactor(code) if redactor else code})

    summary = {k: len(v) + truncated.get(k, 0) for k, v in sorted(items.items())}
    hints = _boundary_hints(summary)
    return {"summary": summary, "truncated": truncated,
            "items": {k: items[k] for k in sorted(items)}, "trust_boundary_hints": hints}


def _boundary_hints(s: Dict[str, int]) -> List[str]:
    h = []
    if s.get("http-route") or s.get("graphql"):
        h.append("Client -> server API boundary: every route/resolver needs authn + object/function-level authz review.")
    if s.get("db-query") or s.get("nosql-query"):
        h.append("Application -> datastore boundary: verify parameterization and least-privilege DB credentials.")
    if s.get("outbound-http"):
        h.append("Server -> external network boundary: check SSRF controls, TLS verification, timeouts, and unsafe consumption of third-party responses.")
    if s.get("subprocess"):
        h.append("Application -> OS boundary: verify no untrusted input reaches shell/exec arguments.")
    if s.get("file-upload") or s.get("file-access"):
        h.append("Application -> filesystem boundary: path traversal, upload validation, storage outside webroot.")
    if s.get("deserialization"):
        h.append("Untrusted data -> object graph boundary: deserialization of attacker-controlled bytes.")
    if s.get("ci-pipeline"):
        h.append("Contributor -> CI -> cloud/registry boundary: workflow triggers, token permissions, secret exposure.")
    if s.get("websocket"):
        h.append("Long-lived WebSocket boundary: origin validation and per-message authorization.")
    if s.get("payment"):
        h.append("Money-moving operations: business-logic, race-condition and idempotency review required.")
    return h
