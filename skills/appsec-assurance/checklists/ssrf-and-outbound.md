# SSRF and outbound requests

Scope: any server-side code that makes network requests whose destination,
path, or redirects are influenced by users or third parties: URL fetchers,
link previews, webhooks, import-from-URL, OAuth/OIDC discovery, XML/SVG/PDF
renderers, image proxies, and integrations. Includes redirect handling, DNS
rebinding, cloud metadata exposure and open redirects that feed SSRF chains.

**Applies when:** inventory shows outbound HTTP clients (`requests`, `httpx`,
`urllib`, `axios`, `fetch`, `got`, `node-fetch`, `HttpClient`, `RestTemplate`,
`WebClient`, `net/http`, `curl`), webhook registration, headless browsers, or
document converters.

**Standards:** OWASP A10:2021 SSRF; API7:2023 Server Side Request Forgery,
API10:2023 Unsafe Consumption of APIs; ASVS V1 Encoding and Sanitization, V4 API
and Web Service, V13 Configuration; CWE-918, CWE-601, CWE-441, CWE-350.

## Items

- **SSRF-01 — Inventory every user-influenced outbound request** (high)
  - Verify: grep client calls and trace the URL argument: `requests.(get|post)\(`, `urlopen\(`, `axios\(`, `fetch\(`, `got\(`, `http.Get\(`, `new URL\(`, `RestTemplate.getForObject`, `WebClient.create`, `HttpClient.GetAsync`, `file_get_contents\(\$`, `curl_setopt.*CURLOPT_URL`. Include host *and* path/query building (partial SSRF: `base + userPath`).
  - Fail: any destination component derived from request data without validation.
- **SSRF-02 — Destination allowlist, not denylist** (high)
  - Verify: allowlist of hosts/domains (exact match after parsing), schemes limited to `https` (and `http` only if needed). Denylists of `127.0.0.1`/`localhost` are bypassed by decimal/octal/IPv6 (`[::1]`, `0`, `2130706433`, `::ffff:127.0.0.1`), DNS names resolving to internal IPs, and redirects.
  - Fail: string-based `if 'localhost' in url` checks; regexes on the raw URL.
- **SSRF-03 — Resolved-IP validation and DNS rebinding** (high)
  - Verify: when arbitrary hosts are allowed (webhooks, previews), the client resolves the name, rejects private/loopback/link-local/multicast/reserved ranges (RFC 1918, 127/8, 169.254/16, 100.64/10, fc00::/7, fe80::/10, ::1, 0.0.0.0) **and connects to the validated IP** (pinned resolver / custom agent / egress proxy like smokescreen). Check libraries: `ssrf-req-filter`, `request-filtering-agent`, `advocate`, custom `DialContext`.
  - Fail: validate-then-fetch with a second DNS lookup (TOCTOU rebinding).
- **SSRF-04 — Redirect handling** (high)
  - Verify: redirects disabled or each hop re-validated (`allow_redirects=False`, `maxRedirects: 0`, `CheckRedirect` in Go, `HttpClientHandler.AllowAutoRedirect=false`).
  - Fail: allowlisted external host 302s to `http://169.254.169.254/`.
- **SSRF-05 — Scheme and protocol smuggling** (high)
  - Verify: `file://`, `gopher://`, `dict://`, `ftp://`, `jar:`, `netdoc:` blocked; libcurl `CURLOPT_PROTOCOLS` restricted; Java `URL` handler use; URL parser differentials (`http://allowed.com@evil`, `http://evil#@allowed`, backslashes).
  - Fail: user URL passed to a multi-protocol fetcher.
- **SSRF-06 — Cloud metadata protection** (critical when reachable)
  - Verify: AWS IMDSv2 required (`http_tokens = "required"`, hop limit 1 for containers), GCP/Azure metadata require headers but are still reachable by header-controllable SSRF; K8s pods blocked from metadata by NetworkPolicy; check whether the fetcher lets users set headers.
  - Fail: SSRF + IMDSv1 → instance role credentials. Chain severity critical.
- **SSRF-07 — Webhooks** (medium–high)
  - Verify: webhook URLs validated at registration *and* at delivery (DNS changes); deliveries from an isolated egress with no internal network access; timeouts and size limits; response bodies not shown verbatim to the user (blind→full SSRF); outbound webhook payloads signed (HMAC with timestamp) so receivers can verify.
  - Fail: webhook test button displays internal service responses.
- **SSRF-08 — Inbound webhook verification** (high)
  - Verify: third-party callbacks (Stripe, GitHub, Slack, Twilio) verified by signature with constant-time compare and timestamp tolerance; raw body used for HMAC.
  - Fail: trusting unsigned callbacks or source IP alone.
- **SSRF-09 — Headless browsers and document renderers** (high)
  - Verify: Puppeteer/Playwright/wkhtmltopdf/WeasyPrint/LibreOffice/ImageMagick/ffmpeg rendering user HTML/SVG/Office files can fetch `file://` and internal URLs. Check request interception, `--disable-local-file-access`/`enable-local-file-access` flags, WeasyPrint `url_fetcher`, ImageMagick `policy.xml`, ffmpeg `-protocol_whitelist`, network isolation of renderer.
  - Fail: `<iframe src="file:///etc/passwd">` or `<img src="http://169.254.169.254/">` in PDF export input.
- **SSRF-10 — XML, SVG and import features** (high)
  - Verify: external entities and `xi:include` disabled (see deserialization-and-parsers.md); "import from URL", RSS readers, OpenGraph/oEmbed unfurlers, avatar-from-URL.
  - Fail: feature fetches any URL with server privileges.
- **SSRF-11 — Open redirects** (medium; high when chained with OAuth/SSRF)
  - Verify: `redirect(request.args['next'])`, `res.redirect(req.query.url)`, `returnUrl`, `continue`, `RedirectResult(...)`. Require relative paths (reject `//`, `/\`, schemes) or allowlist.
  - Fail: `?next=//evil.example` redirects off-site.
- **SSRF-12 — Egress controls and timeouts** (medium)
  - Verify: egress firewall/security group/NetworkPolicy limiting outbound from app tier; per-request timeouts, response size caps, connection limits.
  - Fail: no timeout (resource exhaustion) and unrestricted egress (record as missing-control).
- **SSRF-13 — Credentials attached to outbound calls** (high)
  - Verify: HTTP clients configured with default auth headers/cookies/mTLS certs used for user-directed URLs.
  - Fail: internal service token sent to attacker-chosen host.

## Common false positives
- Requests to hard-coded constants or config-only URLs not influenced by users.
- Allowlisted SaaS endpoints with redirects disabled.
- SSRF in a sandboxed renderer with verified no-network isolation (confirm the isolation config).

## Safe validation ideas
- Unit-test the URL validator with a list of bypass encodings (`http://0/`, `http://[::1]/`, `http://2130706433/`, `http://localhost.appsec-canary.invalid/`) and assert rejection — no network calls.
- Locally, stand up a listener on `127.0.0.1:<port>` that logs `appsec-canary-<rand>` and point the fetcher at it inside the authorized environment.
- Never target real cloud metadata endpoints, internal production services, or third-party hosts; never use out-of-band collaborator services outside scope.
