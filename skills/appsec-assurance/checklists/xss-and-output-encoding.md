# XSS and output encoding

Scope: reflected, stored and DOM-based cross-site scripting; context-correct
output encoding (HTML body, attribute, URL, JS, CSS); framework auto-escaping
and its escape hatches; HTML sanitizers; Markdown and rich-text rendering; SVG
and other active content served from the application origin.

**Applies when:** the app renders HTML server-side, ships a SPA/SSR frontend,
renders Markdown/rich text/user HTML, serves user uploads inline, or generates
emails/PDFs from HTML.

**Standards:** OWASP A03:2021 Injection; ASVS V1 Encoding and Sanitization, V3
Web Frontend Security; CWE-79, CWE-80, CWE-83, CWE-87, CWE-116, CWE-1236 (CSV export).

## Items

- **XSS-01 — Auto-escaping enabled in server templates** (high)
  - Verify: Jinja2 `autoescape=True`/`select_autoescape` (Flask enables for .html only), Django default on, ERB `<%= %>` escapes in Rails, Go `html/template` (not `text/template`) for HTML, Thymeleaf `th:text`, Razor `@`, Blade `{{ }}`, Twig autoescape.
  - Fail: `text/template` for HTML; `autoescape=False`; templates with non-.html extensions rendering HTML in Flask.
- **XSS-02 — Server-side escape hatches** (high)
  - Verify: grep `\|safe`, `mark_safe`, `{% autoescape off`, `Markup(`, `raw(`, `html_safe`, `<%==`, `{!! !!}` (Blade), `th:utext`, `@Html.Raw`, `template.HTML(`, `{{{ }}}` (Handlebars/Mustache), `<%-` (EJS).
  - Fail: any of these applied to data that is user-controlled or not sanitized immediately before.
- **XSS-03 — Client framework escape hatches** (high)
  - Verify: `dangerouslySetInnerHTML`, `v-html`, `[innerHTML]` + `bypassSecurityTrust*` (Angular), `{@html}` (Svelte), `innerHTML=`, `outerHTML`, `insertAdjacentHTML`, `document.write`, jQuery `.html(`/`.append(` with strings, `$(userString)`.
  - Fail: unsanitized user data reaches these sinks.
- **XSS-04 — DOM XSS sources to sinks** (high)
  - Verify: trace `location.hash`, `location.search`, `URLSearchParams`, `document.referrer`, `window.name`, `postMessage` data, `localStorage` values to sinks above and to `eval`, `setTimeout(string)`, `new Function`, `script.src`, `iframe.srcdoc`.
  - Fail: any unencoded flow; client-side routers that render query params as HTML.
- **XSS-05 — URL-context injection (`javascript:` URLs)** (high)
  - Verify: user-supplied URLs bound to `href`, `src`, `action`, `formaction`, `xlink:href`, `window.location =`, `router.push(external)`. React escapes text but *not* `javascript:` in `href` (warns only). Look for scheme allowlist (`http`, `https`, `mailto`).
  - Fail: profile "website" field rendered as `<a href={user.url}>` without scheme check.
- **XSS-06 — Attribute, JS and CSS contexts** (high)
  - Verify: data placed inside `<script>` blocks (`var x = "{{ user }}"`), inline event handlers, unquoted attributes, `style=` attributes. Use JSON serialization with `<`/`>`/`&`/U+2028 escaping (`json_script`, `serialize-javascript`, `JSON.stringify` + escape) for script contexts.
  - Fail: HTML-escaped value inside JS string (HTML escaping is wrong for JS context); `</script>` breakout from embedded JSON state (SSR hydration blobs like `window.__INITIAL_STATE__`).
- **XSS-07 — Stored XSS in all render paths** (high)
  - Verify: user content rendered in admin panels, email templates, notifications, PDF exports, CSV-to-HTML previews, support tooling, log viewers. Admin views often bypass the main frontend's escaping.
  - Fail: safe in the user UI, raw in the admin UI.
- **XSS-08 — HTML sanitizer usage** (high)
  - Verify: DOMPurify (version, config — `ALLOW_UNKNOWN_PROTOCOLS`, `ADD_TAGS`, `WHOLE_DOCUMENT`), bleach (deprecated — note it), nh3/ammonia, sanitize-html (`allowedTags`, `allowedSchemes`), OWASP Java HTML Sanitizer, HtmlSanitizer (.NET), Rails `sanitize`. Sanitize on output or immediately before sink; do not mutate after sanitizing.
  - Fail: regex-based "sanitizers"; sanitize-then-modify (e.g. string replace after DOMPurify); allowing `style`, `iframe`, `form`, `on*`, `srcdoc`, `data:` URLs; outdated sanitizer with known bypasses.
- **XSS-09 — Markdown rendering** (high)
  - Verify: marked/markdown-it (`html: true`?), showdown, python-markdown, commonmark, react-markdown (`rehype-raw` enables raw HTML), MDX (executes JS — never for user content). Check link scheme filtering and whether output is sanitized afterwards.
  - Fail: raw HTML passthrough; `[x](javascript:...)` links; MDX/compiled templates from users.
- **XSS-10 — SVG and active content uploads** (high)
  - Verify: user-uploaded SVG/HTML/XML/PDF served from app origin with `Content-Type: image/svg+xml` or `text/html`; avatar/logo uploads. Look for separate sandbox domain, `Content-Disposition: attachment`, `Content-Security-Policy: sandbox`, SVG sanitization or rasterization.
  - Fail: SVG with `<script>`/`onload` executes on the main origin.
- **XSS-11 — Content-Type and sniffing** (medium)
  - Verify: JSON endpoints return `application/json`; `X-Content-Type-Options: nosniff`; JSONP endpoints (`callback=` param) validated or removed.
  - Fail: user data reflected in `text/html` error responses; unvalidated JSONP callback.
- **XSS-12 — Rich-text editors and WYSIWYG** (medium)
  - Verify: server re-sanitizes editor output (Quill, TipTap, CKEditor, TinyMCE). Client-side-only sanitization is bypassed by direct API calls.
  - Fail: server stores and renders editor HTML as trusted.
- **XSS-13 — Non-HTML output channels** (medium)
  - Verify: CSV/Excel exports (formula injection: values starting `=`, `+`, `-`, `@`, tab, CR — CWE-1236), HTML emails, PDF generators rendering HTML (wkhtmltopdf/Puppeteer — also an SSRF vector).
  - Fail: user-controlled cells exported unprefixed; HTML email templates with unescaped user names.
- **XSS-14 — Trusted Types / CSP as defense in depth** (low–medium)
  - Verify: CSP `script-src` without `unsafe-inline`; `require-trusted-types-for 'script'` on high-value apps. See csrf-cors-headers-csp.md.
  - Fail: no CSP on an app with any escape hatch in use (record as missing-control).

## Common false positives
- `dangerouslySetInnerHTML` / `v-html` with constant strings or i18n bundles shipped by the developer.
- `|safe` on output of a sanitizer called on the same line/function.
- Reflection in `application/json` responses with `nosniff` (not directly exploitable, but check consumers).
- Self-XSS requiring the victim to paste payloads (report info/low only if chained).

## Safe validation ideas
- Use a non-executing marker: `appsec-canary-<rand>"'<>` and inspect the rendered HTML for unescaped `<`, `"` — no script execution needed.
- If execution proof is approved in a local env, use `<img src=x onerror=console.log('appsec-canary-<rand>')>` — never cookie theft, external beacons or `alert` loops.
- Unit-test sanitizers by feeding a fixed list of benign probe strings and asserting `on*`/`javascript:` are stripped.
- For SVG: upload a local SVG containing only a `<desc>appsec-canary</desc>` and an inert `onload` that logs to console, and check the served `Content-Type` and `Content-Disposition`.
