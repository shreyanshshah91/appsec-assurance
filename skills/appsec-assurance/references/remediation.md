# Remediation (Mode 4)

## Workflow
1. Load `.appsec/out/findings.json`. Propose a fix plan ordered by the
   roadmap; group findings sharing a root cause (one parameterization helper
   fixes ten SQLi sites).
2. **Ask for explicit approval** listing which findings will be changed and
   which files will be touched. Approval for one batch does not extend to the next.
3. For each approved fix:
   - Write a regression test that **fails on the current code** (run it to show
     the failure). Use the project's test framework and conventions.
   - Apply the minimal fix following the project's style. Prefer framework
     primitives (ORM parameters, auto-escaping, policy middleware) over
     hand-rolled sanitizers.
   - Run the regression test and the relevant existing suite.
   - Re-run `appsec.py scan` and confirm the finding's fingerprint is gone; set
     status `fixed` in the manual file with the test name as evidence.
4. Summarize: fixed, partially mitigated, deferred (with reason), and new risks
   introduced (e.g. behaviour changes, breaking API changes).

## Never do automatically
- Rotate or revoke credentials, purge git history (`git filter-repo`), change
  cloud resources, modify branch protection, or force-push. Provide the exact
  commands and let the user run them.
- Disable a check, add a suppression, or edit the baseline to make a gate pass.
- Upgrade major dependency versions without flagging breaking changes.

## Secure alternatives quick reference
| Weakness | Preferred fix |
|---|---|
| SQL/NoSQL injection | Parameterized queries / query builders; type-coerce NoSQL inputs |
| Command injection | Argument arrays without shell; allowlists |
| XSS | Context-aware auto-escaping; sanitizer (DOMPurify, nh3) for required HTML; CSP with nonces; Trusted Types |
| SSRF | Allowlist hosts; resolve-then-check IP ranges; disable redirects; IMDSv2; egress firewall |
| IDOR/BOLA | Scope queries by owner/tenant; central policy; default deny; non-guessable IDs as defense in depth only |
| Deserialization | JSON + schema validation; safe loaders; class allowlists |
| Secrets | Secret manager / workload identity; rotate; pre-commit secret scanning |
| Weak crypto | AES-GCM/ChaCha20-Poly1305, Argon2id/bcrypt, TLS 1.2+, CSPRNG |
| CI injection | env indirection, SHA-pinned actions, least-privilege `permissions:` |
| Containers | non-root USER, read-only FS, drop capabilities, pinned digests |
