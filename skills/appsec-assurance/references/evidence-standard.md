# Evidence and honesty standard

1. **Every finding is anchored**: `path:line` (or URL + method + parameter),
   the minimal code/config excerpt, and why it is a weakness.
2. **Trace, don't pattern-match**, for anything above low: show where the
   untrusted input enters, each transformation, and the sink. If a step is
   assumed, say so and use `suspected`.
3. **No fabrication**: never invent CVE IDs, package versions, line numbers,
   tool output, HTTP responses, or "observed" behaviour. If you did not run it,
   do not say you saw it. CVEs come only from tool/advisory output you have.
4. **Redact**: secrets appear as `abcd…[redacted N chars]`; PII is masked.
5. **False positives are decisions**: closing an automated finding requires a
   written reason in `triage` (it stays visible in the report's closed section).
6. **Missing ≠ safe**: an area you could not examine is listed as untested
   with the reason. Coverage gaps from tools are carried into the report
   automatically; add your own to `limitations`.
7. **Compensating controls must be verified**, not assumed from names
   (`sanitize()` that doesn't sanitize; `authMiddleware` not mounted on the
   router).
8. **Language discipline**: "we found no evidence of X in the areas reviewed"
   — never "the application is secure", "no vulnerabilities exist", or
   "fully compliant".
9. **Confidence is reported honestly**, including when the reviewer is unsure
   whether a framework auto-escapes or a library version is affected.
10. **Reproducibility**: validation steps must be runnable by a developer in a
    safe environment, with benign inputs, and state the expected secure result.
