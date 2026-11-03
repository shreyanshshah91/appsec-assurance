# Security policy

## Reporting a vulnerability in this project
Please report vulnerabilities in the skill or engine (for example, a way to make it leak secrets into
reports, bypass the scope gate, or execute code from a scanned repository) privately via GitHub's
"Report a vulnerability" (Security Advisories) on this repository. Do not open a public issue.
We aim to acknowledge within 5 business days.

## Scope of this tool
appsec-assurance is intended for assessing systems you own or are explicitly authorized to test.
It defaults to read-only, local static analysis; any network-based testing is gated by a scope file
and explicit operator approval. Misuse against systems you are not authorized to test is prohibited.

## Design guarantees we treat as security bugs if broken
- Discovered secrets are redacted in every output file.
- The engine never executes code from the scanned repository (it reads files; external tools you
  installed run with your permissions).
- `scope-check`/`dast` deny targets not explicitly listed, expired scopes, and active testing of production.
