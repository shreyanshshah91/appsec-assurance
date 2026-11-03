# Severity, confidence and scoring

Severity answers *how bad if exploited*; confidence answers *how sure are we
it is real*; status answers *what has been proven*. Keep the three separate —
never raise confidence to make a finding look important, never lower severity
because exploitation is unproven (use status `suspected` instead).

## Severity levels

| Level | Meaning | Typical examples |
|---|---|---|
| critical | Remote, unauthenticated (or trivially obtained access) compromise of the system, its data at scale, or its supply chain | RCE via deserialization/command injection reachable pre-auth; SQLi on a public endpoint; live cloud admin keys in a public repo; pull_request_target running fork code with secrets |
| high | Significant compromise needing some precondition (authenticated user, user interaction, specific config) | IDOR exposing other users' PII; stored XSS in admin views; SSRF to internal network; JWT signature not verified; hardcoded production secret |
| medium | Limited impact or substantial preconditions; or a missing control that materially raises risk | Reflected XSS with CSP partially mitigating; CSRF on low-value action; missing rate limit on login; weak TLS config; container running as root |
| low | Defense-in-depth gaps, minor info disclosure | Version banners; missing Referrer-Policy; unpinned CI action; MD5 for non-security checksums |
| info | Observations and hardening notes with no direct risk | Install hooks inventory; large encoded blobs needing explanation |

Adjust rule defaults with context: reachability (public vs internal), data
sensitivity, compensating controls (verified, not assumed), and blast radius.
Document every adjustment in the triage reason.

## CVSS 3.1

Use CVSS for confirmed and strongly suspected technical vulnerabilities, not
for missing controls. Compute: `appsec.py cvss "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`.
Rule-supplied vectors are generic defaults — re-derive the vector from the
actual context before reporting a score. CVSS measures technical severity, not
business risk; the report severity may differ from the CVSS rating if the
reason is stated (e.g. internal-only admin tool). CVSS 4.0 vectors may be
included as text in `references`/description; the engine scores 3.1 only.

## Confidence

| Level | Requires |
|---|---|
| high | Direct evidence: exact source→sink path, reproducible PoC, or unambiguous config value |
| medium | Strong pattern match with plausible untrusted input, path not fully traced |
| low | Heuristic or partial signal (naming, entropy, test code) |

## Status

`confirmed` (reproduced or unambiguous), `suspected` (likely, unproven),
`unverified` (raw tool output, not yet triaged), `missing-control` (expected
safeguard absent), `false-positive`, `accepted-risk` (owner decision, recorded
with name/date in the reason), `fixed` (verified by rescan/regression test).

## Prioritization

Order remediation by: confirmed exploitability → exposure (internet-facing,
unauthenticated) → impact (data class, privilege) → ease of exploitation →
fix cost. Attack paths that chain lower-severity issues into a critical outcome
are prioritized by the chain's severity.
