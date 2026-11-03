# Safe validation playbook

Goal: move findings from `suspected` to `confirmed` (or to `false-positive`)
with the least intrusive method that produces reproducible evidence.

## Ladder (use the lowest rung that settles the question)

1. **Static proof** — full source→sink trace with file:line, showing no
   sanitizer/guard on the path. Often enough for `confirmed` when unambiguous.
2. **Unit-level proof** — a throwaway test (in the scratchpad or a temp dir,
   not committed unless the user approves) that calls the vulnerable function
   directly with a benign marker. No network, no real data.
3. **Local runtime proof** — the app running locally/in a container with seed
   data, after `scope-check` passes and the user approves. Single requests.
4. **Staging proof** — only if listed in scope with the activity allowed and
   approved; passive or the narrowest benign probe.

## Benign probe catalogue

| Class | Probe | Success signal | Never |
|---|---|---|---|
| SQLi | `' OR '1'='1` on a read-only query in local DB; or ORDER BY column index | Row count/ordering change, SQL error text | stacked queries, `DROP`, `SLEEP`, data extraction |
| Command injection | `;echo appsec-canary-1a2b` in local env | marker in output | `rm`, reverse shells, network callbacks |
| SSTI | `{{7*7}}` / `${7*7}` | `49` rendered | object traversal to RCE |
| XSS | `<appsec-canary-1a2b>` or `"><svg data-x=appsec-canary>` | unencoded marker in DOM | cookie theft scripts, external script loads |
| SSRF | URL to a local listener you started (`python3 -m http.server` on 127.0.0.1) | request received | cloud metadata IPs, internal production hosts |
| Path traversal | `../` to a marker file you created in the fixture | marker contents | `/etc/shadow`, real secrets |
| IDOR/BOLA | two seeded test users; A requests B's object | 200 with B's data | real customer IDs, enumeration loops |
| CSRF | local HTML form posting to the app with a test session | state change without token | real user sessions |
| Deserialization | serialized object of a harmless class / gadget-free type confusion check | type accepted / error path proves deserialization of input | gadget chains that execute code |
| Race condition | 2–5 concurrent requests against local instance | duplicate effect | sustained load |
| Rate limiting | ≤20 sequential login attempts on a test account in local env | no 429 / lockout | anything against shared or production systems |

## Recording
For each validated finding: `validation_steps` (numbered, reproducible),
observed vs expected result, environment used, and the exact command/request
(with secrets/PII removed). Log the activity (it is appended to
`activity.log.jsonl` when run via `appsec.py dast`; note manual runs in
`limitations` or the finding evidence).

## Re-validation after remediation
Re-run the same probe and the regression test; rescan; confirm the fingerprint
is gone or the status can move to `fixed` with evidence.
