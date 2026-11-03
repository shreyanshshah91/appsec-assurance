# Usage guide

## In Claude Code
Ask in natural language, or invoke `/appsec-assurance` with a mode:

| You say | Mode |
|---|---|
| "Quick security check of this PR" | quick |
| "Do a security audit of this repo" | comprehensive |
| "Deep security assurance with threat model; staging is at https://staging.example.com, scope file is .appsec/scope.json" | deep |
| "Fix the high findings from the last audit" | remediate |
| "Add a security gate to our GitHub Actions" | continuous |

Claude will: run the engine, read the results, review code against the checklists, ask before anything
that sends traffic or changes files, write `.appsec/manual-findings.json`, and regenerate the report.

## CLI reference (engine only)
```text
appsec.py doctor                          tool availability
appsec.py rules                           list built-in rules
appsec.py scan [--mode M] [--out D] [--offline] [--osv-api] [--no-tools] [--tools a,b] [--fail-on SEV] [--deterministic]
appsec.py report --in D [--manual FILE]   merge manual review, regenerate reports
appsec.py validate FILE                   validate manual findings file
appsec.py cvss VECTOR                     CVSS 3.1 base score
appsec.py ci --baseline FILE --fail-on SEV [scan options]
appsec.py baseline --in D --write FILE    accept current open findings as baseline
appsec.py diff --baseline A --current B   compare two findings files
appsec.py scope-check --scope FILE --target URL --activity A
appsec.py dast --scope FILE --target URL --approved [--zap]
```
Exit codes: 0 ok · 1 gate failed · 2 error · 3 denied by scope.

## Inline suppression
`# appsec-ignore RULE-ID <reason>` on the same line suppresses that rule there. Prefer recording a
`triage` decision in the manual findings file — it stays visible in the report.

## Interpreting results
- `unverified` = raw automated output. Treat as leads until triaged.
- `missing-control` = an expected safeguard is absent; not necessarily exploitable alone.
- The posture indicator only reflects checks that ran. Read section 8 (limitations) before sharing.
