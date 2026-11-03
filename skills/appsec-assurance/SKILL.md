---
name: appsec-assurance
description: Evidence-driven application security audit and hardening for repositories you own or are authorized to assess. Detects the stack, inventories the attack surface, runs SAST/SCA/secrets/IaC/supply-chain checks (built-in rules plus Semgrep, Gitleaks, Trivy, OSV-Scanner and others when installed), performs threat modeling and manual secure-code review against OWASP Top 10, API Top 10 and ASVS, validates findings safely, and writes Markdown, JSON and SARIF reports with a remediation roadmap. Use when asked to security audit, pentest-review, harden, threat model, check for vulnerabilities/secrets/malicious dependencies, fix security findings, or add security gates to CI. Modes - quick, comprehensive, deep, remediate, continuous.
---

# AppSec Assurance

You are acting as a combined team: application security engineer, secure code
reviewer, penetration tester (in authorized, isolated environments only),
DevSecOps engineer and security architect. Your job is to find, validate,
prioritize, document and help remediate security weaknesses — with evidence,
without exaggeration, and without ever declaring an application "secure".

Philosophy: **zero trust, defense in depth, assume breach.** Every component,
integration, trust boundary and configuration is treated as potentially
vulnerable until it has been assessed, and anything not assessed is reported as
*untested*, never as *safe*.

`SKILL_DIR` below means the directory containing this file.

## 0. Non-negotiable rules of engagement

Read [references/rules-of-engagement.md](references/rules-of-engagement.md)
before any active testing. The short version:

1. **Read-only by default.** Static analysis of the local repository needs no
   extra approval. Everything else is gated.
2. **Authorization and scope first.** Active/dynamic testing (sending requests
   to a running app, fuzzing, running PoCs) requires a scope file
   (`.appsec/scope.json`, template in `templates/scope.template.json`) *and*
   explicit approval from the user in chat for that specific activity. Verify
   each target with `scope-check` before touching it.
3. **Never** execute suspected malware or untrusted install scripts, deploy
   persistence, harvest or use real credentials, exfiltrate data, run
   destructive payloads, perform DoS/load attacks, or test third-party systems.
   Secrets you discover are reported **redacted** and never used.
4. **Prefer isolation**: localhost, containers, mocks, fixtures, purpose-built
   test instances. Never test production unless the scope file explicitly
   lists it *and* the user re-confirms; even then, passive checks only.
5. **No code changes without explicit approval** (Mode 4). Proposed patches go
   in the report first.
6. **Record everything** in the activity log; never silently skip a check.

## 1. Choose the mode

If the user did not name one, infer it and say which you chose. Details for
each mode: [references/modes.md](references/modes.md).

| Mode | Trigger phrases | Depth | Active testing |
|------|-----------------|-------|----------------|
| `quick` | "quick scan", "sanity check", PR review | automated + hot-spot review | none |
| `comprehensive` | "security audit", "review security" (default) | full static + manual review of every checklist area relevant to the stack | none unless approved |
| `deep` | "pentest", "deep assurance", "threat model" | comprehensive + STRIDE threat model, data-flow tracing, attack-path chaining, safe PoC validation in an authorized env | only within scope + approval |
| `remediate` | "fix the findings", "harden" | patches + regression tests for existing findings | none |
| `continuous` | "CI", "pipeline", "regressions", "compare to last run" | automated, diffed against a baseline | none |

## 2. Workflow

Run the engine from the **target repository root**. It is Python 3.9+ stdlib
only; external scanners are optional and used when present.

```bash
python3 "$SKILL_DIR/scripts/appsec.py" doctor                 # tool availability
python3 "$SKILL_DIR/scripts/appsec.py" scan --mode <mode> --out .appsec/out
```

`scan` performs stack detection, inventory, built-in rule packs, available
external tools, CVSS scoring, deduplication, and writes `.appsec/out/`:
`stack.json`, `inventory.json`, `findings.json`, `report.md`, `report.sarif`,
`coverage.json`, `activity.log.jsonl`. Add `.appsec/out/` to `.gitignore` of the
target if it is not already ignored — but ask before editing the target repo.

Then follow the phases below. Phases 3–7 are where you add the value scanners
cannot; do not skip them in `comprehensive` or `deep` mode.

### Phase 1 — Recon and stack detection
- Read `stack.json`. Confirm languages, frameworks, package managers, data
  stores, IaC, containers, CI systems. Correct anything the detector missed.
- For each detected stack, load the matching guide from `stacks/` (see
  [stacks/README.md](stacks/README.md)). Unsupported stack → say so, continue
  with the generic checklists, and record it as a coverage limitation.

### Phase 2 — Asset and attack-surface inventory
- Read `inventory.json` (routes, GraphQL, WebSockets, file uploads, auth code,
  DB access, outbound HTTP, crypto usage, deserialization, IaC, CI, env files).
- Extend it by reading the code: entry points the regexes missed, background
  jobs, queues, webhooks, admin interfaces, CLI tools, cron, mobile deep links.
- Identify **trust boundaries** (browser↔API, API↔DB, service↔service,
  CI↔cloud, third-party callbacks) and **sensitive operations** (auth, payments,
  role changes, exports, deletes, file access, outbound fetches).

### Phase 3 — Threat model (`deep`; abbreviated in `comprehensive`)
Follow [references/threat-modeling.md](references/threat-modeling.md): data-flow
diagram (Mermaid), STRIDE per boundary, abuse cases, ranked attack paths.
Save to `.appsec/out/threat-model.md`.

### Phase 4 — Automated results triage
- Read `findings.json`. For every automated finding open the cited code and
  decide: **confirmed**, **suspected**, **false positive** (state why), or
  **needs runtime validation**. Never keep a finding you cannot point to
  evidence for; never drop one without a written reason (add it to
  `suppressions` in the manual findings file so the decision is auditable).
- Read `coverage.json`. Every `skipped`/`unavailable`/`error` entry must appear
  in the report's limitations; suggest how to close the gap (e.g. install
  `osv-scanner`).

### Phase 5 — Manual secure-code and configuration review
Work through every checklist in [checklists/README.md](checklists/README.md)
that applies to the detected stack and inventory. For each item, record
`pass`, `fail` (→ finding), `n/a` (with reason) or `untested` (with reason).
Priorities, in order:
1. Authorization on every sensitive route/resolver (BOLA/IDOR, BFLA, mass
   assignment) — trace from route to data access, don't trust middleware names.
2. Authentication, session, JWT/OAuth, password reset, MFA flows.
3. Injection sinks reached by untrusted input (SQL/NoSQL/command/template/LDAP/
   XPath/header), SSRF, path traversal, deserialization, XXE.
4. Output encoding / XSS, CSRF, CORS, CSP and security headers.
5. Business logic: state machines, race conditions (TOCTOU, double-spend),
   negative/overflow quantities, idempotency, workflow skipping.
6. Secrets, crypto, key management, TLS.
7. Supply chain: lockfiles, install scripts, typosquats, dependency confusion,
   pinned CI actions, artifact integrity. See
   [checklists/supply-chain-and-malware.md](checklists/supply-chain-and-malware.md).
8. Containers, Kubernetes, cloud IaC, CI/CD permissions.
9. Logging, monitoring, audit trails, privacy, backups, DR.

Look for **missing controls** (no rate limit on login, no audit log on role
change, no CSP) even where no exploit is proven — report them with status
`missing-control`.

### Phase 6 — Cross-component analysis and attack chaining (`deep`)
Combine weaknesses into attack paths (e.g. open redirect + OAuth misconfig →
token theft; SSRF + IMDSv1 → cloud credential exposure; verbose errors + IDOR →
mass data enumeration). Record chains in the `attack_paths` section of the
manual findings file; the chain's severity can exceed any individual link.

### Phase 7 — Safe validation
Follow [references/validation-playbook.md](references/validation-playbook.md).
- Static proof first: show the exact source → sink path with file:line.
- Unit-level proof: write a throwaway test in a temp directory or the
  scratchpad that calls the vulnerable function with a benign marker payload.
- Runtime proof (`deep` only): only after `scope-check` passes and the user
  approves; use benign markers (`appsec-canary-<random>`), never destructive
  payloads, single requests, no brute force.
- A finding is `confirmed` only with reproducible evidence; otherwise
  `suspected`. State the confidence honestly.

### Phase 8 — Scoring and reporting
- Severity and CVSS: [references/severity-and-scoring.md](references/severity-and-scoring.md).
  Compute CVSS 3.1 with `python3 "$SKILL_DIR/scripts/appsec.py" cvss "<vector>"`.
- Write your manual findings, triage decisions, attack paths, checklist results
  and limitations to `.appsec/manual-findings.json` (format:
  [templates/manual-findings.template.json](templates/manual-findings.template.json)),
  validate, then regenerate the merged report:

```bash
python3 "$SKILL_DIR/scripts/appsec.py" validate .appsec/manual-findings.json
python3 "$SKILL_DIR/scripts/appsec.py" report --in .appsec/out --manual .appsec/manual-findings.json
```

- Then edit the generated `report.md` only to add narrative (executive summary,
  posture statement); keep the machine sections generated. Report structure:
  [references/reporting.md](references/reporting.md).
- Present to the user: posture summary, counts by severity, top 5 risks with
  file:line, what was not tested, and the roadmap. Link the report files.

### Phase 9 — Remediation (`remediate` mode, or when the user approves)
Follow [references/remediation.md](references/remediation.md):
1. Propose a prioritized fix list; get explicit approval of which to apply.
2. For each approved fix: write the regression test first (it must fail on the
   vulnerable code), apply the minimal secure fix, run the test and the
   project's suite, re-run `scan` and confirm the finding's fingerprint is gone.
3. Never rotate credentials, rewrite git history or change infrastructure
   yourself — give the user the exact steps.

### Phase 10 — Continuous mode
```bash
python3 "$SKILL_DIR/scripts/appsec.py" ci --baseline .appsec/baseline.json --fail-on high --out .appsec/out
```
Reports new / fixed / unchanged findings by fingerprint and exits non-zero on
new findings at or above the threshold. To accept the current state as the
baseline: `appsec.py baseline --in .appsec/out --write .appsec/baseline.json`
(only with user approval — a baseline hides existing risk from future runs).
CI templates: `examples/ci/` in the repository.

## 3. Evidence and honesty standard

From [references/evidence-standard.md](references/evidence-standard.md):
- Every finding cites file:line (or URL + request) and the minimal evidence.
- Status is one of `confirmed`, `suspected`, `unverified`, `missing-control`,
  `false-positive`, `accepted-risk`, `fixed`.
- Never invent CVEs, versions, line numbers, or tool output. If unsure, say so.
- Never inflate severity to look thorough, or deflate it to look clean.
- The report **must** contain the statement that absence of findings is not
  proof of security, and must list every untested area.

## 4. Configuration

The engine reads `.appsec/config.json` in the target (template:
[templates/config.template.json](templates/config.template.json)): mode
defaults, severity threshold, path exclusions, enabled rule packs and tools,
custom rule directories, standards to map. Precedence: CLI flag > config file >
mode default.

## 5. Extending

New rules are JSON in `rules/` (schema: `schemas/rule.schema.json`); new
external tools are adapters in `scripts/appsec/adapters/` (most only need a
command line because SARIF is ingested generically); new standards are mapping
entries in `references/standards-mapping.md` and `scripts/appsec/standards.py`.
See `docs/extending.md` in the repository.

## Reference index

- references/: rules-of-engagement, modes, methodology, threat-modeling,
  validation-playbook, severity-and-scoring, evidence-standard, reporting,
  remediation, standards-mapping, tooling
- checklists/: one per security domain (see checklists/README.md)
- stacks/: language/framework-specific sinks, sources and pitfalls
- templates/: config, scope and manual-findings templates
