# Assessment modes

| | quick | comprehensive | deep | remediate | continuous |
|---|---|---|---|---|---|
| Engine profile | medium+ confidence rules; gitleaks, osv-scanner only | all rules; all applicable tools | all + installed-dependency install-hook scan + gitleaks git history | as comprehensive | medium+ confidence; all applicable tools |
| Manual review | hot spots only | every applicable checklist | every checklist item recorded | re-verify fixed items | none (automated) |
| Threat model | no | abbreviated (boundaries + top abuse cases) | full STRIDE + attack paths | no | no |
| Active validation | no | only if user asks + scope | yes, within scope + approval | local regression tests only | no |
| Typical time | minutes | hours | a day+ for large apps | per fix | per CI run |

## Mode 1 — quick
1. `scan --mode quick`.
2. Triage every critical/high automated finding (open the code, decide status).
3. Spot-check: auth middleware coverage on routes, the most dangerous sinks in
   inventory (`subprocess`, `deserialization`, `db-query` with string building).
4. Report: top risks, what was *not* covered (most of the manual-only areas).

## Mode 2 — comprehensive (default)
Phases 1–5 and 8 of SKILL.md, abbreviated phase 3. Every checklist relevant to
the detected stack gets a recorded result. Aim for full route coverage on
authorization review; if the app is too large, sample systematically (every
route of the most sensitive modules + random sample elsewhere) and say so.

## Mode 3 — deep
All phases. Additionally:
- Full threat model (`references/threat-modeling.md`) saved as an artifact.
- Source→sink tracing for every inventory entry in `db-query`, `subprocess`,
  `deserialization`, `outbound-http`, `file-access`, `template-render`.
- Cross-component review: frontend assumptions vs backend enforcement, service
  to service auth, CI to cloud trust (OIDC conditions), IaC vs app config.
- Safe adversarial validation per `validation-playbook.md` in the authorized
  environment; every PoC approved individually.
- Run `scan --mode deep --osv-api` only if the user agreed to the OSV lookup.

## Mode 4 — remediate
Input: an existing `.appsec/out/findings.json` (run comprehensive first if
absent). Follow `remediation.md`. Output: patches applied only after approval,
regression tests, rescan diff showing the fingerprints gone.

## Mode 5 — continuous
`appsec.py ci --baseline .appsec/baseline.json --fail-on high`. Diff by
fingerprint; gate only on *new* findings at/above the threshold; upload
`report.sarif` to code scanning. Templates in `examples/ci/`. Never auto-update
the baseline in CI — baseline changes are reviewed in a PR.

**Trust boundary:** on pull/merge requests, load `.appsec/config.json` and
`.appsec/baseline.json` from the *base* branch (the templates do this). If the
gate reads them from the PR's own checkout, a PR can add exclusions, disable
rules, downgrade severities or baseline its own findings and pass its own gate.
Protect `.appsec/` with CODEOWNERS so changes to it need security review.
