# Reporting

`appsec.py report` generates all machine sections. Claude adds narrative via
the manual findings file (`executive_summary`, `posture_statement`,
`limitations`, `attack_paths`, `checklist_results`, `findings`, `triage`).

## report.md structure
1. Metadata (mode, engine, commit, files scanned, whether manual review merged)
   and the mandatory assurance statement.
2. Executive summary — for leadership: what, how bad, what first. No jargon.
3. Overall posture — risk indicator (critical / high / elevated / guarded /
   no-open-findings) + analyst statement. Never "secure".
4. Technologies and components assessed; attack-surface summary; trust
   boundaries.
5. Standards and coverage — OWASP Top 10 mapping, the full check ledger
   (ran / skipped / unavailable / error / not-applicable with reasons),
   manual checklist results.
6. Attack paths.
7. Findings — summary table + per-finding detail: severity, CVSS, status,
   confidence, CWE/OWASP, location, redacted snippet, evidence, impact, safe
   validation steps, remediation, suggested patch (not applied), regression test.
8. Triaged and closed items with reasons.
9. Untested areas and limitations.
10. Prioritized remediation roadmap (immediate / ≤30 / ≤90 days / backlog).
11. Regression testing.

## Machine-readable outputs
- `findings.json` — full results document (schema: `schemas/finding.schema.json` per finding).
- `report.sarif` — SARIF 2.1.0 with `security-severity` and stable
  `partialFingerprints`; upload to GitHub code scanning.
- `coverage.json`, `inventory.json`, `stack.json`, `activity.log.jsonl`.
- Continuous mode: `diff.json`, `diff.md`.

## Presenting results in chat
Lead with the posture indicator and counts, then the top 5 risks with
`file:line` links, then what was not tested, then the roadmap's first items.
Link the report files. Offer remediation (Mode 4) as a next step — do not start
editing code.
