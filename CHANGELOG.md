# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/) and [Semantic Versioning](https://semver.org/).
Rule IDs are stable across versions; a removed rule's ID is never reused.

## [1.0.1] - 2026-11-03
### Security
- Every secret on a line is redacted (previously only the first match), and redaction now runs before truncation.
- Snippets, messages and titles from all external tools are redacted, not only from secret scanners.
- Scope gate: URL-form exclusions are matched on parsed, lowercased host, port and path; targets with
  credentials are rejected; malformed URLs and dates are denied instead of crashing.
- Any environment not explicitly non-production (e.g. `Production`, `prod`, `live`) is treated as production.
- DAST uses one normalized target for the scope check and the request; uppercase `HTTPS://` no longer skips HSTS/cookie checks.
- CI templates load config and baseline from the base branch so a pull request cannot loosen its own gate.
- GitHub Actions in workflows are pinned to verified commit SHAs.
### Fixed
- Triage by `id` now requires a matching `rule_id`; fingerprints remain the preferred key.
- De-duplication only merges the same issue from a built-in rule and an external tool; manual findings,
  distinct secrets and distinct built-in rules are never merged.
- Invalid `severity_overrides`, `mode`, `fail_on` and `max_file_size_kb` values are rejected.
- An output directory inside the scanned root is excluded from later scans.
- Line numbers split on `\n` only (form feeds and U+2028 no longer shift them).
- UTF-8 BOM and UTF-16 files are decoded; unreadable directories are recorded in coverage; paths with
  glob characters load custom rule packs; a failing rule no longer aborts the scan.
- `--tools` overrides the mode profile, rejects unknown names, and keeps unselected tools in coverage.
- SARIF ingest: percent-decoded URIs, `ruleIndex` lookup, only accepted suppressions hide results,
  Trivy misconfigurations categorized as IaC.
- Adapters never parse stale output from a previous run; pip-audit list-shaped JSON parses.
### Changed
- CI-GHA-SCRIPT-INJECTION catches `run:` on its own line and `actions/github-script` `script:`.
- SEC-GENERIC-ASSIGNMENT no longer backtracks quadratically on long dotted lines.
- Fewer false positives: SC-DEP-FROM-URL (package.json metadata), CRY-WEAK-PASSWORD-HASH ("passes"),
  INJ-JS-CHILD-PROCESS-STRING (`regex.exec`), typosquat heuristic (known-good names such as preact, pug, scapy).
- IAC-DOCKER-UNPINNED-BASE is now a structural check that understands multi-stage aliases and registry ports.

## [1.0.0] - 2026-11-03
### Added
- `SKILL.md` with five modes (quick, comprehensive, deep, remediate, continuous) and a ten-phase workflow.
- Standard-library Python engine: stack detection, attack-surface inventory, 140 built-in rules in 10 packs,
  structural supply-chain checks, CVSS 3.1 calculator, fingerprinting and de-duplication.
- Adapters for Semgrep, Gitleaks, OSV-Scanner, Trivy, Bandit, gosec, govulncheck, Brakeman, Checkov,
  Hadolint, zizmor, npm audit and pip-audit, plus generic SARIF ingest.
- Opt-in OSV.dev lookup (`--osv-api`), passive header DAST gated by a scope file, ZAP baseline integration.
- Markdown, JSON and SARIF 2.1.0 reports, coverage ledger, JSONL activity log, baseline diffing for CI.
- 24 review checklists, 12 stack guides, 11 reference documents, templates and JSON schemas.
- Test suite (unittest) and generated vulnerable fixture.
