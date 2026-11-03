# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/) and [Semantic Versioning](https://semver.org/).
Rule IDs are stable across versions; a removed rule's ID is never reused.

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
