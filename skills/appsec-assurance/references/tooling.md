# Tooling

The engine needs only Python 3.9+. External tools are optional and detected
at runtime (`appsec.py doctor`). Nothing is installed automatically.

| Tool | Area | Network | Install | Notes / limitations |
|---|---|---|---|---|
| Semgrep CE | SAST, many languages | Downloads registry rules (`p/default`); `--metrics=off` is passed | `pipx install semgrep` | Use a local rules dir in `tools.semgrep.config` for offline runs. Cross-file taint needs the commercial engine. |
| Gitleaks | Secrets (files; git history in deep mode) | No | `brew install gitleaks` | Run with `--redact`; history scan finds secrets deleted from HEAD. |
| OSV-Scanner v2 | SCA from lockfiles | Yes (OSV.dev) | `brew install osv-scanner` | Needs lockfiles for precise versions. |
| Trivy | SCA + IaC misconfig | Downloads vuln DB | `brew install trivy` | First run downloads ~hundreds of MB. |
| Bandit | Python SAST | No | `pipx install 'bandit[sarif]'` | |
| gosec / govulncheck | Go SAST / reachability-aware SCA | govulncheck: yes | `go install …` | govulncheck reports only reachable vulns — strong signal. |
| Brakeman | Rails SAST | No | `gem install brakeman` | |
| Checkov | Terraform/CFN/K8s/Docker/GHA | No (unless platform API key) | `pipx install checkov` | |
| Hadolint | Dockerfile lint | No | `brew install hadolint` | |
| zizmor | GitHub Actions security | `--offline` passed | `pipx install zizmor` | |
| npm audit / pip-audit | Ecosystem SCA | Yes | bundled / `pipx install pip-audit` | `npm audit` requires package-lock.json. |
| OWASP ZAP baseline | Passive DAST | Targets only | ZAP distribution (`zap-baseline.py`) | Only via `appsec.py dast --zap` after scope gate + approval. |

## Built-in fallbacks
- 140+ regex rules across 10 packs (`appsec.py rules`).
- Structural supply-chain checks (lockfiles, typosquat heuristic, git-tracked
  sensitive files, installed npm install hooks).
- `--osv-api`: stdlib OSV.dev client (opt-in; sends package names+versions).
- Passive header/cookie DAST probe.

## Failure handling
Every adapter outcome lands in `coverage.json`: `ran`, `unavailable` (not
installed — with install hint), `skipped` (mode/config/offline), `error` (with
stderr tail), `not-applicable` (stack doesn't use it). A missing SCA source is
called out explicitly: dependency CVEs were not checked.

## Permissions
Tools run with the invoking user's permissions inside the target directory.
They read files and write only to `.appsec/out/raw/`. Review any tool you
install — the skill trusts your installed binaries.
