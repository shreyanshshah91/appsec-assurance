# CI/CD pipelines

Scope: build and release automation as an attack surface: GitHub Actions,
GitLab CI, Jenkins, and equivalents (CircleCI, Azure Pipelines, Bitbucket,
Buildkite). Covers untrusted-input triggers, script injection, third-party
action/plugin trust, token permissions, runner isolation, cloud OIDC trust,
secret exposure, artifact/cache poisoning, branch protection and release
signing. A compromised pipeline is usually a compromised production.

**Applies when:** `.github/workflows/*.yml`, `action.yml`, `.gitlab-ci.yml`,
`Jenkinsfile`, `.circleci/config.yml`, `azure-pipelines.yml`,
`bitbucket-pipelines.yml`, `.buildkite/` exist. Use zizmor/actionlint/Poutine
output when available.

**Standards:** OWASP A08:2021 Software and Data Integrity Failures, A05:2021;
OWASP Top 10 CI/CD Security Risks (CICD-SEC-1..10) as reference; ASVS V15,
V13; CWE-78, CWE-94, CWE-829, CWE-494, CWE-250, CWE-269, CWE-732, CWE-200.

## GitHub Actions
- **CICD-01 — `pull_request_target` / `workflow_run` with untrusted checkout** (critical)
  - Verify: workflows on `pull_request_target` or `workflow_run` that `actions/checkout` with `ref: ${{ github.event.pull_request.head.sha }}`/`head.ref`/`refs/pull/*/merge`, then run build/test/install scripts, or download artifacts from the triggering run and execute/unpack them.
  - Fail: fork code executes with secrets and write token ("pwn request").
- **CICD-02 — Script injection via expressions** (critical/high)
  - Verify: `${{ github.event.issue.title }}`, `...body`, `...pull_request.title`, `...head_ref`, `github.head_ref`, `...comment.body`, `...review.body`, `...commits.*.message`, `...pages.*.page_name`, `...head_commit.author.email`, `inputs.*` from `workflow_dispatch`/`repository_dispatch` `client_payload` interpolated directly in `run:` or `actions/github-script` `script:`.
  - Fail: attacker-controlled text spliced into shell/JS. Fix: pass via `env:` and quote `"$VAR"`.
- **CICD-03 — Third-party actions pinned to full commit SHA** (high)
  - Verify: `uses: owner/action@v3` or `@main` vs `@<40-hex>  # v3.x.y`; Docker actions `docker://image:tag` without digest; reusable workflows from other orgs. First-party `actions/*` still recommended pinned.
  - Fail: mutable tag/branch references (tag hijack, e.g. compromised popular actions).
- **CICD-04 — `GITHUB_TOKEN` permissions minimized** (high)
  - Verify: top-level `permissions:` set (e.g. `contents: read`) with per-job elevation; repo/org default "read" (ask user); no `permissions: write-all`; `id-token: write` only on jobs that need OIDC.
  - Fail: default write-all token in workflows that process untrusted input.
- **CICD-05 — Self-hosted runners** (high)
  - Verify: self-hosted runners not used for public repos or fork PRs; ephemeral/JIT runners; runner groups restricting which repos/workflows; no persistent credentials or Docker socket on hosts; network-isolated from prod.
  - Fail: persistent self-hosted runner on a public repo (persistence, lateral movement).
- **CICD-06 — Secrets exposure to forks and untrusted contexts** (high)
  - Verify: secrets not available to `pull_request` from forks (default) and not re-exposed via `pull_request_target`; environment protection rules with required reviewers for deploy secrets; secrets not printed or written to artifacts/caches; `ACTIONS_STEP_DEBUG` not left on.
  - Fail: deploy secrets available on PR-triggered jobs.
- **CICD-07 — Artifact poisoning** (high)
  - Verify: `actions/download-artifact` / `dawidd6/action-download-artifact` in privileged workflows consuming artifacts from PR-triggered runs; artifacts extracted into workspace paths later executed; artifact names predictable.
  - Fail: untrusted artifact overwrites scripts used by privileged job.
- **CICD-08 — Cloud OIDC trust conditions** (critical)
  - Verify: AWS IAM role trust for `token.actions.githubusercontent.com` with `StringEquals`/`StringLike` on `sub` restricted to `repo:org/repo:ref:refs/heads/main` or `environment:prod` (not `repo:org/*` or `*`), `aud = sts.amazonaws.com`; GCP Workload Identity attribute conditions on `repository`/`ref`; Azure federated credential subject exact.
  - Fail: any repo or branch (or any GitHub user) can assume the deploy role.
- **CICD-09 — Cache poisoning** (medium)
  - Verify: `actions/cache` / setup-* caches restored in release workflows from keys writable by PR workflows; cache contents executed (node_modules, pip wheels, build outputs).
  - Fail: release builds trust caches populated by untrusted runs.
- **CICD-10 — Dangerous triggers and dispatch inputs** (medium)
  - Verify: `issue_comment`-triggered workflows (e.g. `/deploy` commands) check commenter permissions (`author_association` is not sufficient alone; check via API); `workflow_dispatch` inputs validated; `GITHUB_ENV`/`GITHUB_OUTPUT` writes of untrusted data (env injection, e.g. `LD_PRELOAD`, `NODE_OPTIONS`).
- **CICD-11 — Other GitHub settings (ask user if not in repo)** (medium)
  - Verify: branch protection/rulesets on default and release branches (required reviews, status checks, no force push, CODEOWNERS for `.github/workflows/`), "Allow GitHub Actions to create and approve pull requests" disabled, fork PR workflows require approval for first-time contributors, Dependabot/secret scanning/push protection enabled.

## GitLab CI
- **CICD-12 — Protected variables and runners** (high)
  - Verify: deploy variables marked protected + masked and scoped to environments; MR pipelines from forks don't get protected variables; `rules:` preventing deploy jobs on MRs; shared runners vs project runners for privileged jobs; Docker-in-Docker `privileged = true` runners not shared.
- **CICD-13 — Includes and images pinned** (medium)
  - Verify: `include: remote:` URLs and `project:` includes pinned to `ref:` SHA/tag; job `image:` by digest; `CI_JOB_TOKEN` allowlist (job token scope) restricted.
- **CICD-14 — Script injection** (high)
  - Verify: `$CI_COMMIT_MESSAGE`, `$CI_COMMIT_BRANCH`, `$CI_MERGE_REQUEST_TITLE` used in `eval`, unquoted contexts or generated scripts.

## Jenkins and others
- **CICD-15 — Jenkins pipeline trust** (high)
  - Verify: `Jenkinsfile` from untrusted branches/forks executed with credentials (multibranch "trust" settings); `sh "... ${params.X}"` Groovy interpolation of untrusted values (use single-quoted `sh '...$X'` with env); script approval bypasses; `@Library` shared libraries pinned; agents not running on controller; credentials bound with `withCredentials` and masked.
  - Fail: PR author edits Jenkinsfile to dump credentials.
- **CICD-16 — Equivalent checks for CircleCI/Azure/Bitbucket/Buildkite** (high)
  - Verify: orbs/tasks/pipes pinned by version or digest, contexts/variable groups restricted to protected branches, fork PR secrets disabled, OIDC subject constraints.

## Release integrity
- **CICD-17 — Signed and attested releases** (medium)
  - Verify: tags/commits signed where policy requires; release artifacts and images signed (cosign), SLSA provenance/attestations generated in CI and verified at deploy (see SC-15); release jobs gated by environment approval.
  - Fail: releases publishable from any branch without approval.
- **CICD-18 — Deployment separation** (medium)
  - Verify: build and deploy stages separated; production deploy credentials only in deploy jobs on protected refs; manual approval for prod.
- **CICD-19 — Pipeline-installed tooling** (medium)
  - Verify: `curl | bash` installers, unpinned `pip install tool`, `npx some-cli@latest` in pipelines; tools verified by checksum/signature.

## Common false positives
- `pull_request_target` workflows that only label/comment and never check out or execute PR code.
- Expressions like `${{ github.event.pull_request.number }}` or `github.sha` (not attacker-controlled text).
- Unpinned first-party `actions/checkout@v4` in a low-privilege, read-only workflow (report low, not high).

## Safe validation ideas
- Static review is sufficient; do not open PRs, issues or comments on real repositories to test injection.
- Reproduce expression injection locally with `act` only if installed, approved, and using a throwaway repo copy with no secrets; marker `appsec-canary-<rand>` in a test title.
- Resolve action tags to SHAs from already-cloned sources or ask the user; do not push changes.
