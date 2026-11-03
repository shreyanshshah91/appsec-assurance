# Architecture

```mermaid
flowchart TB
  subgraph Claude["Claude Code (SKILL.md workflow)"]
    M[Mode selection] --> P1[Recon & inventory review] --> P3[Threat model] --> P4[Triage] --> P5[Manual review<br/>checklists + stack guides] --> P6[Attack chaining] --> P7[Safe validation] --> P8[Report] --> P9[Remediation]
  end
  subgraph Engine["scripts/appsec (Python stdlib)"]
    W[walker] --> D[detect] --> I[inventory]
    W --> R[rule engine<br/>rules/*.json]
    W --> S[supplychain]
    A[adapters<br/>Semgrep, Gitleaks, OSV, Trivy, ...] --> SI[SARIF ingest]
    O[osv.py opt-in]
    R & S & SI & O --> F[findings: score, fingerprint, dedupe]
    F --> REP[report.md / findings.json / report.sarif]
    C[coverage ledger] --> REP
    L[activity log]
    SC[scope gate] --> DA[dast.py passive]
    B[baseline diff]
  end
  P1 -. runs .-> Engine
  P4 -. reads findings.json .-> F
  P8 -. manual-findings.json .-> REP
  P7 -. scope-check .-> SC
```

## Design principles
- **Two halves.** The engine does what tools do well (fast, deterministic, exhaustive pattern and
  dependency checks). Claude does what tools do badly (authorization, business logic, data flow,
  chaining, judgement) guided by checklists. The merge step keeps both auditable in one report.
- **Coverage is a first-class output.** Every rule pack, tool and manual-only area is recorded as
  ran / skipped / unavailable / error / not-applicable with a reason. Reports can't silently omit.
- **Stable identity.** Fingerprints hash rule + path + normalized code, so findings survive line
  shifts; CI diffs and triage decisions key on them.
- **Safe by construction.** No code from the target is executed by the engine. Network use is limited
  to optional tools/opt-in OSV lookups, and DAST passes through the scope gate plus `--approved`.
- **Deterministic.** Sorted file walking, sorted findings, sorted JSON keys, `--deterministic` omits
  timestamps (or honor `SOURCE_DATE_EPOCH`).
- **Extensible by data.** Rules, checklists, stack guides and standards mappings are data files.

## Module map
| Module | Responsibility |
|---|---|
| `walker.py` | File enumeration, exclusions, size/binary/symlink handling |
| `detect.py` | Languages, frameworks, package managers, lockfiles, data stores, IaC, CI, cloud, mobile |
| `inventory.py` | Entry points and sensitive operations; trust-boundary hints |
| `rules.py` | Rule loading/validation, line and file rule kinds, redaction, placeholder/entropy filters |
| `supplychain.py` | Lockfiles, typosquats, git-tracked sensitive files, installed npm hooks |
| `adapters/` | External tools: availability, command lines, parsing |
| `sarif.py` | SARIF export and generic ingest |
| `osv.py` | Opt-in OSV.dev client |
| `findings.py` | Model, severity, fingerprint, merge, summary |
| `cvss.py` | CVSS 3.1 base scores |
| `manual.py` | Manual findings validation, triage, merge |
| `report.py` | Markdown report and posture indicator |
| `baseline.py` | Fingerprint diff and CI gate |
| `scope.py`, `dast.py` | Authorization gate; passive header/cookie checks; ZAP baseline |
| `engine.py`, `cli.py` | Orchestration and CLI |

## Output directory (`.appsec/out/`)
`automated-findings.json` (engine only; input to `report`), `findings.json` (merged), `report.md`,
`report.sarif`, `coverage.json`, `inventory.json`, `stack.json`, `activity.log.jsonl`, `raw/`
(tool outputs), and in CI `diff.json` / `diff.md`.
