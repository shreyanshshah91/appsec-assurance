# Methodology

The skill combines five complementary techniques; each catches what the
others miss.

| Technique | Catches | Misses | Implemented by |
|---|---|---|---|
| Pattern SAST (built-in rules, Semgrep, Bandit, gosec, Brakeman) | Known-dangerous sinks, insecure config literals | Logic flaws, authz gaps, multi-hop data flow | `rules/*.json`, adapters |
| SCA (OSV-Scanner, Trivy, npm audit, pip-audit, govulncheck, `--osv-api`) | Known-vulnerable dependency versions | Zero-days, reachability, malicious-but-unreported packages | adapters, `osv.py` |
| Supply-chain heuristics | Install hooks, typosquats, obfuscation, unpinned/URL deps, dependency confusion | Sophisticated targeted implants | `supply-chain` pack, `supplychain.py` |
| IaC/CI/container review (Checkov, Trivy, Hadolint, zizmor, built-ins) | Misconfiguration in Docker, K8s, Terraform, workflows | Deployed drift, runtime state | `iac`, `cicd` packs, adapters |
| Expert manual review + threat modeling | Authorization, business logic, races, trust assumptions, chained attack paths | Bounded by time and access | SKILL.md phases 2–7, `checklists/` |
| Safe dynamic validation (authorized) | Proof of exploitability, runtime headers/cookies | Untested code paths | `dast.py`, validation playbook |

## Layer-by-layer review

Assess each layer independently, then collectively:

1. **Frontend**: what the client trusts, stores, renders; what the server
   wrongly assumes the client enforces.
2. **API / backend**: authn on every entry point, authz on every object,
   input validation at the boundary, output encoding, error handling.
3. **Data**: query construction, DB privileges, encryption, backups,
   multi-tenancy isolation.
4. **Middleware / integrations**: queues, webhooks (signature verification,
   replay), third-party APIs (timeouts, response validation), SSO.
5. **Infrastructure / deployment**: container hardening, orchestrator policy,
   cloud IAM, network exposure, secrets delivery.
6. **Build / supply chain**: dependency provenance, lockfiles, CI permissions,
   artifact integrity, release signing.

Cross-layer questions: Is any control enforced only in one layer that an
attacker can bypass (e.g. frontend-only checks, gateway-only auth with direct
service access)? Do configs in one layer undo another (CORS `*` in app while
the gateway restricts)? Does a low-privilege foothold in one layer pivot to
another (SSRF → metadata → cloud IAM; CI token → registry → production)?

## Extensibility

Standards and vulnerability classes evolve. The framework adds coverage by:
data (rule packs, checklists, stack guides), adapters (any SARIF tool), and
mappings (`standards.py`). Nothing is hardcoded to a single standard edition.
