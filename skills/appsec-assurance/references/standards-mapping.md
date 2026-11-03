# Standards mapping

| Standard | How it is used |
|---|---|
| OWASP Top 10 (2021) | Primary category tag on findings (`A01:2021` … `A10:2021`); report coverage matrix. `standards.py` maps CWEs to categories for tool findings. |
| OWASP Top 10 (2025) | When the final 2025 list is adopted by your organization, add a `CWE_TO_OWASP_2025` map in `standards.py` and tag rules with `A0x:2025`. Mappings differ (e.g. supply-chain failures and exceptional-condition handling became their own categories), so do not reuse 2021 IDs. Verify against the official OWASP publication before tagging. |
| OWASP API Security Top 10 (2023) | `API1:2023`…`API10:2023` tags; `checklists/api-graphql-websocket.md` maps each item. |
| OWASP ASVS 5.0 | Checklists reference ASVS chapters. For a formal ASVS level assessment, record each requirement as a `checklist_results` entry (`checklist: "asvs-5.0"`, `item: "<requirement id>"`). |
| OWASP WSTG | Validation techniques in `validation-playbook.md` follow WSTG categories. |
| OWASP MASVS v2 | `checklists/mobile.md`, `stacks/mobile.md`. |
| CWE | Every rule carries CWE IDs; SARIF tags use `external/cwe/cwe-N`. |
| CVSS 3.1 | Base score calculator (`appsec.py cvss`). |
| SLSA / OpenSSF Scorecard ideas | `checklists/supply-chain-and-malware.md`, `cicd-pipelines.md`. |
| CIS Benchmarks (Docker, Kubernetes) | Container/K8s checklist items and rules approximate common CIS controls; use Checkov/Trivy for full benchmark coverage. |
| OWASP CI/CD Top 10 | `checklists/cicd-pipelines.md`. |

## Adding a standard
1. Add the ID→name map (and CWE map if applicable) to `scripts/appsec/standards.py`.
2. Tag rules (`owasp` field accepts any string IDs) and checklist items.
3. Extend `report.py` coverage matrix if the standard needs its own table.
4. Add tests asserting the mapping (see `tests/test_standards.py`).

Compliance caveat: mapping findings to a standard is not certification.
Reports state coverage, never compliance.
