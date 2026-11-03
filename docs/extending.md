# Extending appsec-assurance

## Add a built-in rule
1. Pick the pack in `skills/appsec-assurance/rules/` (or create `<pack>.json`, schema in
   `schemas/rule.schema.json`).
2. Add the rule. Line rule example:
   ```json
   {
     "id": "INJ-PY-LDAP-FORMAT", "title": "LDAP filter built with string formatting",
     "severity": "high", "confidence": "medium", "category": "injection",
     "files": ["*.py"], "pattern": "search(_s|_ext_s)?\\(.*(%|\\.format\\(|f[\"'])",
     "cwe": ["CWE-90"], "owasp": ["A03:2021"],
     "remediation": "Escape with ldap.filter.escape_filter_chars or use parameterized filter builders."
   }
   ```
   File rule (multi-signal / missing control): use `"kind": "file"`, `all_of`, `none_of`, and usually
   `"status": "missing-control"`.
   Secrets: set `"secret": true` and capture the value in `(?P<secret>...)` so it is redacted.
3. Add a positive and negative sample to `SAMPLES` in `tests/test_rules.py`.
4. Run `python3 -m unittest discover -s tests -t .`.

## Organization-specific rules (no fork needed)
Put packs in the target repo (e.g. `.appsec/rules/org.json`) and list the directory in
`.appsec/config.json` → `custom_rule_dirs`. IDs must not collide with built-ins.

## Add an external tool
Most tools emit SARIF; add a `SarifAdapter` to `REGISTRY` in `scripts/appsec/adapters/__init__.py`:
```python
SarifAdapter("mytool", "mytool", "sast", "pipx install mytool",
             applies=lambda s: "python" in s["languages"], network=False,
             argv=lambda root, raw, cfg, stack: [["mytool", "--sarif", "-o", "{OUT}", "."]]),
```
`{OUT}` is replaced with the output path; set `stdout=True` if the tool prints SARIF. For non-SARIF
tools subclass `Adapter` and implement `commands()` and `parse()`. Add a parsing test with a small
recorded output sample (no real secrets).

## Add a standard
See `skills/appsec-assurance/references/standards-mapping.md`.

## Add a checklist or stack guide
Follow the format of existing files (stable item IDs, verify/fail lines, false positives, safe validation),
add it to the README index in that folder (a test enforces this), and reference it from `SKILL.md` if
it introduces a new review phase.
