# Contributing

Thanks for helping improve appsec-assurance. Contributions of rules, checklists, stack guides, adapters and
bug fixes are welcome.

## Ground rules
- **Evidence over volume.** Every rule needs a positive and a negative sample in `tests/test_rules.py`.
  Rules that fire on safe code erode trust; prefer `confidence: low` or a `negative` pattern.
- **Stable IDs.** Never rename or reuse a rule ID. Deprecate by moving to `disabled` docs and keeping the ID reserved.
- **No secrets or live payloads in the repo.** Test fixtures that look like secrets are assembled at runtime
  (see `tests/fixtures/build_fixture.py`).
- **Stdlib only** in `scripts/appsec/`. External tools are optional adapters, never imports.
- **Safety first.** Changes must not weaken the rules of engagement, the scope gate, or redaction.

## Development
```bash
python3 -m unittest discover -s tests -t .          # run all tests
python3 skills/appsec-assurance/scripts/appsec.py rules   # list rules
python3 tests/fixtures/build_fixture.py /tmp/fx && \
  python3 skills/appsec-assurance/scripts/appsec.py scan --root /tmp/fx --out /tmp/fx-out --offline
./install.sh --link                                  # use your working copy in Claude Code
```

## Adding things
See [docs/extending.md](docs/extending.md) for rules, adapters, standards, checklists and stack guides.

## Pull requests
- Include tests and update `CHANGELOG.md`.
- Keep `.claude-plugin/plugin.json` version in sync with `scripts/appsec/__init__.py` (a test enforces this).
- CI runs the suite on Python 3.9–3.13 and scans this repository with the skill itself.
