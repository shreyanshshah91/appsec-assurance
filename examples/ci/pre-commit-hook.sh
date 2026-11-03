#!/usr/bin/env sh
# Fast local gate before commit: quick mode, built-in checks only, fail on high+.
# Install: cp examples/ci/pre-commit-hook.sh .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
SKILL="${APPSEC_SKILL:-$HOME/.claude/skills/appsec-assurance}"
exec python3 "$SKILL/scripts/appsec.py" scan --mode quick --no-tools --offline --fail-on high --out .appsec/out
