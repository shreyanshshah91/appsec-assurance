#!/usr/bin/env sh
# Install the appsec-assurance skill for Claude Code.
#   ./install.sh            -> ~/.claude/skills/appsec-assurance (all projects)
#   ./install.sh --project  -> ./.claude/skills/appsec-assurance (current project)
#   add --link to symlink instead of copy (handy while developing the skill)
set -eu

SRC="$(cd "$(dirname "$0")" && pwd)/skills/appsec-assurance"
DEST_ROOT="$HOME/.claude/skills"
MODE=copy
for arg in "$@"; do
  case "$arg" in
    --project) DEST_ROOT="$(pwd)/.claude/skills" ;;
    --link) MODE=link ;;
    -h|--help) sed -n '2,6p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

command -v python3 >/dev/null 2>&1 || { echo "python3 (3.9+) is required" >&2; exit 1; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' || { echo "python3 >= 3.9 required" >&2; exit 1; }

DEST="$DEST_ROOT/appsec-assurance"
mkdir -p "$DEST_ROOT"
if [ -e "$DEST" ] || [ -L "$DEST" ]; then
  echo "Replacing existing $DEST"
  rm -rf "$DEST"
fi
if [ "$MODE" = link ]; then
  ln -s "$SRC" "$DEST"
else
  cp -R "$SRC" "$DEST"
  find "$DEST" -name '__pycache__' -type d -prune -exec rm -rf {} +
fi
python3 "$DEST/scripts/appsec.py" doctor
echo
echo "Installed to $DEST. In Claude Code, ask e.g. \"run a comprehensive security audit of this repo\" or invoke /appsec-assurance."
