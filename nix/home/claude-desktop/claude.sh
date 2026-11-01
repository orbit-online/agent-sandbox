# shellcheck shell=bash
# Claude Code as the app keeps it, ~/.config/Claude/claude-code/<version>/<hash>/claude: the newest version there
shopt -s nullglob
exes=("$HOME"/.config/Claude/claude-code/*/*/claude)
((${#exes[@]})) || { echo "claude: No Claude Code under ~/.config/Claude/claude-code; the app downloads it" >&2; exit 1; }
exe=$(printf '%s\n' "${exes[@]}" | sort -V | tail -n1)
exec "$exe" "$@"
