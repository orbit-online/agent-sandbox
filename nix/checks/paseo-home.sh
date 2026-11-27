# shellcheck shell=bash
# Paseo's part of the state script's home step (nix/home/paseo/home.sh) on a home of its own, as state.sh runs it, with
# state.sh's replace: $HOME_SH, $DEFAULTS (config-defaults.json), $SERVERS and $TOML (the module's servers as JSON and
# as Codex's block), $DOC (the doc for AGENTS.md). Checks Paseo's defaults on a fresh home with dictation off, a second
# run changing nothing, the user's entries kept in each file, the module's servers of the last launch replaced, and an
# empty block removed
set -euo pipefail
: "${HOME_SH:?}" "${DEFAULTS:?}" "${SERVERS:?}" "${TOML:?}" "${DOC:?}"
replace() {
  local tmp
  tmp=$(mktemp "$1.XXXXXX")
  cat >"$tmp"
  mv -fT "$tmp" "$1"
}
fail() {
  echo "paseo-home: $*" >&2
  exit 1
}
h=$PWD/home
# shellcheck disable=SC2034 # read by home.sh
run() (
  PASEO_CONFIG=$h/.paseo/config.json PASEO_DEFAULTS=$DEFAULTS MCP_SERVERS=$1 MCP_RECORD=$h/.local/state/agent-sandbox/mcp-servers.json \
    CLAUDE_JSON=${CLAUDE-$h/.claude.json} CODEX_DIR=$h/.codex CODEX_MCP=$2 AGENTS_DOC=$DOC
  # shellcheck disable=SC1090
  source "$HOME_SH"
)

# A fresh home: Paseo's defaults, dictation off, the servers and the doc
mkdir -p "$h"
run "$SERVERS" "$TOML"
jq -e --slurpfile d "$DEFAULTS" '. == ($d[0] | .features.dictation.enabled = false)' "$h/.paseo/config.json" >/dev/null ||
  fail "config.json on a fresh home: $(<"$h/.paseo/config.json")"
jq -e --slurpfile s "$SERVERS" '.mcpServers == $s[0]' "$h/.claude.json" >/dev/null || fail ".claude.json: $(<"$h/.claude.json")"
grep -qxF '# agent-sandbox: begin' "$h/.codex/config.toml" || fail "config.toml lacks the block"
python3 -c 'import sys, tomllib; tomllib.load(open(sys.argv[1], "rb"))' "$h/.codex/config.toml" || fail "config.toml isn't TOML"
grep -qxF '<!-- agent-sandbox: begin -->' "$h/.codex/AGENTS.md" || fail "AGENTS.md lacks the block"
[[ $(stat -c %a "$h/.paseo/config.json" "$h/.claude.json") == $'600\n600' ]] || fail "the files aren't private"

# The user's own entries, and a server the module wrote last time and has dropped since
jq '.features.dictation.enabled = true | .daemon.relay.enabled = true' "$h/.paseo/config.json" | replace "$h/.paseo/config.json"
jq '.numStartups = 3 | .mcpServers.mine = {command: "/bin/mine"} | .mcpServers.stale = {command: "/bin/old"}' \
  "$h/.claude.json" | replace "$h/.claude.json"
jq '. + ["stale"]' "$h/.local/state/agent-sandbox/mcp-servers.json" | replace "$h/.local/state/agent-sandbox/mcp-servers.json"
{
  printf '# mine\nmodel = "o3"\n\n'
  cat "$h/.codex/config.toml"
  printf '\n[profiles.fast]\nmodel = "o4-mini"\n'
} | replace "$h/.codex/config.toml"
{
  printf 'Be brief.\n\n'
  cat "$h/.codex/AGENTS.md"
} | replace "$h/.codex/AGENTS.md"
run "$SERVERS" "$TOML"
cp -r "$h" "$PWD/once"
run "$SERVERS" "$TOML"
diff -r "$PWD/once" "$h" || fail "a second run changed the home"
jq -e '.features.dictation.enabled == true and .daemon.relay.enabled == true' "$h/.paseo/config.json" >/dev/null ||
  fail "the user's settings in config.json: $(<"$h/.paseo/config.json")"
jq -e --slurpfile s "$SERVERS" '.numStartups == 3 and .mcpServers == ({mine: {command: "/bin/mine"}} + $s[0])' \
  "$h/.claude.json" >/dev/null || fail ".claude.json with the user's entries: $(<"$h/.claude.json")"
[[ $(grep -cxF '# agent-sandbox: begin' "$h/.codex/config.toml") == 1 ]] || fail "config.toml has the block twice"
python3 -c 'import sys, tomllib; c = tomllib.load(open(sys.argv[1], "rb")); assert c["model"] == "o3" and c["profiles"]["fast"]["model"] == "o4-mini", c' \
  "$h/.codex/config.toml" || fail "config.toml lost the user's keys: $(<"$h/.codex/config.toml")"
grep -qxF '# mine' "$h/.codex/config.toml" || fail "config.toml lost the user's comment"
[[ $(head -n1 "$h/.codex/AGENTS.md") == 'Be brief.' && $(grep -cxF '<!-- agent-sandbox: begin -->' "$h/.codex/AGENTS.md") == 1 ]] ||
  fail "AGENTS.md: $(<"$h/.codex/AGENTS.md")"

# No servers: the module's gone from ~/.claude.json, the block from config.toml, the user's left
echo '{}' >"$PWD/none.json"
: >"$PWD/none.toml"
run "$PWD/none.json" "$PWD/none.toml"
jq -e '.mcpServers == {mine: {command: "/bin/mine"}}' "$h/.claude.json" >/dev/null || fail ".claude.json without servers: $(<"$h/.claude.json")"
! grep -q 'agent-sandbox' "$h/.codex/config.toml" || fail "config.toml keeps an empty block"
grep -qxF 'model = "o4-mini"' "$h/.codex/config.toml" || fail "config.toml lost the user's keys"

# ~/.claude.json bound as a file: left alone
CLAUDE='' run "$SERVERS" "$TOML"
jq -e '.mcpServers == {mine: {command: "/bin/mine"}}' "$h/.claude.json" >/dev/null || fail ".claude.json was written though bound"
echo "paseo-home: ok"
