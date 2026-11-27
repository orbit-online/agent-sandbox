# shellcheck shell=bash
# Paseo's part of the state script's home step (state.sh's app_home, run confined before each launch; app.nix and
# agents.nix set the variables). Each file is replaced through a temp file and a rename (state.sh's replace), the
# user's and the agents' own entries kept:
#   $PASEO_CONFIG, Paseo's config.json: Paseo's defaults for a fresh home ($PASEO_DEFAULTS) when missing, as Paseo
#     writes them only then and a file without daemon.relay.enabled turns the relay on; dictation off unless set
#   $CLAUDE_JSON, Claude Code's ~/.claude.json (empty: left alone, bound from the host as a file): its mcpServers with
#     the ones $MCP_RECORD names, the module's from the last launch, replaced by $MCP_SERVERS
#   $CODEX_DIR/config.toml and $CODEX_DIR/AGENTS.md: the block between the markers replaced by $CODEX_MCP and
#     $AGENTS_DOC, the rest of each file as it was
: "${PASEO_CONFIG:?}" "${PASEO_DEFAULTS:?}" "${MCP_SERVERS:?}" "${MCP_RECORD:?}" "${CODEX_DIR:?}" "${CODEX_MCP:?}" \
  "${AGENTS_DOC:?}"

mkdir -p "${PASEO_CONFIG%/*}"
config=$(<"$PASEO_DEFAULTS")
[[ ! -s $PASEO_CONFIG ]] || config=$(<"$PASEO_CONFIG")
jq '.features.dictation.enabled |= (if . == null then false end)' <<<"$config" | replace "$PASEO_CONFIG"

if [[ -n ${CLAUDE_JSON:-} ]]; then
  mkdir -p "${MCP_RECORD%/*}"
  claude='{}'
  [[ ! -s $CLAUDE_JSON ]] || claude=$(<"$CLAUDE_JSON")
  record='[]'
  [[ ! -s $MCP_RECORD ]] || record=$(<"$MCP_RECORD")
  jq --slurpfile m "$MCP_SERVERS" --argjson old "$record" \
    '.mcpServers = ((.mcpServers // {}) | delpaths($old | map([.])) ) + $m[0]' <<<"$claude" | replace "$CLAUDE_JSON"
  jq 'keys' "$MCP_SERVERS" | replace "$MCP_RECORD"
fi

# File $1 with the lines from $2 to $3 dropped and file $4 put between them at the end, unless it's empty
block() {
  local text=''
  [[ ! -s $1 ]] || text=$(awk -v b="$2" -v e="$3" '$0 == b { skip = 1 } !skip { print } $0 == e { skip = 0 }' "$1")
  {
    [[ -z $text ]] || printf '%s\n' "$text"
    if [[ -s $4 ]]; then
      [[ -z $text ]] || echo
      printf '%s\n' "$2"
      cat "$4"
      printf '%s\n' "$3"
    fi
  } | replace "$1"
}
mkdir -p "$CODEX_DIR"
block "$CODEX_DIR/config.toml" '# agent-sandbox: begin' '# agent-sandbox: end' "$CODEX_MCP"
block "$CODEX_DIR/AGENTS.md" '<!-- agent-sandbox: begin -->' '<!-- agent-sandbox: end -->' "$AGENTS_DOC"
