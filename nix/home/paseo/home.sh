# shellcheck shell=bash
# Paseo's part of the state script's home step (state.sh's app_home, run confined before each launch; app.nix and
# agents.nix set the variables). Each file goes through state.sh's merge: replaced only when the merge succeeded, else
# left as it was with a warning, the launch going on.
#   $PASEO_CONFIG, Paseo's config.json: Paseo's defaults for a fresh home ($PASEO_DEFAULTS) when missing, as Paseo
#     writes them only then and a file without daemon.relay.enabled turns the relay on; dictation off unless set.
#     Written where ~/.paseo is bound from the host too: it is Paseo's own home there, the same on both sides
#   $CLAUDE_JSON, Claude Code's ~/.claude.json (empty: bound from the host as a file, the host's, left alone): its
#     mcpServers with the module's servers ($MCP_SERVERS). $MCP_RECORD holds what the module wrote there last time, by
#     name: an entry that still is what the module wrote is the module's and replaced (or dropped, with its server),
#     any other entry the user's, which wins a name and is never recorded as the module's
: "${PASEO_CONFIG:?}" "${PASEO_DEFAULTS:?}" "${MCP_SERVERS:?}" "${MCP_RECORD:?}"

mkdir -p "${PASEO_CONFIG%/*}"
merge "$PASEO_CONFIG" "$(<"$PASEO_DEFAULTS")" jq '.features.dictation.enabled |= (if . == null then false end)' || :

if [[ -n ${CLAUDE_JSON:-} ]]; then
  mkdir -p "${MCP_RECORD%/*}"
  record='{}'
  [[ ! -s $MCP_RECORD ]] || record=$(<"$MCP_RECORD")
  # A record not an object of servers (gone astray, or a897abd's list of names) records nothing
  # shellcheck disable=SC2016 # jq's variables
  if merge "$CLAUDE_JSON" '{}' jq --slurpfile m "$MCP_SERVERS" --arg old "$record" '
    ($old | try fromjson catch {} | if type == "object" then . else {} end) as $old
    | (.mcpServers // {}) as $s
    | ($s | with_entries(select(.value != $old[.key]))) as $user
    | .mcpServers = $user + ($m[0] | with_entries(select(.key as $k | $user | has($k) | not)))'; then
    # The module's entries now: those that are the module's server as written
    if ours=$(jq --slurpfile m "$MCP_SERVERS" '.mcpServers | with_entries(select(.value == $m[0][.key]))' "$CLAUDE_JSON"); then
      printf '%s\n' "$ours" | replace "$MCP_RECORD"
    fi
  fi
fi
