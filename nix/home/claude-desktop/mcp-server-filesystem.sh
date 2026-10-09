# shellcheck shell=bash
# Claude Desktop rejects the draft-07 $schema the server declares (modelcontextprotocol/servers#4841)
: "${MCP_SERVER_FILESYSTEM:?}"
# Drop the client's roots so the CLI args stay the allowed dirs
jq -c --unbuffered 'select(.method != "notifications/roots/list_changed")
  | if .method == "initialize" then del(.params.capabilities.roots) end' |
  "$MCP_SERVER_FILESYSTEM" "$@" |
  jq -c --unbuffered 'walk(if type == "object" then del(."$schema") else . end)'
