# shellcheck shell=bash
# Paseo's home step as the state script runs it (state.sh with Paseo's app_home), unconfined, for alice with her home in
# the build's directory: $INNER, the state script's inner part, and $DEFAULTS (config-defaults.json), $SERVERS (the
# module's servers). Checks Paseo's defaults on a fresh home with dictation off, a second run changing nothing, the
# user's entries kept, a server the module wrote last time and has dropped since removed, a user's server by the name of
# one of the module's winning and never recorded as the module's, and a truncated file left as it was with a warning,
# the step going on
set -euo pipefail
: "${INNER:?}" "${DEFAULTS:?}" "${SERVERS:?}"
fail() {
  echo "paseo-home: $*" >&2
  exit 1
}
h=/build/alice/.local/share/paseo/home
config=$h/.paseo/config.json claude=$h/.claude.json record=$h/.local/state/agent-sandbox/mcp-servers.json
run() { "$INNER" home 2>"$PWD/err" || fail "the step failed: $(<"$PWD/err")"; }

# A fresh home: Paseo's defaults, dictation off, the servers, recorded as the module's
run
jq -e --slurpfile d "$DEFAULTS" '. == ($d[0] | .features.dictation.enabled = false)' "$config" >/dev/null ||
  fail "config.json on a fresh home: $(<"$config")"
jq -e --slurpfile s "$SERVERS" '.mcpServers == $s[0]' "$claude" >/dev/null || fail ".claude.json: $(<"$claude")"
jq -e --slurpfile s "$SERVERS" '. == $s[0]' "$record" >/dev/null || fail "the record: $(<"$record")"
[[ $(stat -c %a "$config" "$claude") == $'600\n600' ]] || fail "the files aren't private"
[[ ! -s err ]] || fail "a warning on a fresh home: $(<err)"

# The user's own settings and servers, one by the name of the module's, and a server the module wrote last time
jq '.features.dictation.enabled = true | .daemon.relay.enabled = true' "$config" >c && mv c "$config"
jq '.numStartups = 3 | .mcpServers.mine = {command: "/bin/mine"} | .mcpServers.permissions = {command: "/bin/users"}
  | .mcpServers.stale = {command: "/bin/old"}' "$claude" >c && mv c "$claude"
jq '.stale = {command: "/bin/old"}' "$record" >c && mv c "$record"
run
cp -r "$h" once
run
diff -r once "$h" || fail "a second run changed the home"
jq -e '.features.dictation.enabled == true and .daemon.relay.enabled == true' "$config" >/dev/null ||
  fail "the user's settings in config.json: $(<"$config")"
jq -e '.numStartups == 3 and .mcpServers == {mine: {command: "/bin/mine"}, permissions: {command: "/bin/users"}}' \
  "$claude" >/dev/null || fail ".claude.json with the user's entries: $(<"$claude")"
jq -e '. == {}' "$record" >/dev/null || fail "the record claims the user's server: $(<"$record")"

# Truncated files: left as they were, with a warning, the step going on
printf '{"a":' >"$config"
printf '{"mcpServers":' >"$claude"
run
[[ $(<"$config") == '{"a":' && $(<"$claude") == '{"mcpServers":' ]] || fail "a truncated file was replaced"
for f in "$config" "$claude"; do
  grep -qF "paseo-state: Left $f as it was" err || fail "no warning for the truncated $f: $(<err)"
done
echo "paseo-home: ok"
