# shellcheck shell=bash
# Puts the core's environment.md ($CORE_SRC, with @app@, @appId@ and @environmentPath@ filled in) in place of the
# line `<!-- agent-sandbox: core -->` of the app's ($APP_SRC), which has it once, then splits the result by its
# markers into $out/environment.md (all of it, for consumers without memo), $out/core-environment.md (the sections
# every session needs, for those with memo) and $out/environment.memo (the rest, a memo store). `<!-- memo: FILTER -->` under a `## ` heading moves that section into the store as a memo
# with that filter; `<!-- memo-doc: ATTRIBUTE=VALUE # TEXT -->` documents a value in the store. The store injects
# `environment=$ENVIRONMENT`, the name in the environment doc's frontmatter
: "${APP_SRC:?}" "${CORE_SRC:?}" "${APP:?}" "${APP_ID:?}" "${ENVIRONMENT_PATH:?}"
: "${NAME:?}" "${DESCRIPTION:?}" "${ENVIRONMENT:?}" "${out:?}"

marker='<!-- agent-sandbox: core -->'
[[ $(grep -cxF "$marker" "$APP_SRC") == 1 ]] || { echo "$APP_SRC: needs the line $marker once" >&2; exit 1; }
core=$(sed -e "s|@app@|$APP|g" -e "s|@appId@|$APP_ID|g" -e "s|@environmentPath@|$ENVIRONMENT_PATH|g" "$CORE_SRC")
SRC=$(mktemp)
while IFS= read -r line; do
  if [[ $line == "$marker" ]]; then printf '%s\n' "$core"; else printf '%s\n' "$line"; fi
done <"$APP_SRC" >"$SRC"
! grep -q '@app@\|@appId@\|@environmentPath@' "$SRC" || { echo "$CORE_SRC: a placeholder left unfilled" >&2; exit 1; }

mkdir -p "$out"
awk -v out="$out" -v name="$NAME" -v description="$DESCRIPTION" -v environment="$ENVIRONMENT" '
  function flush(  slug) {
    if (filter == "") return
    slug = tolower(heading)
    gsub(/[^a-z0-9]+/, "-", slug)
    gsub(/^-|-$/, "", slug)
    sub(/^\n+/, "", body)
    sub(/\n+$/, "", body)
    memos = memos "-- " slug "/pragmas --\nfilter=" filter "\n-- " slug "/instructions --\n" body "\n"
    pointer = pointer (pointer == "" ? "" : ", ") heading " (`" filter "`)"
  }
  /^<!-- memo-doc: .* -->$/ {
    sub(/^<!-- memo-doc: /, ""); sub(/ -->$/, "")
    docs = docs $0 "\n"
    next
  }
  /^<!-- memo: .* -->$/ {
    sub(/^<!-- memo: /, ""); sub(/ -->$/, "")
    filter = $0
    next
  }
  # Held back until the marker under it, if any, is read
  /^## / {
    flush()
    heading = substr($0, 4)
    filter = ""
    body = ""
    full = full $0 "\n"
    held = $0 "\n"
    next
  }
  {
    full = full $0 "\n"
    if (held != "" && filter == "") core = core held
    held = ""
    if (filter == "") core = core $0 "\n"
    else body = body $0 "\n"
  }
  END {
    flush()
    printf "%s", full > (out "/environment.md")
    sub(/\n+$/, "\n", core)
    printf "%s\nMore loads through memo when the work touches it: %s.\n", core, pointer > (out "/core-environment.md")
    printf "-- store/properties --\nversion=1.0\nname=%s\ndescription=%s\n-- store/types --\nenvironment=string\n", name, description > (out "/environment.memo")
    printf "-- store/docs --\nenvironment # The environment the agent runs in\n%s", docs > (out "/environment.memo")
    printf "-- store/values/dynamic --\nunix=environment\n-- store/bin/environment --\n#!/bin/sh\necho environment=%s\n%s", environment, memos > (out "/environment.memo")
  }
' "$SRC"
