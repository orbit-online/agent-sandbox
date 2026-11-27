# shellcheck shell=bash
# Splits the environment doc by its markers. $MODE app: puts the core's environment.md ($CORE_SRC, with @app@, @appId@
# and @environmentPath@ filled in) in place of the line `<!-- agent-sandbox: core -->` of the app's ($APP_SRC), which
# has it once, and writes $out/environment.md (all of it, for consumers without memo), $out/core-environment.md (the
# sections every session needs, for those with memo, with a pointer to the rest) and $out/environment.memo, a memo
# store of the app's own sections that load by topic. $MODE core: the core's alone, $out/environment.memo the store of
# its sections that load by topic, which every app shares, so none of them may hold a placeholder. A section loads by
# topic with `<!-- memo: FILTER -->` under its `## ` heading; `<!-- memo-doc: ATTRIBUTE=VALUE # TEXT -->` documents a
# value in the store. A store injects `environment=$ENVIRONMENT`, the name in the environment doc's frontmatter
: "${MODE:?}" "${CORE_SRC:?}" "${NAME:?}" "${DESCRIPTION:?}" "${ENVIRONMENT:?}" "${out:?}"

SRC=$(mktemp)
if [[ $MODE == app ]]; then
  : "${APP_SRC:?}" "${APP:?}" "${APP_ID:?}" "${ENVIRONMENT_PATH:?}"
  marker='<!-- agent-sandbox: core -->'
  [[ $(grep -cxF "$marker" "$APP_SRC") == 1 ]] || { echo "$APP_SRC: needs the line $marker once" >&2; exit 1; }
  core=$(sed -e "s|@app@|$APP|g" -e "s|@appId@|$APP_ID|g" -e "s|@environmentPath@|$ENVIRONMENT_PATH|g" "$CORE_SRC")
  while IFS= read -r line; do
    if [[ $line == "$marker" ]]; then
      printf '%s\n%s\n%s\n' '<!-- agent-sandbox: core begin -->' "$core" '<!-- agent-sandbox: core end -->'
    else
      printf '%s\n' "$line"
    fi
  done <"$APP_SRC" >"$SRC"
  ! grep -q '@app@\|@appId@\|@environmentPath@' "$SRC" || { echo "$CORE_SRC: a placeholder left unfilled" >&2; exit 1; }
else
  { echo '<!-- agent-sandbox: core begin -->'; cat "$CORE_SRC"; echo '<!-- agent-sandbox: core end -->'; } >"$SRC"
fi

mkdir -p "$out"
awk -v out="$out" -v name="$NAME" -v description="$DESCRIPTION" -v environment="$ENVIRONMENT" -v mode="$MODE" '
  function flush(  slug, memo) {
    if (filter == "") return
    slug = tolower(heading)
    gsub(/[^a-z0-9]+/, "-", slug)
    gsub(/^-|-$/, "", slug)
    sub(/^\n+/, "", body)
    sub(/\n+$/, "", body)
    memo = "-- " slug "/pragmas --\nfilter=" filter "\n-- " slug "/instructions --\n" body "\n"
    # The store of the mode: the core'"'"'s sections in the core'"'"'s, the app'"'"'s in the app'"'"'s
    if (incore == (mode == "core")) {
      if (mode == "core" && body ~ /@(app|appId|environmentPath)@/) {
        print "the core'"'"'s section " heading " loads by topic, so every app shares it, but holds a placeholder" > "/dev/stderr"
        failed = 1
      }
      memos = memos memo
    }
    pointer = pointer (pointer == "" ? "" : ", ") heading " (`" filter "`)"
  }
  /^<!-- agent-sandbox: core begin -->$/ { flush(); filter = ""; incore = 1; next }
  /^<!-- agent-sandbox: core end -->$/ { flush(); filter = ""; incore = 0; next }
  /^<!-- memo-doc: .* -->$/ {
    sub(/^<!-- memo-doc: /, ""); sub(/ -->$/, "")
    if (incore == (mode == "core")) docs = docs $0 "\n"
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
    if (failed) exit 1
    printf "%s", full > (out "/environment.md")
    sub(/\n+$/, "\n", core)
    printf "%s\nMore loads through memo when the work touches it: %s.\n", core, pointer > (out "/core-environment.md")
    printf "-- store/properties --\nversion=1.0\nname=%s\ndescription=%s\n-- store/types --\nenvironment=string\n", name, description > (out "/environment.memo")
    printf "-- store/docs --\nenvironment # The environment the agent runs in\n%s", docs > (out "/environment.memo")
    printf "-- store/values/dynamic --\nunix=environment\n-- store/bin/environment --\n#!/bin/sh\necho environment=%s\n%s", environment, memos > (out "/environment.memo")
  }
' "$SRC"
