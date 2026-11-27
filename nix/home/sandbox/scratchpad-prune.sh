# shellcheck shell=bash
# Prunes Claude Code's per-uid temp dir (the session scratchpads, bound from the host so they survive restarts):
# session dirs (<project>/<session>/) with nothing changed in 30 days, then emptied project dirs, and top-level
# files as old (harness state such as cache-break-state-*.json). The harness' own top-level dirs stay, they hold sockets
dir=${CLAUDE_CODE_TMPDIR:-${TMPDIR:-/tmp}}/claude-$(id -u)
[[ -d $dir ]] || exit 0
# Project dirs are named after the project's path, so they start with a dash
for session in "$dir"/-*/*/; do
  [[ -d $session && -z $(find "$session" -newermt '30 days ago' -print -quit) ]] || continue
  echo "Removing $session"
  rm -rf "$session"
done
find "$dir" -mindepth 1 -maxdepth 1 -name '-*' -type d -empty -delete
find "$dir" -mindepth 1 -maxdepth 1 -type f -mtime +30 -print -delete
