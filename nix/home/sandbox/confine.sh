# shellcheck shell=bash
# Runs $COMMAND (state.sh) for the host in a bwrap that holds only its closure (read-only) and the directories named
# before `--` (read-write). Those are the sandbox's to write, so it can plant links there, and swap them while it runs:
# here a link resolves within this view, to the sandbox's own files or to nothing, never to the host's. Checking for
# links in bash would race the running sandbox.
# $@: the directories, `--`, then the arguments of $COMMAND
: "${BWRAP:?}" "${CLOSURE:?}" "${COMMAND:?}"
args=()
while read -r p; do args+=(--ro-bind "$p" "$p"); done <"$CLOSURE"
while [[ ${1:?} != -- ]]; do
  args+=(--bind "$1" "$1")
  shift
done
shift
# /proc for nix, which reads /proc/self/exe; its pid namespace holds only this
exec "$BWRAP" --unshare-all --die-with-parent --new-session --clearenv --setenv HOME /tmp --setenv PATH /var/empty \
  --proc /proc --dev /dev --tmpfs /tmp "${args[@]}" -- "$COMMAND" "$@"
