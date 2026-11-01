#!/usr/bin/env bash
# Usage: collect.sh DIR PREFIX
#   Adds this job's own builds to the binary cache in DIR and drops the paths no check of the flake builds any more.
#   Prints key=PREFIX<hash of the paths in it> to $GITHUB_OUTPUT, or key= when that's the key nix-cache-restore
#   restored ($NIX_CACHE_RESTORED) or DIR is empty.
#   Own builds: outputs in the checks' build closure that are valid here and carry no signature, so built here or
#   substituted from DIR. Fixed-output downloads stay out, fetching them again is cheap
set -euo pipefail
dir=$1 prefix=$2
mapfile -t drvs < <(nix eval --json .#checks.x86_64-linux --apply 'cs: map (c: c.drvPath) (builtins.attrValues cs)' |
  jq -r '.[]')
outputs=$(nix-store -qR "${drvs[@]}" | grep '\.drv$' | xargs nix-store -q --outputs | sort -u)
mapfile -t own < <(while read -r path; do [[ ! -e $path ]] || echo "$path"; done <<<"$outputs" |
  xargs nix path-info --json-format 1 --json |
  jq -r 'to_entries[] | select(.value != null and .value.signatures == [] and .value.ca == null) | .key')
shopt -s nullglob
cd "$dir"
if ((${#own[@]})); then
  # A binary cache takes a path only once it has the path's references. Those from cache.nixos.org get a stand-in
  # narinfo for the copy: substituting reads each path's narinfo on its own, so the cache never needs them
  stubs=()
  trap 'rm -f "${stubs[@]}"' EXIT
  while read -r ref; do
    stub=$(basename "$ref" | cut -c1-32).narinfo
    [[ ! -e $stub ]] || continue
    printf 'StorePath: %s\nURL: nar/none\nCompression: none\nNarHash: sha256:%s\nNarSize: 1\n' \
      "$ref" 0000000000000000000000000000000000000000000000000000 >"$stub"
    stubs+=("$stub")
  done < <(nix-store -q --references "${own[@]}" | sort -u | grep -vxFf <(printf '%s\n' "${own[@]}"))
  nix copy --no-recursive --to "file://$PWD?compression=zstd" "${own[@]}"
  rm -f "${stubs[@]}"
fi
for narinfo in *.narinfo; do
  grep -qxF "$(sed -n 's/^StorePath: //p' "$narinfo")" <<<"$outputs" || rm "$narinfo"
done
narinfos=(*.narinfo)
for nar in nar/*; do
  grep -qxF "URL: $nar" "${narinfos[@]}" /dev/null || rm "$nar"
done
key=
if ((${#narinfos[@]})); then
  key=$prefix$(printf '%s\n' "${narinfos[@]}" | sha256sum | cut -c1-32)
  [[ $key != "${NIX_CACHE_RESTORED:-}" ]] || key=
fi
echo "${#narinfos[@]} paths, $(du -sh . | cut -f1); key: ${key:-unchanged}"
echo "key=$key" >>"${GITHUB_OUTPUT:-/dev/null}"
