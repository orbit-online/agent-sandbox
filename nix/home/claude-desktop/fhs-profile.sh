# shellcheck shell=sh
# Appended to the FHS env's /etc/profile, which prepends /run/wrappers/bin:/usr/bin:/usr/sbin to PATH and is sourced
# twice on the way to the Code tab (buildFHSEnv's init, then the app's shell-path-worker running `$SHELL -l`).
# Moves the FHS dirs behind the module's PATH, once, so its tools win and FHS-only ones (tar, gzip, xz) stay reachable
fhs_prefix=/run/wrappers/bin:/usr/bin:/usr/sbin:
while case $PATH in "$fhs_prefix"*) true ;; *) false ;; esac; do PATH=${PATH#"$fhs_prefix"}; done
for fhs_dir in /usr/bin /usr/sbin; do
  case :$PATH: in *:$fhs_dir:*) ;; *) PATH=$PATH:$fhs_dir ;; esac
done
unset fhs_prefix fhs_dir
