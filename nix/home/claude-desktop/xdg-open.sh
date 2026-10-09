# shellcheck shell=bash
# No browser in the sandbox; hands links (incl. OAuth sign-in) to the host via the OpenURI portal.
# The D-Bus proxy blocks Introspect, so gdbus can't look up the signature: the options are typed explicitly
exec gdbus call --session \
  --dest org.freedesktop.portal.Desktop --object-path /org/freedesktop/portal/desktop \
  --method org.freedesktop.portal.OpenURI.OpenURI "" "$1" "@a{sv} {}"
