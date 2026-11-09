# shellcheck shell=bash
: "${QML_BIN:?}" "${QML_DIR:?}"
usage="permissions-window-preview - The Permissions window against a mock broker

Usage:
  permissions-window-preview [options]

Shows the window with a fixed state and applies its actions to it (printed on
stderr), for working on its looks.

Options:
  --qml=DIR         The window's QML, e.g. a checkout's
                    nix/packages/permissions-window [default: the package's]
  --state=FILE      The broker's state as JSON [default: the package's sample]
  --screenshot=PNG  Save the window's content to PNG and quit, offscreen
  --width=PX        [default: 640]
  --height=PX       [default: 720]
  --scale=N         Qt's scale factor, e.g. 2 for a HiDPI screenshot
  --page=TAB        The tab shown: requests, granted, activity or config
  --expand=KEYS     What's expanded, comma-separated: grant:<id>, details:<id>
  --style=STYLE     The Qt Quick Controls style, e.g. org.kde.desktop (Plasma's,
                    as the tests run) or Fusion [default: Qt's pick]
"
dir=$QML_DIR state="" shot="" width=640 height=720 scale="" page="" expand=""
for a in "$@"; do
  case $a in
  --qml=*) dir=${a#*=} ;;
  --state=*) state=${a#*=} ;;
  --screenshot=*) shot=${a#*=} ;;
  --width=*) width=${a#*=} ;;
  --height=*) height=${a#*=} ;;
  --scale=*) scale=${a#*=} ;;
  --page=*) page=${a#*=} ;;
  --expand=*) expand=${a#*=} ;;
  --style=*) export QT_QUICK_CONTROLS_STYLE=${a#*=} ;;
  -h | --help) printf '%s' "$usage"; exit 0 ;;
  *) printf '%s' "$usage" >&2; exit 2 ;;
  esac
done
state=$(realpath "${state:-$dir/preview-state.json}")
args=(--width "$width" --height "$height" --state "$state" --page "$page" --expand "$expand")
if [[ -n $shot ]]; then
  export QT_QPA_PLATFORM=offscreen
  args+=(--screenshot "$(realpath -m "$shot")")
fi
[[ -n $scale ]] && export QT_SCALE_FACTOR=$scale
export QML_XHR_ALLOW_FILE_READ=1 QT_FORCE_STDERR_LOGGING=1
exec "$QML_BIN" "$dir/Preview.qml" -- "${args[@]}"
