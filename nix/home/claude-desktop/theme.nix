# The sandbox's GTK theme follows the desktop's colour scheme, at launch and live (gtk-theme.sh, gtk-theme-watch.sh)
{
  lib,
  pkgs,
  config,
  sl,
  launcherName,
  ...
}:
let
  ids = sl.idsOf launcherName;
  gtkTheme = sl.script "gtk-theme.sh" {
    name = "claude-desktop-gtk-theme";
    runtimeInputs = [ pkgs.glib ];
    vars = {
      STATE = lib.getExe config.build.state;
      SANDBOX_HOME = ids.home;
    };
  };
in
{
  config = {
    env = {
      # Where gtk-theme.sh writes the theme
      GSETTINGS_BACKEND = "keyfile";
      XDG_DATA_DIRS = "${pkgs.gnome-themes-extra}/share\${XDG_DATA_DIRS:+:$XDG_DATA_DIRS}";
    };
    # The dark theme gtk-theme.sh switches to; GTK3 has none built in
    build.storeRoots = [ pkgs.gnome-themes-extra ];
    build.launcherVars.GTK_THEME = lib.getExe gtkTheme;
    build.appUnitVars.GTK_THEME_WATCH = lib.getExe (
      sl.script "gtk-theme-watch.sh" {
        name = "claude-desktop-gtk-theme-watch";
        runtimeInputs = [
          pkgs.glib
          pkgs.coreutils
          pkgs.procps
        ];
        vars.GTK_THEME = lib.getExe gtkTheme;
      }
    );
  };
}
