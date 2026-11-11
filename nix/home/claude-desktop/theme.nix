# The sandbox's GTK theme, which the launcher keeps following the desktop's colour scheme (cmd/launcher/theme.go)
{ pkgs, ... }:
{
  env = {
    # Where the launcher writes the theme
    GSETTINGS_BACKEND = "keyfile";
    XDG_DATA_DIRS = "${pkgs.gnome-themes-extra}/share\${XDG_DATA_DIRS:+:$XDG_DATA_DIRS}";
  };
  # The dark theme the launcher switches to; GTK3 has none built in
  build.storeRoots = [ pkgs.gnome-themes-extra ];
}
