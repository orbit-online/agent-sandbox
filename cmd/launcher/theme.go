package main

import (
	"fmt"
	"os/exec"
	"strconv"

	"github.com/godbus/dbus/v5"
)

// Electron takes light/dark from GTK, not the portal (electron/electron#25925), and GTK only follows GSettings live.
// The launcher mirrors the portal's color-scheme into the sandbox's GSettings keyfile as the GTK theme. The keyfile
// only works because buildFHSEnv's inner bwrap keeps nixpak's /.flatpak-info out of the FHS root; GTK3 would otherwise
// read the theme from the portal's org.gnome.* settings, which KDE leaves empty. The keyfile is in the sandbox's home,
// written through claude-desktop-state while the sandbox runs

const (
	portalName = "org.freedesktop.portal.Desktop"
	portalPath = "/org/freedesktop/portal/desktop"
	settings   = "org.freedesktop.portal.Settings"
)

// setTheme sets the sandbox's GTK theme for scheme (1 dark), the portal's when empty
func setTheme(cfg *config, scheme string) error {
	if scheme == "" {
		if conn, err := dbus.ConnectSessionBus(); err == nil {
			if s, err := readScheme(conn); err == nil {
				scheme = strconv.Itoa(int(s))
			}
			conn.Close()
		}
	}
	return applyScheme(cfg, scheme)
}

func applyScheme(cfg *config, scheme string) error {
	out, err := exec.Command(cfg.State, cfg.Home, "--", "theme", scheme).CombinedOutput()
	if err != nil {
		return fmt.Errorf("Set the GTK theme: %w: %s", err, out)
	}
	return nil
}

// readScheme asks the portal for its color-scheme: 0 no preference, 1 dark, 2 light
func readScheme(conn *dbus.Conn) (uint32, error) {
	var v dbus.Variant
	err := conn.Object(portalName, portalPath).Call(settings+".ReadOne", 0, "org.freedesktop.appearance", "color-scheme").Store(&v)
	if err != nil {
		return 0, err
	}
	s, ok := v.Value().(uint32)
	if !ok {
		return 0, fmt.Errorf("The portal's color-scheme is a %s", v.Signature())
	}
	return s, nil
}

// watchScheme calls changed with the portal's color-scheme now and on every change, until the connection closes
func watchScheme(conn *dbus.Conn, changed func(uint32)) error {
	if err := conn.AddMatchSignal(dbus.WithMatchObjectPath(portalPath), dbus.WithMatchInterface(settings),
		dbus.WithMatchMember("SettingChanged")); err != nil {
		return err
	}
	signals := make(chan *dbus.Signal, 16)
	conn.Signal(signals)
	if s, err := readScheme(conn); err == nil {
		changed(s)
	}
	go func() {
		for sig := range signals {
			if len(sig.Body) != 3 || sig.Body[0] != "org.freedesktop.appearance" || sig.Body[1] != "color-scheme" {
				continue
			}
			if v, ok := sig.Body[2].(dbus.Variant); ok {
				if s, ok := v.Value().(uint32); ok {
					changed(s)
				}
			}
		}
	}()
	return nil
}
