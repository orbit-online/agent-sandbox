package dbuspolicy

import "testing"

const app = "com.nixpak.ClaudeDesktop"

func talk(names ...string) Set { return Set{Talk: names} }

func call(name string, rules ...string) Set { return Set{Call: map[string][]string{name: rules}} }

// What each bus's policy refuses, and what it lets through next to it
func TestCheck(t *testing.T) {
	for _, tc := range []struct {
		bus string
		set Set
		ok  bool
	}{
		// The session bus's escapes, the names below them and wildcards covering them
		{"session", talk("org.freedesktop.DBus"), false},
		{"session", talk("ca.desrt.dconf"), false},
		{"session", Set{See: []string{"org.gnome.Terminal"}}, false},
		{"session", talk("org.gnome.Terminal.Window"), false},
		{"session", talk("org.freedesktop.secrets"), false},
		{"session", talk("org.gnome.keyring"), false},
		{"session", call("org.kde.KWin", "org.kde.kwin.Scripting.loadScript"), false},
		{"session", talk("org.kde.klauncher5"), false},
		{"session", talk("org.gnome.Mutter.RemoteDesktop"), false},
		{"session", talk("org.gnome.Mutter.ScreenCast"), false},
		{"session", talk("org.gnome.Shell"), false},
		{"session", talk("org.freedesktop.portal.Flatpak"), false},
		{"session", talk("org.freedesktop.Flatpak"), false},
		{"session", talk("org.freedesktop.systemd1"), false},
		{"session", talk("org.gnome.Mutter.*"), false},
		{"session", talk("org.gnome.Mutter.DisplayConfig"), true},
		{"session", talk("org.kde.klipper"), true},
		// Wildcards: three elements before .*, none over the portals
		{"session", talk("org.gnome.*"), false},
		{"session", talk("org.kde.*"), false},
		{"session", talk("org.freedesktop.*"), false},
		{"session", talk("ca.desrt.*"), false},
		{"session", Set{See: []string{"org.freedesktop.portal.*"}}, false},
		{"session", Set{See: []string{"org.freedesktop.portal.Desktop.*"}}, false},
		{"session", Set{See: []string{"org.freedesktop.portal.Documents.*"}}, false},
		{"session", talk("org.example.App.*"), true},
		{"session", talk("org.example.*"), false},
		// The portal: calls naming an interface, never RemoteDesktop or ScreenCast
		{"session", talk("org.freedesktop.portal.Desktop"), false},
		{"session", call("org.freedesktop.portal.Desktop", "*"), false},
		{"session", call("org.freedesktop.portal.Desktop", "@/org/freedesktop/portal/desktop"), false},
		{"session", call("org.freedesktop.portal.Desktop", "org.freedesktop.portal.RemoteDesktop.Start"), false},
		{"session", call("org.freedesktop.portal.Desktop", "org.freedesktop.portal.ScreenCast.*"), false},
		{"session", call("org.freedesktop.portal.Desktop", "org.freedesktop.portal.OpenURI.OpenURI"), true},
		{"session", Set{Broadcast: map[string][]string{"org.freedesktop.portal.Desktop": {"*"}}}, true},
		// A METHOD starting with * is every method, so only * alone
		{"session", call("org.example.App", "*.Get"), false},
		{"session", call("org.example.App", "*@/a"), true},
		// The system bus
		{"system", talk("org.freedesktop.PolicyKit1"), false},
		{"system", talk("org.freedesktop.systemd1"), false},
		{"system", talk("org.freedesktop.DBus"), false},
		{"system", talk("org.freedesktop.timedate1.*"), false},
		{"system", Set{Own: []string{app}}, false},
		{"system", talk("org.freedesktop.login1"), false},
		{"system", call("org.freedesktop.login1", "*"), false},
		{"system", call("org.freedesktop.login1", "org.freedesktop.login1.Manager.*"), false},
		{"system", call("org.freedesktop.login1", "org.freedesktop.login1.Manager.CanReboot@/org/freedesktop/login1"), true},
		{"system", talk("org.freedesktop.timedate1"), true},
		// own: the app ID, names below it not another launcher's, the tray's
		{"session", Set{Own: []string{app}}, true},
		{"session", Set{Own: []string{app + ".Helper"}}, true},
		{"session", Set{Own: []string{app + ".Helper.*"}}, true},
		{"session", Set{Own: []string{app + ".work"}}, false},
		{"session", Set{Own: []string{app + ".*"}}, false},
		{"session", Set{Own: []string{"org.freedesktop.StatusNotifierItem-12-1"}}, true},
		{"session", Set{Own: []string{"org.freedesktop.StatusNotifierWatcher"}}, false},
		{"session", Set{Own: []string{"org.example.App"}}, false},
		{"other", talk("org.example.App"), false},
	} {
		if err := Check(tc.bus, app, tc.set); (err == nil) != tc.ok {
			t.Errorf("%s %+v: %v, want ok %v", tc.bus, tc.set, err, tc.ok)
		}
	}
	if err := Check("session", "", Set{Own: []string{app}}); err == nil {
		t.Error("own without an app ID")
	}
}

// Method as the proxy parses a rule
func TestMethod(t *testing.T) {
	for rule, want := range map[string][2]string{
		"":                {"", ""},
		"*":               {"", ""},
		"*.Get":           {"", ""},
		"a.b.C.*@/x":      {"a.b.C", ""},
		"a.b.C.M":         {"a.b.C", "M"},
		"@/org/x":         {"", ""},
		"org.freedesktop": {"org", "freedesktop"},
	} {
		if i, m := Method(rule); i != want[0] || m != want[1] {
			t.Errorf("%q: %q %q, want %q", rule, i, m, want)
		}
	}
}
