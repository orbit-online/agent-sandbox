package main

import "testing"

func TestPinName(t *testing.T) {
	for _, up := range []string{"eth0", "eth0.100", "wl-p2s0"} {
		name := pinName(up, "pre")
		if got, prog, ok := pinOf(name); !ok || got != up || prog != "pre" {
			t.Errorf("pinOf(%q) = %q, %q, %v", name, got, prog, ok)
		}
		for _, c := range name {
			if c == '.' {
				t.Errorf("pinName(%q) = %q, which bpffs refuses", up, name)
			}
		}
	}
}
