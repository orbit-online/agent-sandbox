package main

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// What an uplink name may hold: kernel and udev names do, and it goes into the einat TOML unescaped
var ifName = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,15}$`)

// uplinks returns names when given, or else the physical NICs under sysNet (/sys/class/net) that carry Ethernet
// frames (type 1, ARPHRD_ETHER: Ethernet and Wi-Fi), whose header the programs parse. Sorted
func uplinks(sysNet string, names []string) ([]string, error) {
	if len(names) == 0 {
		entries, err := os.ReadDir(sysNet)
		if err != nil {
			return nil, fmt.Errorf("List network devices: %w", err)
		}
		for _, e := range entries {
			if _, err := os.Stat(filepath.Join(sysNet, e.Name(), "device")); err != nil {
				continue
			}
			typ, err := os.ReadFile(filepath.Join(sysNet, e.Name(), "type"))
			if err != nil || strings.TrimSpace(string(typ)) != "1" {
				continue
			}
			names = append(names, e.Name())
		}
	}
	for _, n := range names {
		if !ifName.MatchString(n) {
			return nil, fmt.Errorf("Uplink name %q: not an interface name", n)
		}
	}
	if len(names) == 0 {
		return nil, errors.New("No uplinks: no physical Ethernet or Wi-Fi device")
	}
	names = slices.Clone(names)
	slices.Sort(names)
	return slices.Compact(names), nil
}

// einatConfig is the einat config for the uplinks: NAT44 and NAT66 of the sandbox blocks alone (snat_internals), on
// ports above the ephemeral range of the kernel (32768-60999) and below 64xxx listeners. Link-local and ULA addresses on
// an uplink are never external: neither routes off the link or site. Hairpinning stays off (the einat default)
func einatConfig(uplinks []string, v4, v6 netip.Prefix) string {
	var b strings.Builder
	b.WriteString("# Written by sandbox-uplink einat-config\n[defaults]\n" +
		"tcp_ranges = [\"61000-63999\"]\nudp_ranges = [\"61000-63999\"]\n")
	for _, u := range uplinks {
		fmt.Fprintf(&b, "\n[[interfaces]]\nif_name = %q\nnat44 = true\nnat66 = true\nsnat_internals = [%q, %q]\n",
			u, v4.String(), v6.String())
		for _, local := range []string{"fe80::/10", "fc00::/7"} {
			fmt.Fprintf(&b, "\n[[interfaces.externals]]\nmatch_address = %q\nno_snat = true\nno_hairpin = true\n", local)
		}
	}
	return b.String()
}
