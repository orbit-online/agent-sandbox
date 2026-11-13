package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"
	"github.com/docopt/docopt-go"
	"github.com/orbit-online/agent-sandbox/internal/journal"
	"github.com/orbit-online/agent-sandbox/internal/uplink"
)

const usage = `sandbox-uplink - Programs of the sandbox network on the uplinks, around einat

Usage:
  sandbox-uplink einat-config [--uplink=<name>...] <file>
  sandbox-uplink run [--uplink=<name>...]

The uplinks are the devices named with --uplink, or else every physical NIC
carrying Ethernet frames (Ethernet and Wi-Fi), as the bridge or bond it is
enslaved to when it is. The sandboxes have addresses in 169.254.100.0/22 and
in a ULA /48 derived from the machine ID.

einat-config writes the einat config for the uplinks to <file>: NAT44 and NAT66
of the sandbox blocks on ports 61000-63999. Without uplinks, which einat refuses,
it writes nothing and exits 1, so as ExecCondition= the einat unit skips.
Errors exit 255, which fails it.

run loads the programs, reusing the registration map pinned in
/run/sandbox-uplink, and keeps them attached on every uplink, pinned there:
pre at the head of tcx ingress, post and egress right after the einat link
of tcx ingress and egress, so pre runs ahead of einat and the others after it
and ahead of programs attached at the tail (Cilium). It checks every half
second and puts them back where einat or a device change moved them, and
joins the mDNS groups on each uplink, so responses reach pre. It publishes
to the sandboxes (netns-netkit) the uplinks with all three programs attached,
and removes what sandboxes that are gone left.
`

// Set by the package to the compiled uplink.bpf.c
var object string

const sysNet = "/sys/class/net"

func main() {
	journal.Setup()
	opts, err := docopt.ParseDoc(usage)
	if err != nil {
		slog.Error("Parse arguments", "err", err)
		os.Exit(2)
	}
	names, _ := opts["--uplink"].([]string)
	if err := run(opts, names); err != nil {
		slog.Error(err.Error())
		os.Exit(255)
	}
}

func run(opts docopt.Opts, names []string) error {
	ups, err := uplinks(sysNet, names)
	if err != nil {
		return err
	}
	v6, err := uplink.ULABlock()
	if err != nil {
		return err
	}
	if ok, _ := opts.Bool("einat-config"); ok {
		if len(ups) == 0 {
			slog.Info("No uplinks, no einat config")
			os.Exit(1)
		}
		file, _ := opts.String("<file>")
		if err := os.WriteFile(file, []byte(einatConfig(ups, uplink.V4Block, v6)), 0o644); err != nil {
			return fmt.Errorf("Write the einat config: %w", err)
		}
		slog.Info("Wrote the einat config", "uplinks", ups, "ipv4", uplink.V4Block, "ipv6", v6)
		return nil
	}
	return attachAll(ups, v6)
}

func attachAll(ups []string, v6 netip.Prefix) error {
	l, err := load(object, uplink.PinDir, uplink.V4Block, v6)
	if err != nil {
		return err
	}
	if err := l.unpinOthers(ups); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	slog.Info("Keeping the programs attached", "uplinks", ups)
	// The links stay pinned when it stops
	l.keep(ctx, ups, 500*time.Millisecond, func() { daemon.SdNotify(false, daemon.SdNotifyReady) })
	return nil
}
