package main

import (
	"testing"

	"github.com/cilium/ebpf"
)

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

// Programs on a hook: p and q ours (pre, post), e einat, c Cilium at the tail, f another program at the head
func TestEinatLink(t *testing.T) {
	const p, q, e, e2, c, f ebpf.ProgramID = 1, 2, 10, 11, 20, 30
	ours := map[ebpf.ProgramID]bool{p: true, q: true}
	for _, tc := range []struct {
		name              string
		ids               []ebpf.ProgramID
		mine, known, head ebpf.ProgramID
		first             bool
		want              ebpf.ProgramID
	}{
		{"first round, einat at the head, nothing of ours", []ebpf.ProgramID{e, c}, 0, 0, 0, true, e},
		{"first round, pinned links, einat restarted", []ebpf.ProgramID{e2, p, q, c}, q, 0, p, true, e2},
		{"first round, another program ahead of einat", []ebpf.ProgramID{p, f, e, q, c}, q, 0, p, true, e},
		{"known, another program at the head since", []ebpf.ProgramID{f, p, e, q, c}, q, e, p, false, e},
		{"einat attached again at the head", []ebpf.ProgramID{e2, p, q, c}, q, e, p, false, e2},
		{"einat gone, Cilium left", []ebpf.ProgramID{p, q, c}, q, e, p, false, 0},
		// aim-office, 2026-11-13: Cilium alone on the hook when sandbox-uplink started, so the first round took it
		// for einat and post went after it, behind Cilium, where it never ran: replies reached the NIC and no
		// sandbox. einat attaching at the head revises it, on ingress right after pre and on egress at the head
		{"first round, Cilium alone", []ebpf.ProgramID{c}, 0, 0, 0, true, c},
		{"Cilium taken for einat, einat attached since", []ebpf.ProgramID{p, e, c, q}, q, c, p, false, e},
		{"the same on egress, where pre holds no head", []ebpf.ProgramID{e, c, q}, q, c, 0, false, e},
		{"Cilium taken for einat, einat not there yet", []ebpf.ProgramID{p, c, q}, q, c, p, false, c},
		{"einat gone on egress, Cilium left", []ebpf.ProgramID{q, c}, q, e, 0, false, 0},
	} {
		if got := einatProg(tc.ids, ours, tc.mine, tc.known, tc.head, tc.first); got != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, got, tc.want)
		}
	}
}
