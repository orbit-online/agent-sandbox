package main

import (
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/orbit-online/agent-sandbox/internal/uplink"
	"github.com/vishvananda/netlink"
)

// The default route of the lowest metric through an uplink, whatever holds a lower one elsewhere (a full-tunnel VPN)
func TestGateway(t *testing.T) {
	ups := map[uint32]bool{2: true, 3: true}
	routes := []netlink.Route{
		{LinkIndex: 9, Priority: 0, Gw: net.ParseIP("10.66.0.1")},
		{LinkIndex: 3, Priority: 600, Gw: net.ParseIP("192.168.2.1")},
		{LinkIndex: 2, Priority: 100, Gw: net.ParseIP("192.168.1.1")},
		{LinkIndex: 0, Priority: 0},
	}
	want := uplink.Gateway{Ifindex: 2, Addr: [16]byte{10: 0xff, 11: 0xff, 12: 192, 13: 168, 14: 1, 15: 1}}
	if got := gateway(routes, ups); got != want {
		t.Errorf("gateway = %+v, want %+v", got, want)
	}
	v6 := []netlink.Route{{LinkIndex: 3, Gw: net.ParseIP("fe80::1")}}
	if got := gateway(v6, ups); got.Ifindex != 3 || got.Addr != [16]byte{0: 0xfe, 1: 0x80, 15: 1} {
		t.Errorf("gateway = %+v", got)
	}
	if got := gateway(routes[:1], ups); got != (uplink.Gateway{}) {
		t.Errorf("Only a VPN: gateway = %+v", got)
	}
	if got := gateway([]netlink.Route{{LinkIndex: 2}}, ups); got != (uplink.Gateway{Ifindex: 2}) {
		t.Errorf("No gateway: %+v", got)
	}
}

// A sandbox dir goes only while it names the gone primary it named when read first: an up of the same launcher may
// have put a new sandbox there meanwhile
func TestRemoveGone(t *testing.T) {
	gone := func(p uint32) bool { return p == 5 }
	for _, tc := range []struct {
		name  string
		reads []uint32
		want  bool
	}{
		{"gone", []uint32{5, 5}, true},
		{"running", []uint32{6, 6}, false},
		{"replaced meanwhile", []uint32{5, 7}, false},
	} {
		dir := filepath.Join(t.TempDir(), "1000")
		os.Mkdir(dir, 0o700)
		reads := tc.reads
		read := func(string) (uint32, error) {
			p := reads[0]
			reads = reads[1:]
			return p, nil
		}
		removed, err := removeGone(dir, read, gone)
		if err != nil {
			t.Fatal(err)
		}
		_, statErr := os.Stat(dir)
		if removed != tc.want || os.IsNotExist(statErr) != tc.want {
			t.Errorf("%s: removed %v, dir gone %v, want %v", tc.name, removed, os.IsNotExist(statErr), tc.want)
		}
	}
}

// A primary without pins goes once it has been without them past orphanGrace, a pinned one or one pinned meanwhile never
func TestOrphaned(t *testing.T) {
	since, t0 := map[uint32]time.Time{}, time.Unix(1000, 0)
	pinned := map[uint32]bool{7: true}
	if old := orphaned(since, []uint32{5, 6, 7}, pinned, t0); len(old) != 0 {
		t.Fatalf("at once: %v", old)
	}
	if old := orphaned(since, []uint32{5, 6, 7}, pinned, t0.Add(orphanGrace)); len(old) != 0 {
		t.Fatalf("within the grace: %v", old)
	}
	// 6 pinned meanwhile; 8 new
	pinned[6] = true
	if old := orphaned(since, []uint32{5, 6, 7, 8}, pinned, t0.Add(orphanGrace+time.Second)); !slices.Equal(old, []uint32{5}) {
		t.Errorf("past the grace: %v, want [5]", old)
	}
	if _, ok := since[6]; ok {
		t.Error("6 still tracked once pinned")
	}
	// 5 gone, 8 past the grace counted from when it was first seen
	if old := orphaned(since, []uint32{8}, pinned, t0.Add(2*orphanGrace+2*time.Second)); !slices.Equal(old, []uint32{8}) || len(since) != 1 {
		t.Errorf("later: %v, %v", old, since)
	}
}
