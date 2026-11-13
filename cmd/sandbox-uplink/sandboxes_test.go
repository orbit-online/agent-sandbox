package main

import (
	"net"
	"testing"

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
