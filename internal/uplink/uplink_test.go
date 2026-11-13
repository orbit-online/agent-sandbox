package uplink

import (
	"net/netip"
	"testing"
)

func TestULABlock(t *testing.T) {
	// hmac in Python over the same inputs gives fd51:383b:c9ef
	got, err := ULABlock("6f9a5b8a41ef434c8033785031738fda\n")
	if err != nil {
		t.Fatal(err)
	}
	if want := netip.MustParsePrefix("fd51:383b:c9ef::/48"); got != want {
		t.Errorf("ULABlock = %v, want %v", got, want)
	}
	other, _ := ULABlock("00000000000000000000000000000001")
	if other == got {
		t.Error("Two machine IDs gave the same block")
	}
	for _, bad := range []string{"", "6f9a5b8a41ef434c80337850317385", "zz9a5b8a41ef434c8033785031738fda"} {
		if _, err := ULABlock(bad); err == nil {
			t.Errorf("ULABlock(%q) took it", bad)
		}
	}
}

func TestKey(t *testing.T) {
	if got := Key(netip.MustParseAddr("169.254.100.2")); got != [16]byte{10: 0xff, 11: 0xff, 12: 169, 13: 254, 14: 100, 15: 2} {
		t.Errorf("Key(169.254.100.2) = %x", got)
	}
	a := netip.MustParseAddr("fd51:383b:c9ef::2")
	if got := Key(a); got != a.As16() {
		t.Errorf("Key(%v) = %x", a, got)
	}
}
