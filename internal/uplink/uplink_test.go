package uplink

import (
	"net/netip"
	"testing"
)

func TestULABlock(t *testing.T) {
	// hmac in Python over the same inputs gives fd51:383b:c9ef
	got, err := ulaBlock("6f9a5b8a41ef434c8033785031738fda\n")
	if err != nil {
		t.Fatal(err)
	}
	if want := netip.MustParsePrefix("fd51:383b:c9ef::/48"); got != want {
		t.Errorf("ULABlock = %v, want %v", got, want)
	}
	other, _ := ulaBlock("00000000000000000000000000000001")
	if other == got {
		t.Error("Two machine IDs gave the same block")
	}
	for _, bad := range []string{"", "6f9a5b8a41ef434c80337850317385", "zz9a5b8a41ef434c8033785031738fda"} {
		if _, err := ulaBlock(bad); err == nil {
			t.Errorf("ulaBlock(%q) took it", bad)
		}
	}
}
