package main

import "testing"

func TestParseAddress(t *testing.T) {
	addrs, err := parseAddress("tcp:host=x;unix:path=/run/a%2cb,guid=00;unix:abstract=c")
	if err != nil || len(addrs) != 2 || addrs[0].Name != "/run/a,b" || addrs[1].Name != "@c" {
		t.Errorf("Got %v %v", addrs, err)
	}
	for _, bad := range []string{"tcp:host=x", "unix:path=%zz", "unix:path=%2"} {
		if _, err := parseAddress(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
