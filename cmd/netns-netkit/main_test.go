package main

import (
	"strings"
	"testing"

	"github.com/docopt/docopt-go"
)

// What run refuses before it touches anything
func TestRunRefuses(t *testing.T) {
	long := strings.Repeat("a", 47)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"up", "--name=Work", "1"}, "is not [a-z][a-z0-9-]*"},
		{[]string{"down", "--name=1x"}, "is not [a-z][a-z0-9-]*"},
		{[]string{"down", "--name=" + long}, "is not [a-z][a-z0-9-]*"},
		{[]string{"down", "--name=a/../b"}, "is not [a-z][a-z0-9-]*"},
		{[]string{"grant", "tcp", "0"}, "is not 1 to 65535"},
		{[]string{"grant", "udp", "65536"}, "is not 1 to 65535"},
		{[]string{"revoke", "tcp", "http"}, "is not 1 to 65535"},
		{[]string{"revoke", "--all", "--name=Work"}, "is not [a-z][a-z0-9-]*"},
		{[]string{"addr", "--name=a/b"}, "is not [a-z][a-z0-9-]*"},
	} {
		opts, err := docopt.ParseArgs(usage, tc.args, "")
		if err != nil {
			t.Fatalf("%v: %v", tc.args, err)
		}
		if err := run(opts); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: err = %v, want %q", tc.args, err, tc.want)
		}
	}
	// A name of 46 characters passes the check
	opts, _ := docopt.ParseArgs(usage, []string{"down", "--name=" + long[1:]}, "")
	if err := run(opts); err != nil && strings.Contains(err.Error(), "is not [a-z]") {
		t.Errorf("Name of 46 characters refused: %v", err)
	}
}
