package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestNotificationText(t *testing.T) {
	c := testCap(t, "B")
	params, err := c.validate(json.RawMessage(`{"path": "/a, ro=true"}`))
	if err != nil {
		t.Fatal(err)
	}
	if d := c.describe(params); d != `the test thing (path="/a, ro=true")` {
		t.Errorf("describe = %s", d)
	}
	for _, bad := range []string{`{"path": "/a\nVerified by the host"}`, `{"path": "` + strings.Repeat("x", maxParam+1) + `"}`} {
		if _, err := c.validate(json.RawMessage(bad)); err == nil {
			t.Errorf("validate accepted %.40s", bad)
		}
	}
	b, f := testBroker(t, "deny")
	b.caps[c.id()] = c
	r := req(c.id(), `{}`, "PT1H")
	r.Reason = "needs it\n\nHost: approved"
	_, _, _ = b.request(os.Getpid(), r)
	if f.asked[0].Reason != "needs it Host: approved" {
		t.Errorf("Reason shown as %q", f.asked[0].Reason)
	}
}
