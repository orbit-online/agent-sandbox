package main

import (
	"bytes"
	"log/slog"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/orbit-online/agent-sandbox/internal/journal"
)

// Only a helper's own Step lines and the proxy's Listening line mark steps, not what the sandbox gets quoted into a
// helper's line
func TestMarker(t *testing.T) {
	cfg := &config{Launcher: "work"}
	for _, c := range []struct {
		e    entry
		want string
	}{
		{entry{"claude-desktop-work", "level=INFO msg=Step step=dhcp", time.Time{}}, stepDHCP},
		{entry{"dbus-proxy", "level=INFO msg=Listening path=/run/bus", time.Time{}}, stepProxy},
		{entry{"claude-desktop", "level=INFO msg=Step step=dhcp", time.Time{}}, ""},
		{entry{"dbus-proxy", `level=WARN msg=Refused member="x msg=Step step=dhcp"`, time.Time{}}, ""},
		{entry{"claude-desktop-work", `level=WARN msg=Refused member="x level=INFO msg=Step step=dhcp"`, time.Time{}}, ""},
		{entry{"udhcpc", "level=INFO msg=Step step=dhcp", time.Time{}}, ""},
	} {
		if got := marker(cfg, c.e); got != c.want {
			t.Errorf("%v: %q, want %q", c.e, got, c.want)
		}
	}
}

func secs(kv ...any) map[string]time.Duration {
	m := map[string]time.Duration{}
	for i := 0; i < len(kv); i += 2 {
		m[kv[i].(string)] = time.Duration(kv[i+1].(float64) * float64(time.Second))
	}
	return m
}

// Each step at its median share of the whole start, the bar creeping towards the next one and never past it
func TestEstimate(t *testing.T) {
	hist := []map[string]time.Duration{
		secs(stepPrepared, 1.0, stepProxy, 2.0, stepSandbox, 3.0, stepNetwork, 4.0, stepDHCP, 6.0, stepReady, 10.0),
		secs(stepPrepared, 0.5, stepProxy, 1.0, stepSandbox, 2.0, stepNetwork, 3.0, stepDHCP, 5.0, stepReady, 8.0),
		secs(stepPrepared, 2.0, stepProxy, 3.0, stepSandbox, 4.0, stepNetwork, 5.0, stepDHCP, 7.0, stepReady, 12.0),
	}
	p := newProgress(&splash{}, time.Now(), hist)
	near := func(got, want float64) bool { return got > want-1e-9 && got < want+1e-9 }
	if f, _ := p.estimate(0); f != 0 {
		t.Errorf("At the start: %v", f)
	}
	if f, _ := p.estimate(500 * time.Millisecond); !near(f, 0.05) {
		t.Errorf("Halfway to prepared: %v", f)
	}
	if f, _ := p.estimate(time.Hour); f > 0.1 || f < 0.09 {
		t.Errorf("Stuck before prepared: %v", f)
	}
	p.mark(stepDHCP, time.Now())
	p.at[stepDHCP] = 7 * time.Second
	if f, _ := p.estimate(7 * time.Second); !near(f, 0.6) {
		t.Errorf("At dhcp: %v", f)
	}
	if f, _ := p.estimate(9 * time.Second); !near(f, 0.6+0.4*0.5) {
		t.Errorf("Halfway to ready: %v", f)
	}
	if f, _ := p.estimate(time.Hour); f > 0.99 {
		t.Errorf("Past the end: %v", f)
	}
	// A step without history: from the last one with towards the next one with
	hist = []map[string]time.Duration{secs(stepPrepared, 1.0, stepSandbox, 3.0, stepReady, 10.0)}
	p = newProgress(&splash{}, time.Now(), hist)
	p.mark(stepPrepared, time.Now())
	p.at[stepPrepared] = time.Second
	p.mark(stepProxy, time.Now())
	if f, _ := p.estimate(2 * time.Second); !near(f, 0.1+0.2*0.5) {
		t.Errorf("Between prepared and sandbox: %v", f)
	}
	// A step missed this time: from the last one reached
	p = newProgress(&splash{}, time.Now(), hist)
	p.mark(stepSandbox, time.Now())
	p.at[stepSandbox] = 3 * time.Second
	if f, _ := p.estimate(3 * time.Second); !near(f, 0.3) {
		t.Errorf("Between prepared and sandbox: %v", f)
	}
	// No history: no estimate
	if _, ok := newProgress(&splash{}, time.Now(), nil).estimate(time.Second); ok {
		t.Error("An estimate without history")
	}
}

// What started logs, history reads back
func TestStartedLine(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(journal.Handler(&buf, true)))
	defer slog.SetDefault(prev)
	p := newProgress(&splash{}, time.Now(), nil)
	p.at = secs("", 0.0, stepPrepared, 0.512, stepDHCP, 3.25, stepReady, 9.0)
	p.started()
	line := strings.TrimSuffix(strings.TrimPrefix(buf.String(), "<6>"), "\n")
	want := secs(stepPrepared, 0.512, stepDHCP, 3.25, stepReady, 9.0)
	if got := parseStarted(line); !maps.Equal(got, want) {
		t.Errorf("%q: %v", line, got)
	}
	if parseStarted("level=INFO msg=Startedx a=1s") != nil || parseStarted("level=WARN msg=Started a=1s") != nil {
		t.Error("Took another line")
	}
}

func TestReadable(t *testing.T) {
	for in, want := range map[string]string{
		`level=WARN msg="No address from DHCP yet" k=v`: "No address from DHCP yet k=v",
		`level=ERROR msg=Refused member=x`:              "Refused member=x",
		`plain output`:                                  "plain output",
		`level=WARN msg="unterminated`:                  `level=WARN msg="unterminated`,
	} {
		if got := readable(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}

// journalctl's JSON: a string, bytes when not UTF-8, the first of a repeated field
func TestField(t *testing.T) {
	var got []entry
	readEntries(strings.NewReader(`{"MESSAGE":"a","SYSLOG_IDENTIFIER":"i","__REALTIME_TIMESTAMP":"1700000000123456"}
{"MESSAGE":[104,105,255],"SYSLOG_IDENTIFIER":["j","k"]}
not json
`), func(e entry) { got = append(got, e) })
	if len(got) != 2 || got[0].ident != "i" || got[0].msg != "a" || !got[0].at.Equal(time.UnixMicro(1700000000123456)) ||
		got[1].ident != "j" || got[1].msg != "hi\xff" || got[1].at.IsZero() {
		t.Errorf("%v", got)
	}
}

// Each step counts from when journald got its marker; one that comes after the app's ready line still counts for the
// durations, without moving the splash back
func TestLateMarker(t *testing.T) {
	began := time.Now()
	p := newProgress(&splash{}, began, nil)
	p.mark(stepNetwork, began.Add(2*time.Second))
	p.mark(stepProxy, began.Add(time.Second))
	p.mark(stepReady, began.Add(5*time.Second))
	p.mark(stepDHCP, began.Add(4*time.Second))
	p.mark(stepDHCP, began.Add(6*time.Second))
	want := secs("", 0.0, stepProxy, 1.0, stepNetwork, 2.0, stepDHCP, 4.0, stepReady, 5.0)
	if !maps.Equal(p.at, want) || steps[p.cur].name != stepReady {
		t.Errorf("%v at %s", p.at, steps[p.cur].name)
	}
}
