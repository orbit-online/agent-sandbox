package main

import (
	"log/slog"
	"math"
	"slices"
	"strings"
	"sync"
	"time"
)

// The markers of the start's steps the host's helpers log as `Step step=<name>` (helper.go), besides supervise's own
const (
	stepPrepared = "prepared"
	stepProxy    = "proxy"
	stepSandbox  = "sandbox"
	stepNetwork  = "network"
	stepReady    = "ready"
)

// The start's steps in order, each from its marker on, with what the splash says meanwhile
var steps = []struct{ name, text string }{
	{"", "Preparing the sandbox"},
	{stepPrepared, "Starting the D-Bus proxy"},
	{stepProxy, "Creating the sandbox"},
	{stepSandbox, "Connecting the sandbox to the network"},
	{stepNetwork, "Starting Claude"},
	{stepReady, ""},
}

// marker is the step an entry of the host side's journal namespace marks, if any. The entry's start is a helper's own
// (slog's level and message): what the sandbox gets into a helper's line, a refused call's member say, is quoted after
func marker(cfg *config, e entry) string {
	switch e.ident {
	case progName(cfg):
		if name, ok := strings.CutPrefix(e.msg, "level=INFO msg=Step step="); ok {
			return name
		}
	case "dbus-proxy":
		if strings.HasPrefix(e.msg, "level=INFO msg=Listening ") {
			return stepProxy
		}
	}
	return ""
}

// progress shows the start's steps on the splash, and its progress estimated from earlier launches: each step at its
// median share of their time, the bar creeping towards the next step, never past it. The store's copy, which only a
// rebuild brings, counts for neither: it gets a segment of its own, see copying
type progress struct {
	sp *splash

	mu     sync.Mutex
	began  time.Time
	paused time.Duration // Copying the store
	pause  time.Time     // When the copy started, zero when not copying
	cur    int           // The step in steps
	at     map[string]time.Duration
	shown  float64 // The bar never goes back
	// From earlier launches: the median duration to each step, and the share of the whole start that makes
	median map[string]time.Duration
	share  map[string]float64
	// The bar when the copy started, and where its segment ended, which the rest of the start is scaled into
	copyFrom, copyTo float64
}

func newProgress(sp *splash, began time.Time, hist []map[string]time.Duration) *progress {
	p := &progress{sp: sp, began: began, at: map[string]time.Duration{"": 0}, median: map[string]time.Duration{"": 0}}
	for _, s := range steps[1:] {
		var ds []time.Duration
		for _, h := range hist {
			if d, ok := h[s.name]; ok {
				ds = append(ds, d)
			}
		}
		if len(ds) > 0 {
			slices.Sort(ds)
			p.median[s.name] = ds[len(ds)/2]
		}
	}
	if total := p.median[stepReady]; total > 0 {
		p.share = map[string]float64{"": 0}
		last := 0.0
		for _, s := range steps[1:] {
			if d, ok := p.median[s.name]; ok {
				last = min(max(last, float64(d)/float64(total)), 1)
				p.share[s.name] = last
			}
		}
	}
	p.mu.Lock()
	p.send(true)
	p.mu.Unlock()
	return p
}

// elapsed is the time since began without the copy's. Under mu
func (p *progress) elapsed(now time.Time) time.Duration {
	e := now.Sub(p.began) - p.paused
	if !p.pause.IsZero() {
		e -= now.Sub(p.pause)
	}
	return e
}

// mark takes the step name as begun at, and moves the splash on to it when it comes after the current one. A marker
// that comes late, after the app's ready line say, still counts for the durations
func (p *progress) mark(name string, at time.Time) {
	i := slices.IndexFunc(steps, func(s struct{ name, text string }) bool { return s.name == name })
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.at[name]; i < 0 || ok {
		return
	}
	p.at[name] = p.elapsed(at)
	if i > p.cur && p.cur != len(steps)-1 {
		p.cur = i
		if name != stepReady {
			p.send(true)
		}
	}
}

// copying shows the copy of the store at f, its time not counted. A copy runs from a few paths to the whole closure, so
// no history tells how long it takes: the rest of the bar goes by its time so far over that time extrapolated from f
// plus the rest of the start, which only grows and ends where the rest of the start takes over
func (p *progress) copying(f float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if p.pause.IsZero() {
		p.pause = now
		p.copyFrom = p.shown
	}
	g := f
	if p.share != nil {
		g = p.copyFrom + (1-p.copyFrom)*p.copyShare(f, now)
	}
	p.shown = max(p.shown, g)
	p.sp.step("Copying the sandbox's programs", &p.shown)
}

// copyShare is the share of the copy in what the start had left when the copy began, with f of it done. Under mu
func (p *progress) copyShare(f float64, now time.Time) float64 {
	c := float64(now.Sub(p.pause))
	rest := (1 - p.copyFrom) * float64(p.median[stepReady])
	if c*f == 0 {
		return 0
	}
	// c / (c/f + rest), c/f being the whole copy
	return c * f / (c + rest*f)
}

// copied ends a copy, if any: the step's text again
func (p *progress) copied() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pause.IsZero() {
		return
	}
	now := time.Now()
	if p.share != nil {
		p.copyTo = p.copyFrom + (1-p.copyFrom)*p.copyShare(1, now)
	}
	p.paused += now.Sub(p.pause)
	p.pause = time.Time{}
	p.send(true)
}

// tick moves the bar on
func (p *progress) tick() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pause.IsZero() {
		p.send(false)
	}
}

// send shows the estimate, with the step's text when text is set. Under mu
func (p *progress) send(text bool) {
	st := splashState{}
	if text {
		st.Text = steps[p.cur].text
	}
	if f, ok := p.estimate(p.elapsed(time.Now())); ok {
		if p.copyTo > 0 {
			// After a copy: the rest of the start in what the copy left
			f = p.copyTo + max(f-p.copyFrom, 0)/(1-p.copyFrom)*(1-p.copyTo)
		}
		p.shown = max(p.shown, f)
		st.Progress = &p.shown
	} else if !text {
		return
	}
	p.sp.send(st)
}

// estimate is the share of the start done after elapsed: from the latest step reached with a share towards the next
// step with one, over the median time between them. Under mu
func (p *progress) estimate(elapsed time.Duration) (float64, bool) {
	if p.share == nil {
		return 0, false
	}
	// The latest step reached, this time and in earlier launches
	from := ""
	for _, s := range steps[1 : p.cur+1] {
		_, had := p.share[s.name]
		if _, ok := p.at[s.name]; ok && had {
			from = s.name
		}
	}
	to := stepReady
	for _, s := range steps[p.cur+1:] {
		if _, ok := p.share[s.name]; ok {
			to = s.name
			break
		}
	}
	if from == stepReady {
		return 1, true
	}
	d := max(p.median[to]-p.median[from], 100*time.Millisecond)
	x := float64(elapsed-p.at[from]) / float64(d)
	return min(p.share[from]+(p.share[to]-p.share[from])*creep(x), 0.99), true
}

// creep is x up to 0.8, then nears 1 without reaching it, as smoothly
func creep(x float64) float64 {
	if x <= 0.8 {
		return max(x, 0)
	}
	return 0.8 + 0.2*(1-math.Exp(-(x-0.8)/0.2))
}

// started logs the durations to each step reached, which later launches estimate from (history), and the copy's
func (p *progress) started() {
	p.mu.Lock()
	defer p.mu.Unlock()
	var attrs []any
	for _, s := range steps[1:] {
		if d, ok := p.at[s.name]; ok {
			attrs = append(attrs, s.name, d.Round(time.Millisecond))
		}
	}
	if p.paused > 0 {
		attrs = append(attrs, "copy", p.paused.Round(time.Millisecond))
	}
	slog.Info("Started", attrs...)
}

// parseStarted reads a Started line as started logs it, nil for any other
func parseStarted(msg string) map[string]time.Duration {
	rest, ok := strings.CutPrefix(msg, "level=INFO msg=Started")
	if !ok || (rest != "" && rest[0] != ' ') {
		return nil
	}
	d := map[string]time.Duration{}
	for _, kv := range strings.Fields(rest) {
		k, v, _ := strings.Cut(kv, "=")
		if t, err := time.ParseDuration(v); err == nil {
			d[k] = t
		}
	}
	return d
}
