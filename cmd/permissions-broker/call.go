package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/duration"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/hostcmd"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/wire"
)

// Calls of host commands: validated, covered by a grant or asked for, run as a transient user unit with the arguments
// on stdin, answered with what the command printed

const (
	// More than this on stdout fails the call
	maxOutput = 16 << 20
	// The tail of stderr a failed call reports
	maxStderr = 4 << 10
	// Calls kept for the window, and how much of a string argument each keeps
	maxCalls    = 200
	maxRecorded = 200
)

// A call as the window shows it
type callRecord struct {
	Grant string `json:"grant"`
	// The grant's capability, which the window names once the grant has ended
	Capability string          `json:"capability"`
	Time       time.Time       `json:"time"`
	Command    string          `json:"command"`
	Arguments  json.RawMessage `json:"arguments"`
	Exit       int             `json:"exit"`
	Error      string          `json:"error,omitempty"`
}

// call runs a host command under a grant that covers it, asking the user for one if none does. Everything the call
// carries is checked before the user is asked
func (b *broker) call(p peer, req wire.Request) (response, error) {
	c, ok := b.caps[req.Capability]
	if !ok || c.Type != "command" {
		return response{}, fmt.Errorf("No host commands %q: see list", req.Capability)
	}
	cmd, ok := c.Commands[req.Command]
	if !ok {
		return response{}, fmt.Errorf("%s has no command %q: see list", c.id(), req.Command)
	}
	params, err := c.validate(req.Params)
	if err != nil {
		return response{}, err
	}
	args, err := cmd.ValidateArgs(req.Arguments)
	if err != nil {
		return response{}, fmt.Errorf("%s_%s: %w", c.id(), req.Command, err)
	}
	reason, err := foldReason(req.Reason)
	if err != nil {
		return response{}, err
	}
	lease := req.Lease
	if lease == "" {
		lease = defaultLease
	}
	g, err := b.obtain(p, c, params, reason, lease, &askingCall{Command: req.Command, Arguments: cmd.Shown(args, 0)})
	if err != nil {
		return response{}, err
	}
	if g.Lease == "once" {
		// It covers this call only: made for it, never found by another
		defer g.end("its call was answered")
	}
	return b.runCall(c, req.Command, cmd, g, args)
}

// runCall runs cmd under g, once the instance's slot and a call slot are free. The grant must still be live then
// and when the output is handed out: a call may wait for a slot while the grant is revoked or runs out
func (b *broker) runCall(c *capability, name string, cmd *hostcmd.Command, g *grant, args json.RawMessage) (response, error) {
	release, err := c.callSlot(string(g.Params))
	if err != nil {
		return response{}, err
	}
	defer release()
	validity, err := b.callValidity(g, cmd)
	if err != nil {
		return response{}, err
	}
	if err := c.inList(g.Params); err != nil {
		return response{}, err
	}
	if !b.isLive(g) {
		return response{}, errors.New("The grant ended: ask again")
	}
	unit := unitPrefix(b.cfg.Launcher) + "call-" + randomID()
	// The grant ending stops the unit, whatever it started included. Until the call returns, as the end may come
	// before systemd has the unit
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-g.ended:
		case <-finished:
			return
		}
		for {
			_ = exec.Command(systemctl, "--user", "stop", unit).Run()
			select {
			case <-finished:
				return
			case <-time.After(500 * time.Millisecond):
			}
		}
	}()

	timeout, _ := duration.Parse(cmd.Timeout)
	runArgs := []string{"--user", "--quiet", "--pipe", "--collect", "--unit=" + unit,
		"--property=RuntimeMaxSec=" + strconv.Itoa(int(timeout.Seconds()))}
	if b.cfg.Unit != "" {
		runArgs = append(runArgs, "--property=BindsTo="+b.cfg.Unit, "--property=After="+b.cfg.Unit)
	}
	runArgs = append(append(runArgs, "--"), cmd.Run...)
	in, _ := json.Marshal(hostcmd.Input{Capability: c.id(), Command: name, Grant: g.ID, Bounding: g.Params, Arguments: args,
		Validity: duration.Format(validity)})
	// systemd ends the unit at RuntimeMaxSec; this ends the wait should systemd-run itself hang
	ctx, cancel := context.WithTimeout(context.Background(), timeout+runSlack)
	defer cancel()
	run := exec.CommandContext(ctx, systemdRun, runArgs...)
	out, errOut := &capped{max: maxOutput}, &tail{max: maxStderr}
	run.Stdin, run.Stdout, run.Stderr = bytes.NewReader(in), out, errOut
	runErr := run.Run()
	if runErr != nil && (ctx.Err() != nil || out.over) {
		_ = exec.Command(systemctl, "--user", "stop", unit).Run()
	}
	rec := callRecord{Grant: g.ID, Capability: c.id(), Time: b.now(), Command: name, Arguments: cmd.Shown(args, maxRecorded)}
	stderr := strings.TrimSpace(errOut.String())
	var exitErr *exec.ExitError
	switch {
	case out.over:
		rec.Error = strings.TrimSpace(fmt.Sprintf("printed more than %d bytes. %s", maxOutput, stderr))
	case ctx.Err() != nil:
		rec.Error = strings.TrimSpace("timed out. " + stderr)
	case errors.As(runErr, &exitErr):
		rec.Exit = exitErr.ExitCode()
		rec.Error = stderr
	case runErr != nil:
		rec.Error = runErr.Error()
	}
	b.recordCall(rec)
	if !b.isLive(g) {
		return response{}, errors.New("The grant ended: ask again")
	}
	if rec.Error != "" || rec.Exit != 0 {
		return response{}, fmt.Errorf("%s_%s failed (exit %d): %s", c.id(), name, rec.Exit, rec.Error)
	}
	res := response{Grant: b.view(g)}
	if cmd.Result == "text" {
		if !utf8.Valid(out.buf.Bytes()) {
			return response{}, fmt.Errorf("%s_%s printed something that isn't text", c.id(), name)
		}
		res.Output = out.buf.String()
	} else {
		res.Mime, res.Data = cmd.Result, out.buf.Bytes()
	}
	return res, nil
}

// callValidity is what a call is told its output may be valid for: the time g has left, at most cmd's maxValidity.
// None when neither bounds it
func (b *broker) callValidity(g *grant, cmd *hostcmd.Command) (time.Duration, error) {
	v, _ := duration.Parse(cmd.MaxValidity)
	if !g.Expires.IsZero() {
		left := g.Expires.Sub(b.now())
		if left <= 0 {
			return 0, errors.New("The grant just ran out: ask again")
		}
		if v == 0 || left < v {
			v = left
		}
	}
	return v, nil
}

// How long a call waits for its slot before it gives up, and how long past its timeout for systemd-run
var (
	callWait = 2 * time.Minute
	runSlack = 15 * time.Second
)

// callSlot waits until no other call with the same bounding values runs, and a call slot is free, callWait at most
func (c *capability) callSlot(instance string) (func(), error) {
	c.slotsMu.Lock()
	if c.slots == nil {
		c.slots = map[string]chan struct{}{}
	}
	slot, ok := c.slots[instance]
	if !ok {
		slot = make(chan struct{}, 1)
		c.slots[instance] = slot
	}
	c.slotsMu.Unlock()
	timeout := time.After(callWait)
	select {
	case slot <- struct{}{}:
	case <-timeout:
		return nil, errors.New("Other calls on this instance are still running: try again later")
	}
	select {
	case callSlots <- struct{}{}:
	case <-timeout:
		<-slot
		return nil, errors.New("Too many calls are running: try again later")
	}
	return func() {
		<-callSlots
		<-slot
	}, nil
}

func (b *broker) recordCall(rec callRecord) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, rec)
	if n := len(b.calls); n > maxCalls {
		b.calls = b.calls[n-maxCalls:]
	}
}

// capped keeps what's written up to max bytes, and fails the write past it
type capped struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (w *capped) Write(p []byte) (int, error) {
	if w.buf.Len()+len(p) > w.max {
		w.over = true
		return 0, errors.New("Too much output")
	}
	return w.buf.Write(p)
}

// tail keeps the last max bytes written
type tail struct {
	buf []byte
	max int
}

func (w *tail) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	if len(w.buf) > w.max {
		w.buf = w.buf[len(w.buf)-w.max:]
	}
	return len(p), nil
}

func (w *tail) String() string { return strings.ToValidUTF8(string(w.buf), "") }
