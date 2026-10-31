package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

const (
	// No answer in this long denies
	askTimeout = 2 * time.Minute
	// Once the user opens the window on a request, it waits this long at most
	optionsTimeout = 10 * time.Minute
	// Requests the user may turn down in a row before the broker stops asking about the capability for a while
	maxRefusals = 3
	blockFor    = 2 * time.Minute
	maxReason   = 300
	maxLog      = 200
	// Bounds on what a client can hold or send: open connections per socket (watch streams included), and a
	// request's size
	maxConns   = 64
	maxRequest = 64 << 10
)

// How long a client has to send its request
var readTimeout = 10 * time.Second

// A request on request.sock, or an operation on control.sock
type request struct {
	Op         string          `json:"op"`
	Capability string          `json:"capability,omitempty"`
	Params     json.RawMessage `json:"params,omitempty"`
	Reason     string          `json:"reason,omitempty"`
	Lease      string          `json:"lease,omitempty"`
	Grant      string          `json:"grant,omitempty"`
	// control.sock's answer to a pending request
	Pending string `json:"pending,omitempty"`
	Allow   bool   `json:"allow,omitempty"`
	// control.sock's end: processes holding a revoked grant
	Pids []int `json:"pids,omitempty"`
}

type response struct {
	Error        string           `json:"error,omitempty"`
	Grant        *grant           `json:"grant,omitempty"`
	Credential   string           `json:"credential,omitempty"`
	Grants       []*grant         `json:"grants,omitempty"`
	Capabilities []capabilityInfo `json:"capabilities,omitempty"`
	Pending      []*pending       `json:"pending,omitempty"`
	Holders      []holder         `json:"holders,omitempty"`
	Always       []alwaysGrant    `json:"always,omitempty"`
	Log          []logEntry       `json:"log,omitempty"`
}

type capabilityInfo struct {
	ID          string                     `json:"id"`
	Type        string                     `json:"type"`
	Description string                     `json:"description"`
	Params      map[string]json.RawMessage `json:"params,omitempty"`
	Instances   json.RawMessage            `json:"instances,omitempty"`
	Error       string                     `json:"error,omitempty"`
	// Type A: whether the plugin speaks MCP on its grant socket, whose tools the MCP server offers
	Tools bool `json:"tools,omitempty"`
}

type grant struct {
	ID         string          `json:"id"`
	Capability string          `json:"capability"`
	Params     json.RawMessage `json:"params"`
	Summary    string          `json:"summary"`
	Lease      string          `json:"lease"`
	Expires    time.Time       `json:"expires,omitzero"`
	// The sessions holding a session lease: it ends with the last
	Sessions []string `json:"sessions,omitempty"`
	Socket   string   `json:"socket,omitempty"`
	// Type C: where it's mounted in the sandbox, and what, as resolved
	Path    string    `json:"path,omitempty"`
	Source  string    `json:"source,omitempty"`
	Granted time.Time `json:"granted"`
	// Type C, once revoked: what still held files on it
	Holders []holder `json:"holders,omitempty"`
	// Type C: the device and root of its mount, by which copies of it are found
	dev, root string

	cap      *capability
	sessions map[string]*session // under broker.mu
	sessGone chan struct{}       // closed when the last session leaves
	ended    chan struct{}
	end      func(why string)
	unlock   func()
}

// A request waiting for the user, which the window can answer once they pick Options
type pending struct {
	ID         string          `json:"id"`
	Capability string          `json:"capability"`
	Params     json.RawMessage `json:"params"`
	Summary    string          `json:"summary"`
	Reason     string          `json:"reason"`
	Lease      string          `json:"lease"`
	Options    bool            `json:"options"`

	answer chan request
}

type alwaysGrant struct {
	Capability string          `json:"capability"`
	Params     json.RawMessage `json:"params"`
	Granted    time.Time       `json:"granted"`
}

type logEntry struct {
	Time     time.Time `json:"time"`
	Summary  string    `json:"summary"`
	Reason   string    `json:"reason,omitempty"`
	Decision string    `json:"decision"`
}

type storeData struct {
	Always []alwaysGrant `json:"always"`
	Log    []logEntry    `json:"log"`
}

// The notification's question and the user's answer: allow, deny or options
type prompt struct {
	Summary, Reason, Lease string
	// Whether to offer Options, which needs the window
	Options bool
}

type asker func(ctx context.Context, p prompt) (string, error)

type gate struct {
	asking       bool
	refused      int
	blockedUntil time.Time
}

type broker struct {
	cfg  config
	caps map[string]*capability
	sb   *sandbox
	ask  asker

	mu      sync.Mutex
	saving  sync.Mutex
	grants  map[string]*grant
	pending map[string]*pending
	gates   map[string]*gate
	store   storeData
	shared  bool
	lockOK  bool
	watches map[chan []byte]bool
	// Added to the time, by tests
	skew atomic.Int64
}

func newBroker(cfg config, caps map[string]*capability, sb *sandbox, ask asker) (*broker, error) {
	b := &broker{cfg: cfg, caps: caps, sb: sb, ask: ask, grants: map[string]*grant{}, pending: map[string]*pending{},
		gates: map[string]*gate{}, watches: map[chan []byte]bool{}}
	data, err := os.ReadFile(cfg.Store)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("Read the grant store: %w", err)
	default:
		// A broken store mustn't keep the daemon from starting: it's set aside, and always grants are asked again
		if err := json.Unmarshal(data, &b.store); err != nil {
			slog.Warn("Broken grant store, set aside", "store", cfg.Store, "err", err)
			b.store = storeData{}
			_ = os.Rename(cfg.Store, cfg.Store+".broken")
		}
	}
	return b, nil
}

// run reconciles what a previous daemon left, listens on both sockets, replays the always grants, and serves until
// the sandbox ends
func (b *broker) run() error {
	// What an earlier daemon left, if its ExecStopPost didn't get to it
	cleanup(b.cfg, b.sb)
	if err := os.MkdirAll(b.cfg.GrantDir, 0o700); err != nil {
		return fmt.Errorf("Create the grant directory: %w", err)
	}
	// claude-desktop.sh creates it; nothing in the sandbox can write there (it's bound read-only), but it must be
	// ours and a directory, not a link to elsewhere
	if fi, err := os.Lstat(b.cfg.GrantDir); err != nil || !fi.IsDir() || fi.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) {
		return fmt.Errorf("The grant directory %s isn't a directory of ours", b.cfg.GrantDir)
	}
	reqLn, err := listen(filepath.Join(b.cfg.GrantDir, "request.sock"))
	if err != nil {
		return err
	}
	ctlLn, err := listen(b.cfg.ControlSocket)
	if err != nil {
		return err
	}
	b.replay("A")
	b.adoptShared()
	go b.serveOn(reqLn, b.handleRequest)
	go b.serveOn(ctlLn, b.handleControl)
	slog.Info("Serving", "launcher", b.cfg.Launcher, "sandbox", b.sb.pid)
	fds := []unix.PollFd{{Fd: int32(b.sb.pidfd), Events: unix.POLLIN}}
	for {
		if _, err := unix.Poll(fds, -1); err == nil || !errors.Is(err, unix.EINTR) {
			break
		}
	}
	slog.Info("Sandbox ended")
	b.endAll("the sandbox ended")
	reqLn.Close()
	ctlLn.Close()
	return nil
}

func listen(path string) (*net.UnixListener, error) {
	_ = os.Remove(path)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("Listen on %s: %w", path, err)
	}
	return ln, nil
}

// serveOn serves a socket until it's closed. Each socket has its own connection budget, so the sandbox filling
// request.sock leaves control.sock to the window; accept errors (out of fds) are waited out, not fatal
func (b *broker) serveOn(ln *net.UnixListener, handle func(*net.UnixConn, int, request) response) {
	slots := make(chan struct{}, maxConns)
	backoff := 10 * time.Millisecond
	for {
		conn, err := ln.AcceptUnix()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			slog.Warn("Accept", "err", err)
			time.Sleep(backoff)
			backoff = min(2*backoff, time.Second)
			continue
		}
		backoff = 10 * time.Millisecond
		select {
		case slots <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		go func() {
			defer func() { <-slots }()
			defer conn.Close()
			pid, pidfd, err := peer(conn)
			if err != nil {
				return
			}
			defer unix.Close(pidfd)
			_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
			var req request
			if err := json.NewDecoder(io.LimitReader(conn, maxRequest)).Decode(&req); err != nil {
				_ = json.NewEncoder(conn).Encode(response{Error: "Not a JSON request"})
				return
			}
			_ = conn.SetReadDeadline(time.Time{})
			// The checks below read the peer's /proc entries by pid: refuse a peer gone by now, whose pid could be
			// another process's
			if !processAlive(pidfd) {
				return
			}
			if req.Op == "watch" {
				b.streamEvents(conn)
				return
			}
			_ = json.NewEncoder(conn).Encode(handle(conn, pid, req))
		}()
	}
}

// peer returns the peer's pid in our pid namespace and a pidfd for it (SO_PEERPIDFD), which tells whether the pid
// still names that process
func peer(conn *net.UnixConn) (int, int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, -1, err
	}
	pidfd := -1
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		pidfd, sockErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PEERPIDFD)
	}); err != nil {
		return 0, -1, err
	}
	if sockErr != nil {
		return 0, -1, sockErr
	}
	pid, err := pidfdPid(pidfd)
	if err != nil {
		unix.Close(pidfd)
		return 0, -1, err
	}
	return pid, pidfd, nil
}

// pidfdPid reads a pidfd's pid in our pid namespace from its fdinfo
func pidfdPid(pidfd int) (int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", pidfd))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "Pid:"); ok {
			pid, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil || pid <= 0 {
				return 0, fmt.Errorf("Peer gone or in another pid namespace: %q", v)
			}
			return pid, nil
		}
	}
	return 0, errors.New("No Pid in the pidfd's fdinfo")
}

// processAlive reports whether a pidfd's process still runs: a pidfd turns readable when it exits
func processAlive(pidfd int) bool {
	fds := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
	n, _ := unix.Poll(fds, 0)
	return n == 0
}

func (b *broker) handleRequest(_ *net.UnixConn, pid int, req request) response {
	var res response
	var err error
	switch req.Op {
	case "list":
		res.Capabilities = b.listCapabilities()
		res.Grants = b.grantViews("")
	case "request":
		var g *grant
		g, res.Credential, err = b.request(pid, req)
		res.Grant = b.view(g)
	case "release":
		err = b.release(req.Grant, "released from inside")
	case "status":
		sess, _ := sessionOf(pid, b.sb.pid)
		id := ""
		if sess != nil {
			id = sess.id
			unix.Close(sess.pidfd)
		}
		res.Grants = b.grantViews(id)
	case "share":
		err = b.shareFrom(pid)
	default:
		err = fmt.Errorf("Unknown operation %q", req.Op)
	}
	if err != nil {
		res.Error = err.Error()
	}
	return res
}

// handleControl serves the Permissions window and the launcher, which run on the host: a peer in another user
// namespace (anything in the sandbox, whatever path it reaches the socket by) gets nothing
func (b *broker) handleControl(_ *net.UnixConn, pid int, req request) response {
	if !sameNs(pid, "user") {
		return response{Error: "Only from the host"}
	}
	var res response
	var err error
	switch req.Op {
	case "state":
		b.mu.Lock()
		for _, p := range b.pending {
			res.Pending = append(res.Pending, p)
		}
		res.Always = append([]alwaysGrant(nil), b.store.Always...)
		res.Log = append([]logEntry(nil), b.store.Log...)
		b.mu.Unlock()
		res.Grants = b.grantViews("")
		res.Capabilities = b.listCapabilities()
	case "options":
		err = b.markOptions(req.Pending)
	case "answer":
		err = b.answer(req)
	case "revoke":
		res.Holders, err = b.revoke(req.Grant)
	case "end":
		err = b.endHolders(req.Pids)
	case "forget":
		err = b.forget(req.Capability, req.Params)
	default:
		err = fmt.Errorf("Unknown operation %q", req.Op)
	}
	if err != nil {
		res.Error = err.Error()
	}
	return res
}

func (b *broker) listCapabilities() []capabilityInfo {
	ids := make([]string, 0, len(b.caps))
	for id := range b.caps {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	infos := make([]capabilityInfo, len(ids))
	for i, id := range ids {
		c := b.caps[id]
		infos[i] = capabilityInfo{ID: id, Type: c.Type, Description: c.Description, Params: c.Params,
			Tools: c.Type == "A" && c.Tools}
		if inst, err := c.listInstances(context.Background()); err != nil {
			infos[i].Error = err.Error()
		} else {
			infos[i].Instances = inst
		}
	}
	return infos
}

func (b *broker) liveGrants(session string) []*grant {
	b.mu.Lock()
	defer b.mu.Unlock()
	var gs []*grant
	for _, g := range b.grants {
		if session == "" || slices.Contains(g.Sessions, session) {
			gs = append(gs, g)
		}
	}
	sort.Slice(gs, func(i, j int) bool { return gs[i].Granted.Before(gs[j].Granted) })
	return gs
}

// view is a copy of g for a response, taken under b.mu: the response is encoded outside it, while the grant's
// sessions may change
func (b *broker) view(g *grant) *grant {
	if g == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return snapshot(g)
}

func snapshot(g *grant) *grant {
	c := *g
	c.Sessions = slices.Clone(g.Sessions)
	c.Holders = slices.Clone(g.Holders)
	return &c
}

// grantViews is liveGrants as copies, for responses
func (b *broker) grantViews(session string) []*grant {
	gs := b.liveGrants(session)
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, g := range gs {
		gs[i] = snapshot(g)
	}
	return gs
}

// shareFrom makes the sandbox's grant directory shared in M1, asked by the FHS env's launcher script in M1 before the
// FHS env's bwrap copies it
func (b *broker) shareFrom(pid int) error {
	if !sameNsAs(pid, b.sb.pid, "mnt") {
		return errors.New("Only from the sandbox's outer mount namespace")
	}
	if err := b.sb.share(b.cfg.SandboxGrantDir); err != nil {
		return err
	}
	b.mu.Lock()
	b.shared = true
	b.mu.Unlock()
	go b.replay("C")
	return nil
}

// adoptShared takes over a grant directory an earlier daemon shared, and replays the type C always grants into it
func (b *broker) adoptShared() {
	if !b.sb.isShared(b.cfg.SandboxGrantDir) {
		return
	}
	b.mu.Lock()
	b.shared = true
	b.mu.Unlock()
	go b.replay("C")
}

// request asks the user for a grant, or finds one already there that covers it, and delivers it
func (b *broker) request(pid int, req request) (*grant, string, error) {
	c, ok := b.caps[req.Capability]
	if !ok {
		return nil, "", fmt.Errorf("No capability %q: see list", req.Capability)
	}
	params, err := c.validate(req.Params)
	if err != nil {
		return nil, "", err
	}
	reason := strings.Join(strings.FieldsFunc(req.Reason, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }), " ")
	if reason == "" {
		return nil, "", errors.New("Say why you need it: the user sees the reason")
	}
	if r := []rune(reason); len(r) > maxReason {
		reason = string(r[:maxReason]) + "…"
	}
	if c.Type == "C" {
		b.mu.Lock()
		shared := b.shared
		b.mu.Unlock()
		if !shared {
			return nil, "", errors.New("Folder and device grants need the sandbox's grant directory shared, which " +
				"failed when it started: restart the app")
		}
	}
	sess, err := sessionOf(pid, b.sb.pid)
	if err != nil {
		return nil, "", err
	}
	keepSess := false
	defer func() {
		if sess != nil && !keepSess {
			unix.Close(sess.pidfd)
		}
	}()
	lease := req.Lease
	if lease == "" {
		lease = "session"
	}
	if err := b.checkLease(lease, sess); err != nil {
		return nil, "", err
	}
	summary := c.describe(params)
	if c.Type == "C" {
		// Checked before asking: what's outside the ceiling is refused without bothering the user
		src, err := b.resolveC(c, params)
		if err != nil {
			return nil, "", err
		}
		summary = describeC(summary, src)
	} else if err := c.inList(context.Background(), params); err != nil {
		return nil, "", err
	}

	// Already granted: always grants and, for type B, a live grant decide whether to ask again. One request per
	// capability at a time here, so concurrent requests find the grant the first made instead of each making one
	c.covered.Lock()
	g := b.matching(c, params)
	if g != nil && g.Lease == "session" && sess != nil {
		// Another session wants it too: the grant now lasts until the last of them ends
		keepSess = b.addSession(g, sess)
	}
	if g == nil && b.isAlways(c, params) {
		if g, err = b.grant(c, params, summary, "always", nil); err != nil {
			c.covered.Unlock()
			return nil, "", err
		}
	}
	c.covered.Unlock()
	if g != nil {
		return b.deliver(c, g)
	}

	unlockGate, err := b.openGate(c.id())
	if err != nil {
		return nil, "", err
	}
	// always is picked in the window only: the notification offers the session, or an hour without one
	asked := lease
	if lease == "always" {
		asked = "PT1H"
		if sess != nil {
			asked = "session"
		}
	}
	answer, err := b.consent(c, params, summary, reason, asked)
	unlockGate(answer.Allow)
	if err != nil {
		return nil, "", fmt.Errorf("Asking the user: %w", err)
	}
	if !answer.Allow {
		b.logDecision(summary, reason, "denied")
		return nil, "", errors.New("The user didn't allow it")
	}
	if answer.Lease != lease {
		if err := b.checkLease(answer.Lease, sess); err != nil {
			return nil, "", err
		}
		lease = answer.Lease
	}
	if len(answer.Params) > 0 {
		if params, err = c.validate(answer.Params); err != nil {
			return nil, "", err
		}
		summary = c.describe(params)
		if c.Type == "C" {
			src, err := b.resolveC(c, params)
			if err != nil {
				return nil, "", err
			}
			summary = describeC(summary, src)
		} else if err := c.inList(context.Background(), params); err != nil {
			return nil, "", err
		}
	}
	g, err = b.grant(c, params, summary, lease, sess)
	if err != nil {
		return nil, "", err
	}
	keepSess = len(g.sessions) > 0
	b.logDecision(summary, reason, "allowed ("+lease+")")
	if lease == "always" {
		b.addAlways(c, params)
	}
	return b.deliver(c, g)
}

// deliver returns a grant's delivery: for type B a credential, issued for the grant's validity
func (b *broker) deliver(c *capability, g *grant) (*grant, string, error) {
	if c.Type != "B" {
		return g, "", nil
	}
	v := b.validity(c, g)
	if v <= 0 {
		return nil, "", errors.New("The grant just ran out: ask again")
	}
	cred, err := c.issue(context.Background(), g.Params, v)
	return g, cred, err
}

func (b *broker) now() time.Time { return time.Now().Add(time.Duration(b.skew.Load())) }

func (b *broker) checkLease(lease string, sess *session) error {
	switch lease {
	case "always":
	case "session":
		if sess == nil {
			return errors.New("No Claude Code session found above the caller, so no session lease: ask for a duration")
		}
	case "lock":
		b.mu.Lock()
		ok := b.lockOK
		b.mu.Unlock()
		if !ok {
			return errors.New("Screen lock isn't watched, so no lock lease: ask for a duration")
		}
	default:
		if _, err := parseDuration(lease); err != nil {
			return fmt.Errorf("Lease %q: session, lock, always or a duration such as PT1H", lease)
		}
	}
	return nil
}

// validity is how long a type B credential lasts: maxValidity, or a duration lease's remainder if shorter
func (b *broker) validity(c *capability, g *grant) time.Duration {
	v, _ := parseDuration(c.Ceiling.MaxValidity)
	if !g.Expires.IsZero() {
		if left := g.Expires.Sub(b.now()); left < v {
			v = left
		}
	}
	return v
}

func (b *broker) matching(c *capability, params json.RawMessage) *grant {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, g := range b.grants {
		if g.cap == c && string(g.Params) == string(params) {
			return g
		}
	}
	return nil
}

// isAlways: exact parameters only, so read-only never covers read-write and a folder never its sub- or parent folder
func (b *broker) isAlways(c *capability, params json.RawMessage) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, a := range b.store.Always {
		if a.Capability == c.id() && string(a.Params) == string(params) {
			return true
		}
	}
	return false
}

// openGate allows one open request per capability, and none for a while after maxRefusals in a row. The returned
// function closes it with the user's decision
func (b *broker) openGate(id string) (func(allowed bool), error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	g := b.gates[id]
	if g == nil {
		g = &gate{}
		b.gates[id] = g
	}
	switch {
	case g.asking:
		return nil, errors.New("The user hasn't answered your last request for this yet")
	case b.now().Before(g.blockedUntil):
		return nil, fmt.Errorf("The user turned down %d requests in a row: ask again after %s", maxRefusals,
			g.blockedUntil.Format(time.TimeOnly))
	}
	g.asking = true
	return func(allowed bool) {
		b.mu.Lock()
		defer b.mu.Unlock()
		g.asking = false
		if allowed {
			g.refused = 0
			return
		}
		if g.refused++; g.refused >= maxRefusals {
			g.refused = 0
			g.blockedUntil = b.now().Add(blockFor)
		}
	}, nil
}

type decision struct {
	Allow  bool
	Lease  string
	Params json.RawMessage
}

// consent asks with a notification. Options hands the request to the window, which answers through control.sock
func (b *broker) consent(c *capability, params json.RawMessage, summary, reason, lease string) (decision, error) {
	p := &pending{ID: randomID(), Capability: c.id(), Params: params, Summary: summary, Reason: reason, Lease: lease,
		answer: make(chan request, 1)}
	b.mu.Lock()
	b.pending[p.ID] = p
	b.mu.Unlock()
	b.event("pending", p.ID)
	defer func() {
		b.mu.Lock()
		delete(b.pending, p.ID)
		b.mu.Unlock()
		b.event("answered", p.ID)
	}()

	ctx, cancelTimeout := context.WithTimeout(context.Background(), askTimeout)
	defer cancelTimeout()
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	type result struct {
		action string
		err    error
	}
	asked := make(chan result, 1)
	go func() {
		action, err := b.ask(ctx, prompt{Summary: summary, Reason: reason, Lease: lease, Options: len(b.cfg.Window) > 0})
		asked <- result{action, err}
	}()
	select {
	case r := <-asked:
		switch {
		case r.err != nil:
			return decision{}, r.err
		case r.action == "allow":
			return decision{Allow: true, Lease: lease}, nil
		case r.action != "options":
			return decision{}, nil
		}
		_ = b.markOptions(p.ID)
		if err := b.openWindow(); err != nil {
			slog.Warn("Open the window", "err", err)
		}
	case a := <-p.answer:
		// Answered in the window while the notification was up
		cancel(errAnswered)
		return windowDecision(a, lease), nil
	}
	select {
	case a := <-p.answer:
		return windowDecision(a, lease), nil
	case <-time.After(optionsTimeout):
		return decision{}, nil
	}
}

// Why a notification is taken down early: the user answered in the window
var errAnswered = errors.New("answered in the window")

func windowDecision(a request, lease string) decision {
	if a.Lease == "" {
		a.Lease = lease
	}
	return decision{Allow: a.Allow, Lease: a.Lease, Params: a.Params}
}

func (b *broker) markOptions(id string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	p, ok := b.pending[id]
	if !ok {
		return fmt.Errorf("No pending request %q", id)
	}
	p.Options = true
	return nil
}

func (b *broker) answer(req request) error {
	b.mu.Lock()
	p, ok := b.pending[req.Pending]
	b.mu.Unlock()
	if !ok {
		return fmt.Errorf("No pending request %q", req.Pending)
	}
	select {
	case p.answer <- req:
		return nil
	default:
		return errors.New("Already answered")
	}
}

// grant makes a grant live: delivers type A and ties it to its lease
func (b *broker) grant(c *capability, params json.RawMessage, summary, lease string, sess *session) (*grant, error) {
	unlock, err := c.exclusiveLock(b.cfg.Launcher, params)
	if err != nil {
		return nil, err
	}
	g := &grant{ID: randomID(), Capability: c.id(), Params: params, Summary: summary, Lease: lease,
		Granted: b.now(), cap: c, ended: make(chan struct{}), unlock: unlock, sessions: map[string]*session{},
		sessGone: make(chan struct{})}
	if lease == "session" {
		g.sessions[sess.id], g.Sessions = sess, []string{sess.id}
	}
	if d, err := parseDuration(lease); err == nil {
		g.Expires = g.Granted.Add(d)
	}
	if c.Type == "A" {
		host := filepath.Join(b.cfg.GrantDir, g.ID+".sock")
		if err := c.startServe(b.cfg.Launcher, g.ID, host, b.cfg.Unit, params); err != nil {
			unlock()
			return nil, err
		}
		g.Socket = filepath.Join(b.cfg.SandboxGrantDir, g.ID+".sock")
	}
	if c.Type == "C" {
		if err := b.mountC(g); err != nil {
			unlock()
			return nil, err
		}
	}
	stopWatch, watchDone, err := c.startWatch(params)
	if err != nil {
		switch c.Type {
		case "A":
			_ = stopServe(b.cfg.Launcher, g.ID)
		case "C":
			b.unmountC(g)
		}
		unlock()
		return nil, err
	}
	var once sync.Once
	g.end = func(why string) {
		once.Do(func() {
			b.mu.Lock()
			delete(b.grants, g.ID)
			b.mu.Unlock()
			stopWatch()
			switch c.Type {
			case "A":
				if err := stopServe(b.cfg.Launcher, g.ID); err != nil {
					slog.Warn("Revoke", "grant", g.ID, "err", err)
				}
			case "C":
				b.unmountC(g)
			}
			b.mu.Lock()
			for id, s := range g.sessions {
				unix.Close(s.pidfd)
				delete(g.sessions, id)
			}
			b.mu.Unlock()
			g.unlock()
			close(g.ended)
			slog.Info("Grant ended", "grant", g.ID, "capability", g.Capability, "why", why)
			b.event("ended", g.ID)
		})
	}
	b.mu.Lock()
	b.grants[g.ID] = g
	b.mu.Unlock()
	go b.lease(g, watchDone)
	slog.Info("Granted", "grant", g.ID, "capability", g.Capability, "lease", lease)
	b.event("granted", g.ID)
	return g, nil
}

// lease ends g when its time runs out, its session's anchor exits, or its plugin's watch exits. Lock leases end
// through lockEvent
func (b *broker) lease(g *grant, watchDone <-chan struct{}) {
	var timeout <-chan time.Time
	if !g.Expires.IsZero() {
		t := time.NewTimer(g.Expires.Sub(b.now()))
		defer t.Stop()
		timeout = t.C
	}
	b.mu.Lock()
	for _, s := range g.sessions {
		go b.watchSession(g, s)
	}
	b.mu.Unlock()
	select {
	case <-timeout:
		g.end("its time ran out")
	case <-g.sessGone:
		g.end("its sessions ended")
	case <-watchDone:
		g.end("its plugin's watch ended")
	case <-g.ended:
	}
}

// addSession ties a session lease to one more session. Returns whether it took the session's pidfd
func (b *broker) addSession(g *grant, s *session) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := g.sessions[s.id]; ok || len(g.sessions) == 0 {
		// Known, or the grant is ending: its last session left
		return false
	}
	g.sessions[s.id] = s
	g.Sessions = append(g.Sessions, s.id)
	go b.watchSession(g, s)
	return true
}

// watchSession drops s from g when its anchor exits, and closes g.sessGone when it was the last
func (b *broker) watchSession(g *grant, s *session) {
	fds := []unix.PollFd{{Fd: int32(s.pidfd), Events: unix.POLLIN}}
	for {
		// Wakes every few seconds to notice the grant ending otherwise
		n, err := unix.Poll(fds, 5000)
		select {
		case <-g.ended:
			return
		default:
		}
		if n > 0 {
			break
		}
		if err != nil && !errors.Is(err, unix.EINTR) {
			return
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if g.sessions[s.id] != s {
		return
	}
	unix.Close(s.pidfd)
	delete(g.sessions, s.id)
	g.Sessions = slices.DeleteFunc(g.Sessions, func(id string) bool { return id == s.id })
	if len(g.sessions) == 0 {
		close(g.sessGone)
	}
}

// lockEvent ends every lock lease: the screen locked or the machine went to sleep
func (b *broker) lockEvent(why string) {
	for _, g := range b.liveGrants("") {
		if g.Lease == "lock" {
			g.end(why)
		}
	}
}

// revoke ends a grant for the user and returns what still held files on it (type C)
func (b *broker) revoke(id string) ([]holder, error) {
	b.mu.Lock()
	g, ok := b.grants[id]
	b.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("No grant %q", id)
	}
	g.end("revoked by the user")
	return g.Holders, nil
}

// endHolders ends processes the window lists as holding a revoked grant, if they are in the sandbox
func (b *broker) endHolders(pids []int) error {
	var errs []error
	for _, pid := range pids {
		// Through a pidfd taken before the check, so the pid can't be another process's by the signal
		fd, err := unix.PidfdOpen(pid, 0)
		if err != nil {
			continue // gone already
		}
		if !b.sb.isDescendant(pid) {
			errs = append(errs, fmt.Errorf("%d isn't in the sandbox", pid))
		} else if err := unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
			errs = append(errs, fmt.Errorf("End %d: %w", pid, err))
		}
		unix.Close(fd)
	}
	return errors.Join(errs...)
}

func (b *broker) release(id, why string) error {
	b.mu.Lock()
	g, ok := b.grants[id]
	b.mu.Unlock()
	if !ok {
		return fmt.Errorf("No grant %q", id)
	}
	g.end(why)
	return nil
}

func (b *broker) endAll(why string) {
	for _, g := range b.liveGrants("") {
		g.end(why)
	}
}

// replay grants the stored always grants of a type: A at launch, C once the grant directory is shared. Type B is
// issued on request without asking
func (b *broker) replay(typ string) {
	b.mu.Lock()
	always := append([]alwaysGrant(nil), b.store.Always...)
	b.mu.Unlock()
	for _, a := range always {
		c, ok := b.caps[a.Capability]
		if !ok || c.Type != typ {
			continue
		}
		params, err := c.validate(a.Params)
		if err != nil {
			slog.Warn("Replay", "capability", a.Capability, "err", err)
			continue
		}
		summary := c.describe(params)
		if typ == "C" {
			src, err := b.resolveC(c, params)
			if err != nil {
				slog.Warn("Replay", "capability", a.Capability, "err", err)
				continue
			}
			summary = describeC(summary, src)
		}
		if _, err := b.grant(c, params, summary, "always", nil); err != nil {
			slog.Warn("Replay", "capability", a.Capability, "err", err)
		}
	}
}

func (b *broker) addAlways(c *capability, params json.RawMessage) {
	b.mu.Lock()
	b.store.Always = append(b.store.Always, alwaysGrant{Capability: c.id(), Params: params, Granted: b.now()})
	b.mu.Unlock()
	b.save()
}

// forget removes an always grant and ends its live grant
func (b *broker) forget(capID string, params json.RawMessage) error {
	c, ok := b.caps[capID]
	if !ok {
		return fmt.Errorf("No capability %q", capID)
	}
	params, err := c.validate(params)
	if err != nil {
		return err
	}
	b.mu.Lock()
	kept := b.store.Always[:0]
	for _, a := range b.store.Always {
		if a.Capability != capID || string(a.Params) != string(params) {
			kept = append(kept, a)
		}
	}
	b.store.Always = kept
	b.mu.Unlock()
	b.save()
	if g := b.matching(c, params); g != nil && g.Lease == "always" {
		g.end("forgotten by the user")
	}
	return nil
}

func (b *broker) logDecision(summary, reason, decision string) {
	b.mu.Lock()
	b.store.Log = append(b.store.Log, logEntry{Time: b.now(), Summary: summary, Reason: reason, Decision: decision})
	if n := len(b.store.Log); n > maxLog {
		b.store.Log = b.store.Log[n-maxLog:]
	}
	b.mu.Unlock()
	b.save()
}

// save writes the store atomically, one save at a time so an older snapshot can't land last
func (b *broker) save() {
	b.saving.Lock()
	defer b.saving.Unlock()
	b.mu.Lock()
	data, _ := json.MarshalIndent(b.store, "", "  ")
	b.mu.Unlock()
	tmp := b.cfg.Store + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err == nil {
		_, err = f.Write(data)
		err = errors.Join(err, f.Sync(), f.Close())
	}
	if err == nil {
		err = os.Rename(tmp, b.cfg.Store)
	}
	if err != nil {
		slog.Warn("Save the grant store", "err", err)
	}
}

// removeOwnLocks removes the exclusive locks a previous daemon of this launcher left
func (b *broker) removeOwnLocks() { removeLocks(b.cfg.Launcher) }

// event tells watch streams (the MCP servers, the window) that something changed; they ask for the state
func (b *broker) event(kind, id string) {
	line, _ := json.Marshal(map[string]string{"event": kind, "id": id})
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.watches {
		select {
		case ch <- line:
		default:
		}
	}
}

func (b *broker) streamEvents(conn *net.UnixConn) {
	ch := make(chan []byte, 16)
	b.mu.Lock()
	b.watches[ch] = true
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.watches, ch)
		b.mu.Unlock()
	}()
	closed := make(chan struct{})
	go func() {
		_, _ = bufio.NewReader(conn).ReadByte()
		close(closed)
	}()
	for {
		select {
		case line := <-ch:
			if _, err := conn.Write(append(line, '\n')); err != nil {
				return
			}
		case <-closed:
			return
		}
	}
}

// openWindow opens the Permissions window on the host, as a unit of its own
func (b *broker) openWindow() error {
	if len(b.cfg.Window) == 0 {
		return errors.New("No window configured")
	}
	args := append([]string{"--user", "--collect", "--quiet", "--"}, b.cfg.Window...)
	return exec.Command(systemdRun, args...).Run()
}

// notifyAsk asks with a notification that has Allow, Deny and Options buttons. Not answering in time denies, and the
// notification is replaced by one without buttons, so a late click doesn't look like it worked. An answer within a
// second of the notification appearing is ignored and the question asked again: the sandbox can post look-alike
// notifications, timed to sit where the user is about to click
func notifyAsk(ctx context.Context, p prompt) (string, error) {
	summary := "Claude asks for " + escapeMarkup(p.Summary)
	body := "Claude's reason, in its own words: " + escapeMarkup(strconv.Quote(p.Reason))
	allow := "Allow " + leaseLabel(p.Lease)
	for {
		idR, idW, err := os.Pipe()
		if err != nil {
			return "", err
		}
		args := []string{"--app-name=Claude permissions", "--icon=security-medium", "--urgency=critical", "--id-fd=3",
			"--action=allow=" + allow, "--action=deny=Deny"}
		if p.Options {
			args = append(args, "--action=options=Options…")
		}
		cmd := exec.CommandContext(ctx, notifySend, append(args, summary, body)...)
		cmd.ExtraFiles = []*os.File{idW}
		var out strings.Builder
		cmd.Stdout = &out
		if err := cmd.Start(); err != nil {
			idW.Close()
			idR.Close()
			return "", err
		}
		idW.Close()
		// notify-send prints the id once the notification is up: the second counts from there
		id, _ := bufio.NewReader(idR).ReadString('\n')
		shown := time.Now()
		idR.Close()
		err = cmd.Wait()
		if ctx.Err() != nil {
			title, body := "Claude's request timed out", "Not granted: "+escapeMarkup(p.Summary)
			if errors.Is(context.Cause(ctx), errAnswered) {
				title, body = "Answered in the Permissions window", escapeMarkup(p.Summary)
			}
			if id = strings.TrimSpace(id); id != "" {
				_ = exec.Command(notifySend, "--app-name=Claude permissions", "--icon=security-medium",
					"--replace-id="+id, "--expire-time=10000", title, body).Run()
			}
			return "deny", nil
		}
		if err != nil {
			return "", err
		}
		action := strings.TrimSpace(out.String())
		if action != "" && time.Since(shown) < time.Second {
			continue
		}
		return action, nil
	}
}

func escapeMarkup(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func leaseLabel(lease string) string {
	switch lease {
	case "session":
		return "for this session"
	case "lock":
		return "until the screen locks"
	}
	if d, err := parseDuration(lease); err == nil {
		return "for " + d.String()
	}
	return lease
}

var durationRe = regexp.MustCompile(`^PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?$`)

// parseDuration reads the ISO 8601 durations leases use: PT1H, PT30M, PT1H30M
func parseDuration(s string) (time.Duration, error) {
	m := durationRe.FindStringSubmatch(s)
	if m == nil || s == "PT" {
		return 0, fmt.Errorf("Not a duration such as PT1H: %q", s)
	}
	var d time.Duration
	for i, unit := range []time.Duration{time.Hour, time.Minute, time.Second} {
		if m[i+1] != "" {
			n, _ := strconv.Atoi(m[i+1])
			d += time.Duration(n) * unit
		}
	}
	if d <= 0 {
		return 0, fmt.Errorf("Not a positive duration: %q", s)
	}
	return d, nil
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	return fmt.Sprintf("PT%dS", int(d.Round(time.Second)/time.Second))
}

func randomID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func hashOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:8])
}

// watchLogind ends lock leases when the graphical session locks or the machine sleeps. The daemon runs in a user
// unit, outside any login session, so it finds the user's graphical session through user/self's Display property;
// logind sends no signals on the self aliases. Lock leases are refused until this is set up
func watchLogind(b *broker) {
	if err := watchLogindErr(b); err != nil {
		slog.Warn("No lock leases", "err", err)
	}
}

func watchLogindErr(b *broker) error {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return fmt.Errorf("Connect to the system bus: %w", err)
	}
	user := conn.Object("org.freedesktop.login1", "/org/freedesktop/login1/user/self")
	var display struct {
		ID   string
		Path dbus.ObjectPath
	}
	if err := user.StoreProperty("org.freedesktop.login1.User.Display", &display); err != nil {
		return fmt.Errorf("Find the graphical session: %w", err)
	}
	if display.Path == "/" || display.Path == "" {
		return errors.New("No graphical session")
	}
	matches := []dbus.MatchOption{dbus.WithMatchObjectPath(display.Path)}
	if err := conn.AddMatchSignal(append(matches, dbus.WithMatchInterface("org.freedesktop.DBus.Properties"))...); err != nil {
		return err
	}
	if err := conn.AddMatchSignal(append(matches, dbus.WithMatchInterface("org.freedesktop.login1.Session"),
		dbus.WithMatchMember("Lock"))...); err != nil {
		return err
	}
	if err := conn.AddMatchSignal(dbus.WithMatchObjectPath("/org/freedesktop/login1"),
		dbus.WithMatchInterface("org.freedesktop.login1.Manager"), dbus.WithMatchMember("PrepareForSleep")); err != nil {
		return err
	}
	signals := make(chan *dbus.Signal, 16)
	conn.Signal(signals)
	b.mu.Lock()
	b.lockOK = true
	b.mu.Unlock()
	slog.Info("Watching the screen lock", "session", display.ID)
	for s := range signals {
		switch s.Name {
		case "org.freedesktop.login1.Session.Lock":
			b.lockEvent("the screen locked")
		case "org.freedesktop.login1.Manager.PrepareForSleep":
			if len(s.Body) == 1 && s.Body[0] == true {
				b.lockEvent("the machine went to sleep")
			}
		case "org.freedesktop.DBus.Properties.PropertiesChanged":
			if len(s.Body) >= 2 {
				if changed, ok := s.Body[1].(map[string]dbus.Variant); ok {
					if v, ok := changed["LockedHint"]; ok && v.Value() == true {
						b.lockEvent("the screen locked")
					}
				}
			}
		}
	}
	b.mu.Lock()
	b.lockOK = false
	b.mu.Unlock()
	b.lockEvent("the screen lock isn't watched any more")
	return errors.New("Lost the system bus")
}
